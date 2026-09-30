import { NextRequest } from "next/server";
import { TransactionBuilder } from "@stellar/stellar-sdk";

import { requireAuth } from "@/lib/auth/require-auth";
import { readJsonBody } from "@/lib/http/read-json-body";
import { jsonWithRequestContext } from "@/lib/observability/http";
import {
  getRequestLogContext,
  logError,
  logInfo,
  logWarn,
} from "@/lib/observability/logger";
import { recordStellarSubmitResult } from "@/lib/observability/metrics";
import { getProtectedPaymentFlowReadinessReport } from "@/lib/readiness/production";
import { consumeRateLimit, rateLimitHeaders } from "@/lib/security/rate-limit";
import {
  decodeSignedXdrSourceAccount,
  submitSignedTransactionXdr,
} from "@/lib/stellar/client";
import { getStellarExplorerTransactionUrl } from "@/lib/stellar/network";
import { assertStellarNetworkConfig } from "@/lib/stellar/network-config";
import { validateDecisionReceipt } from "@/lib/stellar/verify-payment-quote";
import {
  getIdempotencyRecord,
  hashSignedXdr,
  maybeRunCleanup,
  putIdempotencyRecord,
} from "@/lib/storage/submit-idempotency-store";
import { getUserWallet } from "@/lib/storage/user-wallet-store";
import {
  stellarSubmitSignedRequestSchema,
  validateIdempotencyKey,
} from "@/lib/validation/schemas";
import {
  logValidationFailure,
  toPublicValidationDetails,
} from "@/lib/validation/errors";
import { normalizeHorizonError } from "@/lib/utils/horizonErrors";

type HorizonErrorContext = {
  explanation: string;
  nextStep: string;
};

const HORIZON_TX_ERRORS: Record<string, HorizonErrorContext> = {
  tx_bad_seq: {
    explanation: "The transaction sequence number is incorrect.",
    nextStep:
      "Refresh your wallet or account data to synchronize the sequence number and try again.",
  },
  tx_insufficient_fee: {
    explanation: "The network fee provided is too low.",
    nextStep: "Increase the transaction fee.",
  },
  tx_failed: {
    explanation: "The transaction failed during operation execution.",
    nextStep: "Check the operation error codes for more details.",
  },
};

const HORIZON_OP_ERRORS: Record<string, HorizonErrorContext> = {
  op_no_destination: {
    explanation: "The destination account does not exist on the network.",
    nextStep: "Verify the destination address or ensure the account is funded.",
  },
  op_underfunded: {
    explanation:
      "The source account lacks sufficient funds for this operation.",
    nextStep:
      "Fund the source account with enough XLM to cover the payment and reserves.",
  },
};

function verifySignedXdrMatchesDecisionReceipt(
  signedXdr: string,
  receipt: {
    destination: string;
    amountXLM: string;
    asset: string;
    memo?: string;
    network: string;
    receiptHash?: string;
  },
) {
  const validation = validateDecisionReceipt(receipt as any);
  if (!validation.ok) {
    return {
      ok: false,
      status: 403,
      error: validation.error,
      field: validation.field,
    };
  }

  const { networkPassphrase } = assertStellarNetworkConfig();
  let decoded: ReturnType<typeof TransactionBuilder.fromXDR>;

  try {
    decoded = TransactionBuilder.fromXDR(signedXdr, networkPassphrase);
  } catch {
    return {
      ok: false,
      status: 400,
      error:
        "Signed XDR could not be decoded. It may be malformed or built for the wrong network.",
    };
  }

  const paymentOp = decoded.operations.find((op: any) => op.type === "payment");
  if (!paymentOp || paymentOp.type !== "payment") {
    return {
      ok: false,
      status: 403,
      error: "Signed transaction is not a payment operation.",
      field: "destination",
    };
  }

  const network =
    networkPassphrase === "Test SDF Network ; September 2015"
      ? "testnet"
      : "testnet";
  const actual = {
    destination: paymentOp.destination?.trim().toUpperCase(),
    amountXLM: String(paymentOp.amount ?? "0"),
    asset: "native",
    memo: decoded.memo?.type === "text" ? String(decoded.memo.value ?? "") : "",
    network,
  };

  if (actual.destination !== validation.normalized.destination) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction destination does not match the authorized payment decision receipt.",
      field: "destination",
    };
  }

  if (String(validation.normalized.amountXLM) !== String(actual.amountXLM)) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction amount does not match the authorized payment decision receipt.",
      field: "amountXLM",
    };
  }

  if (actual.asset !== validation.normalized.asset) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction asset does not match the authorized payment decision receipt.",
      field: "asset",
    };
  }

  const normalizedMemo = actual.memo.slice(0, 28);
  if (normalizedMemo !== validation.normalized.memo) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction memo does not match the authorized payment decision receipt.",
      field: "memo",
    };
  }

  if (actual.network !== validation.normalized.network) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction network does not match the authorized payment decision receipt.",
      field: "network",
    };
  }

  const expectedHash = validation.normalized.receiptHash;
  if (
    expectedHash &&
    receipt.receiptHash &&
    expectedHash !== receipt.receiptHash
  ) {
    return {
      ok: false,
      status: 403,
      error:
        "Signed transaction does not match the authorized payment decision receipt.",
      field: "amountXLM",
    };
  }

  return { ok: true };
}

export function formatSubmitError(error: unknown) {
  if (!(error instanceof Error)) {
    return { message: "Failed to submit signed transaction." };
  }

  const withResponse = error as Error & {
    response?: {
      data?: {
        extras?: {
          result_codes?: {
            transaction?: string;
            operations?: string[];
          };
        };
      };
    };
  };

  const txCode = withResponse.response?.data?.extras?.result_codes?.transaction;
  const opCodes = withResponse.response?.data?.extras?.result_codes?.operations;

  if (!txCode) {
    return { message: error.message };
  }

  let explanation: string | undefined;
  let nextStep: string | undefined;

  if (opCodes && opCodes.length > 0) {
    const firstOpError = opCodes.find((code) => HORIZON_OP_ERRORS[code]);
    if (firstOpError) {
      explanation = HORIZON_OP_ERRORS[firstOpError].explanation;
      nextStep = HORIZON_OP_ERRORS[firstOpError].nextStep;
    } else if (HORIZON_TX_ERRORS[txCode]) {
      explanation = HORIZON_TX_ERRORS[txCode].explanation;
      nextStep = HORIZON_TX_ERRORS[txCode].nextStep;
    }
  } else if (HORIZON_TX_ERRORS[txCode]) {
    explanation = HORIZON_TX_ERRORS[txCode].explanation;
    nextStep = HORIZON_TX_ERRORS[txCode].nextStep;
  }

  return {
    message: `${error.message} (tx: ${txCode}${opCodes?.length ? `, ops: ${opCodes.join(",")}` : ""})`,
    txCode,
    opCodes,
    explanation,
    nextStep,
  };
}

export async function POST(request: NextRequest) {
  const startedAtMs = Date.now();
  const context = getRequestLogContext(request, "/api/stellar/submit-signed");

  const rate = await consumeRateLimit(request, {
    key: "stellar-submit-signed",
    limit: 30,
    windowMs: 60_000,
  });

  if (!rate.ok) {
    logWarn("Submit signed route rate limited", context);
    return jsonWithRequestContext(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: 429,
      body: { error: "Rate limit exceeded for signed transaction submission." },
      headers: rateLimitHeaders(rate),
    });
  }

  maybeRunCleanup();

  try {
    const auth = requireAuth(request, { allowedRoles: ["operator"] });

    if (!auth.ok) {
      logWarn("Submit signed route unauthorized", context);
      return auth.response;
    }

    const readinessReport = getProtectedPaymentFlowReadinessReport();
    if (readinessReport) {
      logWarn("Submit signed blocked by production readiness check", context);
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 503,
        body: {
          error:
            "Protected payment flows are disabled until Fortexa passes the production readiness check.",
          issues: readinessReport.issues,
          command: "npm run check:production-readiness",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const userId = auth.session.userId;

    const bodyResult = await readJsonBody(request);
    if (!bodyResult.ok) {
      logWarn("Submit signed payload too large", { ...context, userId });
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 413,
        body: { error: bodyResult.error },
        headers: rateLimitHeaders(rate),
      });
    }

    const parsedPayload = stellarSubmitSignedRequestSchema.safeParse(
      bodyResult.data,
    );

    if (!parsedPayload.success) {
      logValidationFailure(
        "Submit signed validation failed",
        { ...context, userId },
        parsedPayload.error,
        bodyResult.data,
      );
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 400,
        body: {
          error: "Invalid signed transaction submission.",
          details: toPublicValidationDetails(parsedPayload.error),
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const payload = parsedPayload.data;

    const assignedWallet = await getUserWallet(userId);

    if (assignedWallet && "expired" in assignedWallet) {
      logWarn("Submit signed wallet expired", { ...context, userId });
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 401,
        body: { error: "Session wallet mapping has expired." },
        headers: rateLimitHeaders(rate),
      });
    }

    if (!assignedWallet) {
      logWarn("Submit signed missing wallet mapping", { ...context, userId });
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 401,
        body: { error: "No session wallet mapping found for this user." },
        headers: rateLimitHeaders(rate),
      });
    }

    const xdrSourceResult = decodeSignedXdrSourceAccount(payload.signedXdr);

    if (!xdrSourceResult.ok) {
      logWarn("Submit signed XDR malformed", { ...context, userId });
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 400,
        body: {
          error:
            "Signed XDR could not be decoded. It may be malformed or built for the wrong network.",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const receiptCheck = verifySignedXdrMatchesDecisionReceipt(
      payload.signedXdr,
      payload.decisionReceipt,
    );
    if (!receiptCheck.ok) {
      logWarn("Submit signed XDR disagrees with decision receipt", {
        ...context,
        userId,
        receiptHash: payload.decisionReceipt.receiptHash,
        signedXdrHash: hashSignedXdr(payload.signedXdr),
        field: receiptCheck.field,
      });
      recordStellarSubmitResult("decision_receipt_mismatch");
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: receiptCheck.status ?? 403,
        body: {
          error: receiptCheck.error,
          field: receiptCheck.field,
          receiptHash: payload.decisionReceipt.receiptHash,
        },
        headers: rateLimitHeaders(rate),
      });
    }

    if (xdrSourceResult.sourceAccount !== assignedWallet.publicKey) {
      logWarn("Submit signed source wallet mismatch", {
        ...context,
        userId,
        expectedWallet: assignedWallet.publicKey,
        actualSource: xdrSourceResult.sourceAccount,
      });
      recordStellarSubmitResult("source_wallet_mismatch");
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 400,
        body: {
          error:
            "Signed transaction source account does not match your session wallet.",
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const headerKey = request.headers.get("idempotency-key")?.trim();
    const bodyKey = payload.idempotencyKey?.trim();
    const mergedIdempotencyKey =
      headerKey && headerKey.length > 0 ? headerKey : bodyKey;

    let idempotencyKey: string | undefined;
    if (mergedIdempotencyKey) {
      const idempotencyValidation =
        validateIdempotencyKey(mergedIdempotencyKey);
      if (!idempotencyValidation.ok) {
        logWarn("Submit signed invalid idempotency key", {
          ...context,
          userId,
        });
        return jsonWithRequestContext(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 400,
          body: { error: idempotencyValidation.error },
          headers: rateLimitHeaders(rate),
        });
      }
      idempotencyKey = idempotencyValidation.key;
    }

    const xdrHash = idempotencyKey ? hashSignedXdr(payload.signedXdr) : null;

    if (idempotencyKey && xdrHash) {
      const existing = await getIdempotencyRecord(userId, idempotencyKey);

      if (existing && existing.xdrHash === xdrHash) {
        logInfo("Signed transaction idempotent replay", {
          ...context,
          userId,
          idempotencyKey,
        });
        recordStellarSubmitResult("idempotency_replay");
        return jsonWithRequestContext(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 200,
          body: existing.result,
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "true",
          },
        });
      }

      if (existing) {
        logWarn("Signed transaction idempotency conflict", {
          ...context,
          userId,
          idempotencyKey,
        });
        recordStellarSubmitResult("idempotency_conflict");
        return jsonWithRequestContext(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 409,
          body: {
            error:
              "Idempotency-Key was already used with a different signed transaction.",
          },
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "false",
          },
        });
      }
    }

    const submitted = await submitSignedTransactionXdr(payload.signedXdr);

    logInfo("Signed transaction submitted", {
      ...context,
      userId,
      txHash: submitted.hash,
      ledger: submitted.ledger,
    });

    recordStellarSubmitResult("success");

    const responseBody = {
      ok: true,
      userId,
      payment: {
        mode: "real",
        ...submitted,
      },
      explorerUrl: getStellarExplorerTransactionUrl(submitted.hash),
    };

    if (idempotencyKey && xdrHash) {
      await putIdempotencyRecord(userId, idempotencyKey, {
        xdrHash,
        result: responseBody,
      });
    }

    return jsonWithRequestContext(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: 200,
      body: responseBody,
      headers: idempotencyKey
        ? { ...rateLimitHeaders(rate), "Idempotency-Replayed": "false" }
        : rateLimitHeaders(rate),
    });
  } catch (error) {
    const formatted = formatSubmitError(error);
    const category = normalizeHorizonError(formatted.txCode);
    logError("Submit signed internal error", {
      ...context,
      detail: formatted.message,
      horizonCategory: category,
    });
    recordStellarSubmitResult("horizon_failure");
    return jsonWithRequestContext(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: 500,
      body: {
        error: formatted.message,
        category,
        resultCode: formatted.txCode,
        operationCodes: formatted.opCodes,
        explanation: formatted.explanation,
        nextStep: formatted.nextStep,
        rawError: formatted,
      },
      headers: rateLimitHeaders(rate),
    });
  }
}
