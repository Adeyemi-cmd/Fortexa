import { NextRequest } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { isLoginAuthorizationPayload } from "@/lib/auth/wallet-challenge";
import { readJsonBody } from "@/lib/http/read-json-body";
import { jsonWithRequestContext } from "@/lib/observability/http";
import { getRequestLogContext, logError, logInfo, logWarn } from "@/lib/observability/logger";
import { recordStellarSubmitResult } from "@/lib/observability/metrics";
import { redactSensitiveFields } from "@/lib/observability/redact";
import { getProtectedPaymentFlowReadinessReport } from "@/lib/readiness/production";
import { consumeRateLimit, rateLimitHeaders } from "@/lib/security/rate-limit";
import { decodeSignedXdrSourceAccount, submitSignedTransactionXdr } from "@/lib/stellar/client";
import { assertStellarNetworkConfig } from "@/lib/stellar/network-config";
import { getStellarExplorerTransactionUrl } from "@/lib/stellar/network";
import { getTransactionHash, verifyBuildAuthorization } from "@/lib/stellar/payment-build-authorization";
import { isPaymentDecisionCurrent } from "@/lib/stellar/verify-payment-quote";
import { getAuditEntryById } from "@/lib/storage/audit-store";
import {
  abortIdempotentSubmit,
  beginIdempotentSubmit,
  completeIdempotentSubmit,
  getIdempotencyInFlightWaitMs,
  hashCanonicalPaymentBody,
  maybeRunCleanup,
} from "@/lib/storage/submit-idempotency-store";
import { getUserWallet } from "@/lib/storage/user-wallet-store";
import { getAuditEntryById } from "@/lib/storage/audit-store";
import {
  stellarSubmitSignedRequestSchema,
  validateIdempotencyKey,
} from "@/lib/validation/schemas";
import { logValidationFailure, toPublicValidationDetails } from "@/lib/validation/errors";
import { normalizeHorizonError } from "@/lib/utils/horizonErrors";
import { verifyPaymentAgainstQuote } from "@/lib/stellar/verify-payment-quote";

type HorizonErrorContext = {
  explanation: string;
  nextStep: string;
};

/**
 * Best-effort destination extraction from a signed XDR for gate checking.
 * Runs before validation; a malformed envelope simply reports no destination
 * (the strict decode later still returns the route's normal 400).
 */
function extractSignedXdrDestination(
  signedXdr: string | undefined,
): SignedXdrDestinationResult {
  if (!signedXdr) {
    return { ok: false, reason: "malformed" };
  }

  try {
    return decodeSignedXdrDestination(signedXdr);
  } catch {
    return { ok: false, reason: "malformed" };
  }
}

const HORIZON_TX_ERRORS: Record<string, HorizonErrorContext> = {
  tx_bad_seq: {
    explanation: "The transaction sequence number is incorrect.",
    nextStep: "Refresh your wallet or account data to synchronize the sequence number and try again.",
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
    // #205: op_no_destination can echo back the user-supplied destination
    // address in Horizon error detail. Keep the operator-facing text, but the
    // log path passes raw error.message through redactSensitiveFields so the
    // address itself never reaches logs.
  },
  op_underfunded: {
    explanation: "The source account lacks sufficient funds for this operation.",
    nextStep: "Fund the source account with enough XLM to cover the payment and reserves.",
  },
};

function getTestnetExplorerUrl(hash: string) {
  return `https://stellar.expert/explorer/testnet/tx/${hash}`;
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

  // Read the body before the gate so the signed transaction's destination
  // operations can be blocklist-checked in the same atomic enforcement step
  // as the rate-limit consumption (issue #202).
  const bodyResult = await readJsonBody(request);

  let gateDestination: string | undefined;
  if (bodyResult.ok) {
    const destinationPreview = extractSignedXdrDestination(
      typeof (bodyResult.data as { signedXdr?: unknown })?.signedXdr === "string"
        ? ((bodyResult.data as { signedXdr: string }).signedXdr)
        : undefined,
    );
    gateDestination = destinationPreview.ok ? destinationPreview.destination : undefined;
  }

  const gate = await enforceRequestGate(request, {
    rateLimitKey: "stellar-submit-signed",
    limit: 30,
    windowMs: 60_000,
    destination: gateDestination,
  });

  if (!gate.ok) {
    logWarn("Submit signed route blocked by enforcement gate", {
      ...context,
      gateCode: gate.code,
    });
    recordStellarSubmitResult("validation_failure");
    return jsonWithRequestContext(request, {
      route: "/api/stellar/submit-signed",
      startedAtMs,
      status: gate.status,
      body: {
        error: gate.error,
        code: gate.code,
      },
      headers: gateErrorHeaders(gate),
    });
  }

  const rate = gate.rate;

  maybeRunCleanup();

  try {
    const auth = requireAuth(request, { allowedRoles: ["signer"] });

    if (!auth.ok) {
      logWarn("Submit signed route unauthorized", context);
      return auth.response;
    }

    const userId = auth.session.userId;
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

    const userId = auth.session.userId;

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

    const parsedPayload = stellarSubmitSignedRequestSchema.safeParse(bodyResult.data);

    if (!parsedPayload.success) {
      logWarn("Submit signed validation failed", { ...context, userId });
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 400,
        body: {
          error: "Invalid signed transaction submission.",
          details: parsedPayload.error.flatten(),
        },
        headers: rateLimitHeaders(rate),
      });
    }

    const payload = parsedPayload.data;

    if (!xdrSourceResult.payment) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 403,
        body: { error: "Signed transaction does not contain one authorized native payment." },
        headers: rateLimitHeaders(rate),
      });
    }

    const auditEntry = await getAuditEntryById(userId, payload.auditEntryId);
    if (!auditEntry?.paymentQuote || xdrSourceResult.payment.memo !== auditEntry.paymentQuote.memo) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 403,
        body: { error: "Signed transaction memo does not match the authorized payment quote." },
        headers: rateLimitHeaders(rate),
      });
    }

    const authorization = verifyPaymentAgainstQuote(auditEntry, {
      ...xdrSourceResult.payment,
      network: "testnet",
    });
    if (!authorization.ok) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: authorization.status,
        body: { error: authorization.error, field: authorization.field },
        headers: rateLimitHeaders(rate),
      });
    }

    if (!xdrSourceResult.payment) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 403,
        body: { error: "Signed transaction does not contain one authorized native payment." },
        headers: rateLimitHeaders(rate),
      });
    }

    const auditEntry = await getAuditEntryById(userId, payload.auditEntryId);
    if (!auditEntry?.paymentQuote || xdrSourceResult.payment.memo !== auditEntry.paymentQuote.memo) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 403,
        body: { error: "Signed transaction memo does not match the authorized payment quote." },
        headers: rateLimitHeaders(rate),
      });
    }

    const authorization = verifyPaymentAgainstQuote(auditEntry, {
      ...xdrSourceResult.payment,
      network: "testnet",
    });
    if (!authorization.ok) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: authorization.status,
        body: { error: authorization.error, field: authorization.field },
        headers: rateLimitHeaders(rate),
      });
    }

    const auditEntry = await getAuditEntryById(userId, payload.decisionId);
    if (!isPaymentDecisionCurrent(auditEntry, payload.decisionId, payload.quoteExpiresAt)) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 403,
        body: { error: "Payment decision or quote is no longer valid. Please re-evaluate the action." },
        headers: rateLimitHeaders(rate),
      });
    }

    const transactionHash = getTransactionHash(
      payload.signedXdr,
      assertStellarNetworkConfig().networkPassphrase,
    );
    if (!verifyBuildAuthorization(payload.buildAuthorization, {
      userId,
      decisionId: payload.decisionId,
      quoteExpiresAt: payload.quoteExpiresAt,
      transactionHash,
    })) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 403,
        body: { error: "Signed transaction does not match the authorized payment build." },
        headers: rateLimitHeaders(rate),
      });
    }

    const headerKey = request.headers.get("idempotency-key")?.trim();
    const bodyKey = payload.idempotencyKey?.trim();
    const idempotencyKey = headerKey && headerKey.length > 0 ? headerKey : bodyKey;

    if (idempotencyKey && (idempotencyKey.length < 8 || idempotencyKey.length > 255)) {
      logWarn("Submit signed invalid idempotency key", { ...context, userId });
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 400,
        body: { error: "Idempotency-Key must be between 8 and 255 characters." },
        headers: rateLimitHeaders(rate),
      });
    }

    // Identity of the request is the hash of the key plus the canonical payment
    // body, so the store and this route can never disagree about what "the same
    // request" means.
    const requestHash = idempotencyKey
      ? hashCanonicalPaymentBody(idempotencyKey, payload)
      : null;

    if (idempotencyKey && requestHash) {
      const claim = await beginIdempotentSubmit(userId, idempotencyKey, requestHash, {
        inFlightWaitMs: getIdempotencyInFlightWaitMs(),
      });

      if (claim.outcome === "conflict") {
        logWarn("Signed transaction idempotency conflict", { ...context, userId, idempotencyKey });
        recordStellarSubmitResult("idempotency_conflict");
        return jsonWithRequestContext(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 409,
          body: {
            error: "Idempotency-Key was already used with a different signed transaction.",
          },
          headers: { ...rateLimitHeaders(rate), "Idempotency-Replayed": "false" },
        });
      }

      if (claim.outcome === "in_flight") {
        logWarn("Signed transaction idempotency in flight", {
          ...context,
          userId,
          idempotencyKey,
        });
        recordStellarSubmitResult("idempotency_in_flight");
        return jsonWithRequestContext(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: 409,
          body: {
            error: "An identical submit for this idempotency key is still in progress.",
            code: "idempotency_in_flight",
          },
          headers: {
            ...rateLimitHeaders(rate),
            "Idempotency-Replayed": "false",
            "Retry-After": "1",
          },
        });
      }

      if (claim.outcome === "replay") {
        logInfo("Signed transaction idempotent replay", {
          ...context,
          userId,
          idempotencyKey,
          transactionHash: claim.record.transactionId,
        });
        recordStellarSubmitResult("idempotency_replay");
        return jsonWithRequestContext(request, {
          route: "/api/stellar/submit-signed",
          startedAtMs,
          status: claim.record.statusCode ?? 200,
          body: claim.record.result,
          headers: { ...rateLimitHeaders(rate), "Idempotency-Replayed": "true" },
        });
      }

      claimedIdempotency = { userId, key: idempotencyKey, requestHash };
    }

    // The idempotency lookup can take time; check the persisted authorization
    // again at the last point before the external submission.
    const currentDecision = await getAuditEntryById(userId, payload.decisionId);
    if (!isPaymentDecisionCurrent(currentDecision, payload.decisionId, payload.quoteExpiresAt)) {
      return jsonWithRequestContext(request, {
        route: "/api/stellar/submit-signed",
        startedAtMs,
        status: 403,
        body: { error: "Payment decision or quote is no longer valid. Please re-evaluate the action." },
        headers: rateLimitHeaders(rate),
      });
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
      transactionHash: submitted.hash,
      payment: {
        mode: "real",
        ...submitted,
      },
      explorerUrl: getTestnetExplorerUrl(submitted.hash),
    };

    if (claimedIdempotency) {
      const claim = claimedIdempotency;
      claimedIdempotency = null;

      try {
        await completeIdempotentSubmit(userId, claim.key, claim.requestHash, {
          statusCode: 200,
          transactionId: submitted.hash,
          result: responseBody,
        });
      } catch (settleError) {
        // The transaction is already on the ledger, so the claim is deliberately
        // left in flight instead of being released: releasing it would invite a
        // retry to resubmit. The lease expiry is what recovers the key.
        logError("Submit signed idempotency settle failed", {
          ...context,
          userId,
          idempotencyKey: claim.key,
          detail: settleError instanceof Error ? settleError.message : "unknown",
        });
      }
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
    if (claimedIdempotency) {
      const claim = claimedIdempotency;
      claimedIdempotency = null;
      // Nothing was settled, so free the key and let the client retry.
      await abortIdempotentSubmit(claim.userId, claim.key, claim.requestHash).catch(
        () => undefined
      );
    }

    const formatted = formatSubmitError(error);
    const category = normalizeHorizonError(formatted.txCode);
    // #205: formatSubmitError embeds raw Horizon error.message (which can carry
    // the signed XDR envelope, destination addresses, or memo values) into
    // formatted.message. Pass the log detail through the shared observability
    // redactor so secrets, signed XDR, and payment metadata never reach logs.
    // recordStellarSubmitResult("horizon_failure") below is unconditional so
    // stable counters keep incrementing even when the error is fully redacted.
    logError("Submit signed internal error", redactSensitiveFields({
      ...context,
      detail: formatted.message,
      horizonCategory: category,
    }));
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