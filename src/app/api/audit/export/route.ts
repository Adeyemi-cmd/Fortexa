import { NextRequest, NextResponse } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { jsonWithRequestContext } from "@/lib/observability/http";
import { getRequestLogContext, logError, logInfo, logWarn } from "@/lib/observability/logger";
import { listAllAuditEntriesByUser, listAuditEntries, validateAuditFilter } from "@/lib/storage/audit-store";
import { sanitizeCsvCell } from "@/utils/csv.utils";
import type { AuditFilter } from "@/lib/storage/audit-store";
import { redactAuditExportEntriesByUser, redactAuditExportPayload } from "@/lib/audit/redact";
import {
  AuditChainError,
  DEFAULT_MAX_CHAIN_ROWS,
  getChainBoundaries,
  verifyAuditChain,
} from "@/lib/audit/hash-chain";

function toCsv(rows: Array<Record<string, string | number | boolean | null>>) {
  if (rows.length === 0) {
    return "";
  }

  const headers = Object.keys(rows[0] ?? {});
  const escape = (value: string) => `"${value.replaceAll("\"", "\"\"")}"`;
  const lines = [headers.join(",")];

  for (const row of rows) {
    const line = headers.map((header) => escape(sanitizeCsvCell(row[header] ?? ""))).join(",");
    lines.push(line);
  }

  return `${lines.join("\n")}\n`;
}

function chainErrorResponse(
  request: NextRequest,
  startedAtMs: number,
  error: AuditChainError,
) {
  const status = error.code === "audit_chain_row_cap_exceeded" ? 413 : 422;
  return jsonWithRequestContext(request, {
    route: "/api/audit/export",
    startedAtMs,
    status,
    body: {
      error: error.message,
      code: error.code,
      ...(error.details ?? {}),
    },
  });
}

export async function GET(request: NextRequest) {
  const startedAtMs = Date.now();
  const context = getRequestLogContext(request, "/api/audit/export");
  const auth = requireAuth(request);

  if (!auth.ok) {
    logWarn("Audit export unauthorized", context);
    return auth.response;
  }

  const format = request.nextUrl.searchParams.get("format")?.toLowerCase() ?? "json";
  const scope = request.nextUrl.searchParams.get("scope")?.toLowerCase() ?? "mine";

  const filter: AuditFilter = {
    from: request.nextUrl.searchParams.get("from") ?? undefined,
    to: request.nextUrl.searchParams.get("to") ?? undefined,
    decision: request.nextUrl.searchParams.get("decision") ?? undefined,
    domain: request.nextUrl.searchParams.get("domain") ?? undefined,
    actionId: request.nextUrl.searchParams.get("actionId") ?? undefined,
  };

  const validationError = validateAuditFilter(filter);
  if (validationError) {
    return jsonWithRequestContext(request, {
      route: "/api/audit/export",
      startedAtMs,
      status: 400,
      body: { error: validationError },
    });
  }

  try {
    const isOperator = auth.session.role === "operator";
    const viewerScopeAll = !isOperator && scope === "all";
    const exportAll = isOperator && scope === "all";

    if (viewerScopeAll) {
      return jsonWithRequestContext(request, {
        route: "/api/audit/export",
        startedAtMs,
        status: 400,
        body: { error: "Viewer role is limited to scope=mine." },
      });
    }

    if (format !== "json" && format !== "csv") {
      return jsonWithRequestContext(request, {
        route: "/api/audit/export",
        startedAtMs,
        status: 400,
        body: { error: "format must be json or csv" },
      });
    }

    if (exportAll) {
      const all = await listAllAuditEntriesByUser(filter);

      // Verify every user's chain before writing any response body.
      const verifiedByUser: Record<string, ReturnType<typeof verifyAuditChain>> = {};
      for (const [userId, entries] of Object.entries(all)) {
        verifiedByUser[userId] = verifyAuditChain(entries);
        const result = verifiedByUser[userId]!.result;
        if (!result.valid) {
          throw new AuditChainError(
            "audit_chain_verification_failed",
            `Audit chain for user "${userId}" failed verification: ${result.reason}`,
            {
              userId,
              entryId: result.entryId ?? null,
              index: result.index ?? null,
              checkedCount: result.checkedCount,
              legacyCount: result.legacyCount,
            },
          );
        }
      }

      if (format === "json") {
        logInfo("Audit export success (all/json)", { ...context, userId: auth.session.userId });
        return jsonWithRequestContext(request, {
          route: "/api/audit/export",
          startedAtMs,
          status: 200,
          body: {
            scope: "all",
            exportedBy: auth.session.userId,
            entriesByUser: redactAuditExportEntriesByUser(all),
            chainBoundariesByUser: Object.fromEntries(
              Object.entries(verifiedByUser).map(([userId, verified]) => [
                userId,
                verified.boundaries,
              ]),
            ),
          },
        });
      }

      const rows: Array<Record<string, string | number | boolean | null>> = [];
      for (const [userId, entries] of Object.entries(all)) {
        for (const entry of entries) {
          rows.push({
            userId,
            id: entry.id,
            timestamp: entry.timestamp,
            decision: entry.decision,
            actionId: entry.action.id,
            actionName: entry.action.name,
            domain: entry.action.domain,
            amountXLM: entry.action.amountXLM,
            explanation: entry.explanation,
            entryHash: entry.entryHash ?? "",
            previousHash: entry.previousHash ?? "",
          });
        }
      }

      logInfo("Audit export success (all/csv)", { ...context, userId: auth.session.userId });
      return new NextResponse(toCsv(redactAuditExportPayload(rows)), {
        status: 200,
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": "attachment; filename=fortexa-audit-all.csv",
          "x-request-id": request.headers.get("x-request-id") ?? crypto.randomUUID(),
        },
      });
    }

    const mine = await listAuditEntries(auth.session.userId, filter);

    // Verify the chain from genesis through the last exported row before
    // writing the body. The row cap is enforced here as well.
    const verified = verifyAuditChain(mine);
    if (!verified.result.valid) {
      const result = verified.result;
      throw new AuditChainError(
        "audit_chain_verification_failed",
        `Audit chain failed verification: ${result.reason}`,
        {
          entryId: result.entryId ?? null,
          index: result.index ?? null,
          checkedCount: result.checkedCount,
          legacyCount: result.legacyCount,
        },
      );
    }

    if (format === "json") {
      logInfo("Audit export success (mine/json)", { ...context, userId: auth.session.userId });
      return jsonWithRequestContext(request, {
        route: "/api/audit/export",
        startedAtMs,
        status: 200,
        body: {
          scope: "mine",
          userId: auth.session.userId,
          entries: redactAuditExportPayload(mine),
          chainBoundary: verified.boundaries,
        },
      });
    }

    const rows = mine.map((entry) => ({
      userId: auth.session.userId,
      id: entry.id,
      timestamp: entry.timestamp,
      decision: entry.decision,
      actionId: entry.action.id,
      actionName: entry.action.name,
      domain: entry.action.domain,
      amountXLM: entry.action.amountXLM,
      explanation: entry.explanation,
      entryHash: entry.entryHash ?? "",
      previousHash: entry.previousHash ?? "",
    }));

    logInfo("Audit export success (mine/csv)", { ...context, userId: auth.session.userId });
    const filenameMine = `fortexa-audit-mine-${new Date().toISOString().slice(0, 10)}.csv`;
    return new NextResponse(toCsv(redactAuditExportPayload(rows)), {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename=${filenameMine}`,
        "x-request-id": request.headers.get("x-request-id") ?? crypto.randomUUID(),
      },
    });
  } catch (error) {
    if (error instanceof AuditChainError) {
      logWarn("Audit export blocked by chain verification", {
        ...context,
        userId: auth.session.userId,
        code: error.code,
        detail: error.message,
      });
      return chainErrorResponse(request, startedAtMs, error);
    }

    logError("Audit export internal error", {
      ...context,
      userId: auth.session.userId,
      detail: error instanceof Error ? error.message : "unknown",
    });

    return jsonWithRequestContext(request, {
      route: "/api/audit/export",
      startedAtMs,
      status: 500,
      body: {
        error: error instanceof Error ? error.message : "Failed to export audit data.",
      },
    });
  }
}
