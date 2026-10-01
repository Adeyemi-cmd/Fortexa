import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { recordApiMetric } from "@/lib/observability/metrics";
import { applySecurityHeaders } from "@/lib/security/headers";

export function jsonWithRequestContext(
  request: NextRequest,
  input: {
    route: string;
    startedAtMs: number;
    status: number;
    body: unknown;
    headers?: Record<string, string>;
    /** Mark the response uncacheable (decisions, session cookies). */
    noStore?: boolean;
  }
) {
  const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
  const durationMs = Math.max(0, Date.now() - input.startedAtMs);

  recordApiMetric({
    route: input.route,
    method: request.method,
    statusCode: input.status,
    durationMs,
  });

  const response = NextResponse.json(input.body, {
    status: input.status,
    headers: {
      "x-request-id": requestId,
      ...input.headers,
    },
  });

  // Every route that uses this helper (auth, decision, payment) gets the shared
  // security header set on success and error responses alike.
  return applySecurityHeaders(response, requestId, { noStore: input.noStore });
}
