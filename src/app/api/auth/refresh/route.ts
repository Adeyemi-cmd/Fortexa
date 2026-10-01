import { NextRequest } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { rotateSessionToken } from "@/lib/auth/session";
import { setSessionCookie } from "@/lib/auth/session-cookie";
import { jsonWithRequestContext } from "@/lib/observability/http";
import { getRequestLogContext, logInfo, logWarn } from "@/lib/observability/logger";

export async function POST(request: NextRequest) {
  const startedAtMs = Date.now();
  const context = getRequestLogContext(request, "/api/auth/refresh");
  // A logged-out session must not be able to mint a new generation.
  const auth = await requireActiveAuth(request);

  if (!auth.ok) {
    logWarn("Auth refresh unauthorized", context);
    return auth.response;
  }

  const rotated = rotateSessionToken(auth.session);

  if (!rotated) {
    logWarn("Auth refresh rejected stale session", {
      ...context,
      userId: auth.session.userId,
      generation: auth.session.gen,
    });
    return jsonWithRequestContext(request, {
      route: "/api/auth/refresh",
      startedAtMs,
      status: 401,
      body: { error: "Unauthorized. Login required." },
    });
  }

  const response = jsonWithRequestContext(request, {
    route: "/api/auth/refresh",
    startedAtMs,
    status: 200,
    body: {
      ok: true,
      user: {
        email: auth.session.email,
        role: auth.session.role,
        userId: auth.session.userId,
      },
    },
    // The response rotates a session cookie, so it must never be cached.
    noStore: true,
  });

  setSessionCookie(response, rotated.token);

  logInfo("Auth refresh success", {
    ...context,
    userId: auth.session.userId,
    role: auth.session.role,
    generation: rotated.generation,
  });

  return response;
}
