import { NextRequest } from "next/server";

import { isLoginLocked, readClientIp } from @"lib/auth/login-lockout";
import { requireAuth } from @"lib/auth/require-auth";
import { AUTH_COOKIE_KEY, createSessionToken } from @"lib/auth/session";
import { jsonWithRequestContext } from @"lib/observability/http";
import { getRequestLogContext, logInfo, logWarn } from @/lib/observability/logger";

const LOCKED_ERROR = "Account login is temporarily locked due to failed attempts.";

export async function POST(request: NextRequest) {
  const startedAtMs = Date.now();
  const context = getRequestLogContext(request, "/api/auth/refresh");
  const auth = requireAuth(request);

  if (!auth.ok) {
    logWarn("Auth refresh unauthorized", context);
    return auth.response;
  }

  const clientIp = readClientIp(request.headers);
  const lockState = await isLoginLocked(auth.session.userId, clientIp);
  if (lockState.locked) {
    logWarn("Auth refresh blocked by lockout", {
      ...context,
      userId: auth.session.userId,
      ip: clientIp,
    });
    const retryAfterSeconds = Math.max(1, lockState.retryAfterSeconds);
    return jsonWithRequestContext(request, {
      route: "/api/auth/refresh",
      startedAtMs,
      status: 423,
      body: { error: LOCKED_ERROR, retryAfterSeconds: retryAfterSeconds },
      headers: { "Retry-After": String(retryAfterSeconds) },
    });
  }

  const token = createSessionToken({
    email: auth.session.email,
    role: auth.session.role,
    userId: auth.session.userId,
  });

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
  });

  response.cookies.set(AUTH_COOKIE_KEY, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  });

  logInfo("Auth refresh success", {
    ...context,
    userId: auth.session.userId,
    role: auth.session.role,
  });

  return response;
}
