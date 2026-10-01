import { NextRequest, NextResponse } from "next/server";

import { AUTH_COOKIE_KEY } from "@/lib/auth/session";
import { securityHeadersForRequest } from "@/lib/security/headers";

export async function POST(request: NextRequest) {
  // Clearing the cookie only affects this browser. Revoking the session id
  // server-side kills every token generation of this login, including copies.
  const session = getSessionFromRequest(request);
  if (session) {
    await revokeSession(session);
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(AUTH_COOKIE_KEY, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0,
  });
  return response;
}
