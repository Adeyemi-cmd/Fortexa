import { NextRequest, NextResponse } from "next/server";

import { AUTH_COOKIE_KEY, verifySessionToken } from "@/lib/auth/session";
import { clearSessionCookie } from "@/lib/auth/session-cookie";
import { revokeSession } from "@/lib/auth/session-store";

export async function POST(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_KEY)?.value;
  const session = token ? verifySessionToken(token, { allowStaleGeneration: true }) : null;

  if (session) {
    revokeSession({ userId: session.userId, sessionId: session.sid });
  }

  const response = NextResponse.json({ ok: true });
  clearSessionCookie(response);
  return response;
}
