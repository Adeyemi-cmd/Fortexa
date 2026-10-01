import { NextRequest, NextResponse } from "next/server";

import { AUTH_COOKIE_KEY } from "@/lib/auth/session";
import { securityHeadersForRequest } from "@/lib/security/headers";

export async function POST(request: NextRequest) {
  const response = NextResponse.json(
    { ok: true },
    // Clearing the session cookie must never be cached.
    { headers: securityHeadersForRequest(request, { noStore: true }) },
  );
  response.cookies.set(AUTH_COOKIE_KEY, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0,
  });
  return response;
}
