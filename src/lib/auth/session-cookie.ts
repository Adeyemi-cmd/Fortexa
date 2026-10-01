import type { NextResponse } from "next/server";

import { AUTH_COOKIE_KEY, DEFAULT_SESSION_TTL_SECONDS } from "@/lib/auth/session";

export type SessionCookieOptions = {
  httpOnly: boolean;
  sameSite: "lax";
  secure: boolean;
  path: string;
  maxAge: number;
};

export function getSessionCookieOptions(): SessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: DEFAULT_SESSION_TTL_SECONDS,
  };
}

export function getClearSessionCookieOptions(): SessionCookieOptions {
  return {
    ...getSessionCookieOptions(),
    maxAge: 0,
  };
}

export function setSessionCookie(response: NextResponse, token: string) {
  response.cookies.set(AUTH_COOKIE_KEY, token, getSessionCookieOptions());
}

export function clearSessionCookie(response: NextResponse) {
  response.cookies.set(AUTH_COOKIE_KEY, "", getClearSessionCookieOptions());
}
