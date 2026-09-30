import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

import type { NextRequest } from "next/server";

export type AuthRole = "operator" | "viewer";

export type AuthSession = {
  userId: string;
  email: string;
  role: AuthRole;
  /**
   * Session id. Minted once at login and carried forward by refresh, so every
   * token generation of one login shares it. Logout revokes by this id.
   */
  sid: string;
  exp: number;
};

export const AUTH_COOKIE_KEY = "fortexa_session";

/** Longest lifetime any session token is issued with. */
export const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;

function getAuthSecret() {
  const secret = process.env.FORTEXA_AUTH_SECRET?.trim();
  if (!secret) {
    throw new Error("FORTEXA_AUTH_SECRET is required for auth session signing.");
  }
  return secret;
}

function encodeBase64Url(value: string | Buffer) {
  const base64 = Buffer.from(value).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function sign(payloadPart: string) {
  return createHmac("sha256", getAuthSecret()).update(payloadPart).digest("base64url");
}

export function createSessionToken(input: {
  email: string;
  role: AuthRole;
  userId?: string;
  sessionId?: string;
  expiresInSeconds?: number;
}) {
  const now = Math.floor(Date.now() / 1000);
  const payload: AuthSession = {
    userId: input.userId ?? randomUUID(),
    email: input.email,
    role: input.role,
    sid: input.sessionId ?? randomUUID(),
    exp: now + (input.expiresInSeconds ?? SESSION_MAX_AGE_SECONDS),
  };

  const payloadPart = encodeBase64Url(JSON.stringify(payload));
  const signaturePart = sign(payloadPart);

  return `${payloadPart}.${signaturePart}`;
}

export function verifySessionToken(token: string): AuthSession | null {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return null;
  }

  const [payloadPart, signaturePart] = parts;
  const expectedSignature = sign(payloadPart);

  const actualBuffer = Buffer.from(signaturePart);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (actualBuffer.length !== expectedBuffer.length) {
    return null;
  }

  if (!timingSafeEqual(actualBuffer, expectedBuffer)) {
    return null;
  }

  try {
    const parsed = JSON.parse(decodeBase64Url(payloadPart)) as AuthSession;

    // A token without a session id cannot be revoked, so it is not accepted.
    if (
      !parsed.userId ||
      !parsed.email ||
      !parsed.role ||
      !parsed.exp ||
      typeof parsed.sid !== "string" ||
      !parsed.sid
    ) {
      return null;
    }

    if (parsed.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }

    if (parsed.role !== "operator" && parsed.role !== "viewer") {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

export function getSessionFromRequest(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_KEY)?.value;
  if (!token) {
    return null;
  }

  return verifySessionToken(token);
}
