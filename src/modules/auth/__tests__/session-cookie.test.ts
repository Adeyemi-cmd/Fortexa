import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it } from "vitest";

import { AUTH_COOKIE_KEY, createSessionToken, verifySessionToken } from "@/lib/auth/session";
import { getClearSessionCookieOptions, getSessionCookieOptions } from "@/lib/auth/session-cookie";
import { resetSessionStore, revokeUserSessions } from "@/lib/auth/session-store";
import { POST as logout } from "@/app/api/auth/logout/route";
import { POST as refresh } from "@/app/api/auth/refresh/route";
import { proxy } from "@/proxy";

function issueToken(overrides?: { userId?: string; expiresInSeconds?: number }) {
  return createSessionToken({
    email: "test@example.com",
    role: "operator",
    userId: "cookie-user",
    expiresInSeconds: 120,
    ...overrides,
  });
}

function cookieHeader(token: string) {
  return `${AUTH_COOKIE_KEY}=${token}`;
}

function refreshRequest(token: string) {
  return new NextRequest("http://localhost/api/auth/refresh", {
    method: "POST",
    headers: { cookie: cookieHeader(token) },
  });
}

function logoutRequest(token: string) {
  return new NextRequest("http://localhost/api/auth/logout", {
    method: "POST",
    headers: { cookie: cookieHeader(token) },
  });
}

function dashboardRequest(token: string) {
  return new NextRequest("http://localhost/dashboard", {
    headers: { cookie: cookieHeader(token) },
  });
}

async function rotateToken(token: string) {
  const response = await refresh(refreshRequest(token));
  expect(response.status).toBe(200);
  const rotated = response.cookies.get(AUTH_COOKIE_KEY)?.value;
  expect(rotated).toBeTruthy();
  expect(rotated).not.toBe(token);
  return rotated as string;
}

describe("Session & Cookie Security Regression Tests", () => {
  beforeEach(() => {
    process.env.FORTEXA_AUTH_SECRET = "test-secret-key-123";
    resetSessionStore();
  });

  describe("Cookie Security Flags", () => {
    it("should use secure cookies in production environment", async () => {
      const response = await refresh(refreshRequest(issueToken()));
      expect(response.status).toBe(200);

      const cookie = response.cookies.get(AUTH_COOKIE_KEY);
      const options = getSessionCookieOptions();

      expect(cookie).toBeDefined();
      expect(cookie?.httpOnly).toBe(options.httpOnly);
      expect(cookie?.sameSite).toBe(options.sameSite);
      expect(cookie?.secure).toBe(options.secure);
      expect(cookie?.path).toBe(options.path);
      expect(cookie?.maxAge).toBe(options.maxAge);
    });

    it("should keep the secure flag tied to the environment", () => {
      const options = getSessionCookieOptions();

      expect(options.secure).toBe(process.env.NODE_ENV === "production");
      expect(options.httpOnly).toBe(true);
      expect(options.sameSite).toBe("lax");
      expect(options.path).toBe("/");
      expect(options.maxAge).toBe(604800);
    });
  });

  describe("Refresh Rotation", () => {
    it("should issue a new cookie and reject the previous generation", async () => {
      const original = issueToken();
      const rotated = await rotateToken(original);

      expect(verifySessionToken(rotated)).not.toBeNull();
      expect(verifySessionToken(original)).toBeNull();

      const replay = await refresh(refreshRequest(original));
      expect(replay.status).toBe(401);

      const second = await refresh(refreshRequest(rotated));
      expect(second.status).toBe(200);
      expect(second.cookies.get(AUTH_COOKIE_KEY)?.value).not.toBe(rotated);
    });

    it("should reject the rotated-out cookie in the proxy", async () => {
      const original = issueToken();
      const rotated = await rotateToken(original);

      const stale = proxy(dashboardRequest(original));
      expect(stale.headers.get("location")).toContain("/login");

      const current = proxy(dashboardRequest(rotated));
      expect(current.headers.get("location")).toBeNull();
    });
  });

  describe("Logout Behavior", () => {
    it("should clear the fortexa_session cookie upon logout", async () => {
      const response = await logout(logoutRequest(issueToken()));
      expect(response.status).toBe(200);

      const cookie = response.cookies.get(AUTH_COOKIE_KEY);
      const options = getClearSessionCookieOptions();

      expect(cookie?.value).toBe("");
      expect(cookie?.maxAge).toBe(options.maxAge);
      expect(cookie?.httpOnly).toBe(options.httpOnly);
      expect(cookie?.sameSite).toBe(options.sameSite);
      expect(cookie?.secure).toBe(options.secure);
      expect(cookie?.path).toBe(options.path);
      expect(options.maxAge).toBe(0);
    });

    it("should invalidate the newest cookie on logout", async () => {
      const original = issueToken();
      const rotated = await rotateToken(original);

      const response = await logout(logoutRequest(rotated));
      expect(response.status).toBe(200);

      expect(verifySessionToken(rotated)).toBeNull();
      expect(verifySessionToken(original)).toBeNull();

      const replay = await refresh(refreshRequest(rotated));
      expect(replay.status).toBe(401);

      const stale = proxy(dashboardRequest(rotated));
      expect(stale.headers.get("location")).toContain("/login");
    });
  });

  describe("Session Revocation", () => {
    it("should invalidate every generation when the user sessions are revoked", async () => {
      const original = issueToken();
      const rotated = await rotateToken(original);

      revokeUserSessions("cookie-user");

      expect(verifySessionToken(original)).toBeNull();
      expect(verifySessionToken(rotated)).toBeNull();
      expect(proxy(dashboardRequest(rotated)).headers.get("location")).toContain("/login");
    });
  });

  describe("Token Hardening", () => {
    it("should safely reject an expired session token", () => {
      const expiredToken = createSessionToken({
        email: "test@example.com",
        role: "viewer",
        userId: "user-1",
        expiresInSeconds: -3600,
      });

      const session = verifySessionToken(expiredToken);
      expect(session).toBeNull();
    });

    it("should safely reject a tampered session token signature", () => {
      const validToken = createSessionToken({
        email: "test@example.com",
        role: "operator",
        userId: "user-2",
      });

      const parts = validToken.split(".");
      const tamperedToken = `${parts[0]}.invalid_signature_here`;

      const session = verifySessionToken(tamperedToken);
      expect(session).toBeNull();
    });

    it("should safely reject malformed session tokens", () => {
      expect(verifySessionToken("not.a.real.token")).toBeNull();
      expect(verifySessionToken("just_one_part")).toBeNull();
      expect(verifySessionToken("")).toBeNull();
    });
  });
});
