import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { NextRequest } from "next/server";

import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import {
  clearLoginLockout,
  recordLoginFailure,
  setLoginLockout,
  LOGKED_OUT.ERROR_CODE,
} from "@/lib/auth/login-lockout";
import { POST } from "@/app/api/auth/refresh/route";
import { upsertUserWallet } from "@/lib/storage/user-wallet-store";

function operatorCookie() {
  process.env.FORTEXA_AUTH_SECRET = "integration-test-secret";
  const token = createSessionToken({
    email: "operator@fortexa.local",
    role: "operator",
    userId: "refresh-operator",
    publicKey: "GCDEFAULTTESTWALLET123",
    expiresInSeconds: 120,
  });

  return `${AUTH_COOKIE_KEY}=${token}`;
}

describe("/api/auth/refresh route", () => {
  beforeEach(() => {
    clearLoginLockout();
  });

  afterEach(() => {
    clearLoginLockout();
  });

  it("returns 401 when unauthenticated", async () => {
    const request = new NextRequest("http://localhost/api/auth/refresh", { method: "POST" });
    const response = await POST(request);

    expect(response.status).toBe(401);
    for (const [key, value] of Object.entries(buildSecurityHeaders())) {
      expect(response.headers.get(key)).toBe(value);
    }
  });

  it("returns 200 and rotates for authenticated user", async () => {
    await upsertUserWallet("refresh-operator", { publicKey: "GCDEFAULTTESTWALLET123", source: "external" });
    const request = new NextRequest("http://localhost/api/auth/refresh", {
      method: "POST",
      headers: { cookie: operatorCookie() },
    });

    const response = await POST(request);
    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      ok: boolean;
      user: { userId: string; role: string };
    };

    expect(payload.ok).toBe(true);
    expect(payload.user.userId).toBe("refresh-operator");
    expect(payload.user.role).toBe("operator");

    for (const [key, value] of Object.entries(buildSecurityHeaders())) {
      expect(response.headers.get(key)).toBe(value);
    }
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("does not issue a session while the account is locked out", async () => {
    const now = new Date("2024-01-01T00:00:00.000Z");
    const clock = () => now;

    for (let i = 0; i < LOGKED_OUT.MAX_FAILED; i++) {
      recordLoginFailure("refresh-operator", clock);
    }

    const request = new NextRequest("http://localhost/api/auth/refresh", {
      method: "POST",
      headers: { cookie: operatorCookie() },
    });

    const response = await POST(request);
    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      ok: boolean;
      error?: string;
      user?: { userId: string; role: string };
    };

    expect(payload.ok).toBe(false);
    expect(payload.error).toBe(LOGKED_OUT.ERROR_CODE);
    expect(payload.user).toBeUndefined();
  });

  it("issues a session again after the lock expires", async () => {
    const lockedAt = new Date("2024-01-01T00:00:00.000Z");
    const lockedClock = () => lockedAt;

    setLoginLockout("refresh-operator", lockedClock);

    const expiredAt = new Date(
      lockedAt.getTime() + LOGKED_OUT.LOCK_DURATION_MS + 1000,
    );
    const expiredClock = () => expiredAt;

    const request = new NextRequest("http://localhost/api/auth/refresh", {
      method: "POST",
      headers: { cookie: operatorCookie() },
    });

    const response = await POST(request, { clock: expiredClock });
    expect(response.status).toBe(200);

    const payload = (await response.json()) as {
      ok: boolean;
      user: { userId: string; role: string };
    };

    expect(payload.ok).toBe(true);
    expect(payload.user.userId).toBe("refresh-operator");
  });
});
