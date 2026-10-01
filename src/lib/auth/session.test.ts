import { createHmac } from "node:crypto";

import { describe, expect, it } from "vitest";

import { createSessionToken, verifySessionToken } from "@/lib/auth/session";

describe("auth session", () => {
  it("creates and verifies a valid token", () => {
    process.env.FORTEXA_AUTH_SECRET = "unit-test-secret";

    const token = createSessionToken({
      email: "operator@fortexa.local",
      role: "operator",
      userId: "user-123",
      expiresInSeconds: 60,
    });

    const session = verifySessionToken(token);

    expect(session).not.toBeNull();
    expect(session?.email).toBe("operator@fortexa.local");
    expect(session?.role).toBe("operator");
    expect(session?.userId).toBe("user-123");
  });

  it("rejects tampered token", () => {
    process.env.FORTEXA_AUTH_SECRET = "unit-test-secret";

    const token = createSessionToken({
      email: "viewer@fortexa.local",
      role: "viewer",
      userId: "user-xyz",
      expiresInSeconds: 60,
    });

    const [payload] = token.split(".");
    const tampered = `${payload}.invalid-signature`;

    const session = verifySessionToken(tampered);
    expect(session).toBeNull();
  });

  it("rejects a correctly signed token that has no session id", () => {
    process.env.FORTEXA_AUTH_SECRET = "unit-test-secret";

    // Logout revokes by session id, so a token without one could never be
    // revoked and must not authenticate.
    const payload = Buffer.from(
      JSON.stringify({
        userId: "user-123",
        email: "operator@fortexa.local",
        role: "operator",
        exp: Math.floor(Date.now() / 1000) + 60,
      })
    ).toString("base64url");
    const signature = createHmac("sha256", "unit-test-secret").update(payload).digest("base64url");

    expect(verifySessionToken(`${payload}.${signature}`)).toBeNull();
  });

  it("keeps a given session id and mints a new one otherwise", () => {
    process.env.FORTEXA_AUTH_SECRET = "unit-test-secret";

    const carried = createSessionToken({ email: "e", role: "viewer", userId: "u", sessionId: "sid-1" });
    const first = createSessionToken({ email: "e", role: "viewer", userId: "u" });
    const second = createSessionToken({ email: "e", role: "viewer", userId: "u" });

    expect(verifySessionToken(carried)?.sid).toBe("sid-1");
    expect(verifySessionToken(first)?.sid).toBeTruthy();
    expect(verifySessionToken(first)?.sid).not.toBe(verifySessionToken(second)?.sid);
  });
});
