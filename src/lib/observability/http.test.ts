import { afterEach, describe, expect, it, vi } from "vitest";

import { logHttpExchange } from "@/lib/observability/http";

describe("logHttpExchange", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("drops a fixture secret from a login body and keeps method, path, and status", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);

    logHttpExchange({
      method: "POST",
      path: "/api/auth/login",
      status: 401,
      requestBody: {
        publicKey: "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L",
        secret: "fixture-secret-value",
        signature: "login-signature-value",
        challenge: "challenge-raw-value",
      },
      responseBody: { error: "Wallet signature verification failed.", status: "denied" },
    });

    const logged = log.mock.calls.map((call) => String(call[0])).join("\n");
    expect(logged).not.toContain("fixture-secret-value");
    expect(logged).not.toContain("login-signature-value");
    expect(logged).not.toContain("challenge-raw-value");
    expect(logged).toContain("POST");
    expect(logged).toContain("/api/auth/login");
    expect(logged).toContain("401");
  });

  it("drops signed XDR from a submit body and keeps the path and status", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const signedXdr = "AAAA-signed-xdr-fixture-value";

    logHttpExchange({
      method: "POST",
      path: "/api/stellar/submit-signed",
      status: 200,
      requestBody: { signedXdr, memo: "payment-memo-value" },
      responseBody: { ok: true, signedXdr },
    });

    const logged = log.mock.calls.map((call) => String(call[0])).join("\n");
    expect(logged).not.toContain(signedXdr);
    expect(logged).not.toContain("payment-memo-value");
    expect(logged).toContain("/api/stellar/submit-signed");
    expect(logged).toContain("200");
  });

  it("redacts a decision body and does not log a body that failed the size limit", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const oversized = "oversized-body-secret";

    logHttpExchange({
      method: "POST",
      path: "/api/decision",
      status: 413,
      requestBody: { secret: oversized, password: "pw-value" },
      responseBody: { error: "Request body exceeds the limit." },
      requestBodyTooLarge: true,
    });

    const logged = log.mock.calls.map((call) => String(call[0])).join("\n");
    expect(logged).not.toContain(oversized);
    expect(logged).not.toContain("pw-value");
    expect(logged).not.toContain("requestBody");
    expect(logged).toContain("/api/decision");
    expect(logged).toContain("413");
    expect(logged).toContain("Request body exceeds the limit.");
  });
});
