import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";

import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";
import { POST } from "@/app/api/policy/rollback/route";
import { updatePolicyConfig } from "@/lib/storage/policy-store";
import { appendAuditEntry, resetAuditState } from "@/lib/storage/audit-store";
import { putIdempotencyRecord, resetSubmitIdempotencyState } from "@/lib/storage/submit-idempotency-store";
import { defaultPolicyConfig } from "@/lib/policy/engine";
import { randomUUID } from "node:crypto";

function operatorCookie() {
  process.env.FORTEXA_AUTH_SECRET = "integration-test-secret";
  const token = createSessionToken({
    email: "operator@fortexa.local",
    role: "operator",
    userId: "policy-rollback-operator",
    expiresInSeconds: 120,
  });

  return `${AUTH_COOKIE_KEY}=${token}`;
}

describe("/api/policy/rollback route", () => {
  it("returns 401 when unauthenticated", async () => {
    const request = new NextRequest("http://localhost/api/policy/rollback", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ targetVersion: 1 }),
    });

    const response = await POST(request);
    expect(response.status).toBe(401);
  });

  it("allows operator rollback to version 1", async () => {
    const request = new NextRequest("http://localhost/api/policy/rollback", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: operatorCookie(),
      },
      body: JSON.stringify({ targetVersion: 1 }),
    });

    const response = await POST(request);
    expect(response.status).toBe(200);
  });

  it("rejects rollback when an in-flight allow would become deny", async () => {
    await resetAuditState("policy-rollback-operator");
    await resetSubmitIdempotencyState("policy-rollback-operator");

    const v2 = await updatePolicyConfig({ ...defaultPolicyConfig, perTxCapXLM: 10 });
    const v3 = await updatePolicyConfig({ ...defaultPolicyConfig, perTxCapXLM: 1000 });

    const entryId = randomUUID();
    await appendAuditEntry("policy-rollback-operator", {
      id: entryId,
      timestamp: new Date().toISOString(),
      action: {
        id: "action-1",
        name: "Test Payment",
        kind: "api_payment",
        target: "GABC...",
        domain: "example.com",
        amountXLM: 100,
      },
      decision: "APPROVE",
      explanation: "ok",
      triggeredPolicies: [],
      riskFindings: [],
      paymentQuote: {
        destination: "GABC...",
        amountXLM: "100",
        asset: "native",
        memo: "test",
        network: "testnet"
      }
    });

    await putIdempotencyRecord("policy-rollback-operator", entryId, {
       xdrHash: "hash",
       result: { ok: true }
    });

    const request = new NextRequest("http://localhost/api/policy/rollback", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: operatorCookie(),
      },
      body: JSON.stringify({ targetVersion: v2.version }),
    });

    const response = await POST(request);
    expect(response.status).toBe(409);
    
    const body = await response.json();
    expect(body.conflictingPaymentIds).toContain(entryId);
  });

  it("proceeds with rollback when no reserved payment changes", async () => {
    await resetAuditState("policy-rollback-operator");
    await resetSubmitIdempotencyState("policy-rollback-operator");

    const v2 = await updatePolicyConfig({ ...defaultPolicyConfig, perTxCapXLM: 10 });
    const v3 = await updatePolicyConfig({ ...defaultPolicyConfig, perTxCapXLM: 1000 });

    const entryId = randomUUID();
    await appendAuditEntry("policy-rollback-operator", {
      id: entryId,
      timestamp: new Date().toISOString(),
      action: {
        id: "action-2",
        name: "Test Payment Small",
        kind: "api_payment",
        target: "GABC...",
        domain: "example.com",
        amountXLM: 5,
      },
      decision: "APPROVE",
      explanation: "ok",
      triggeredPolicies: [],
      riskFindings: [],
      paymentQuote: {
        destination: "GABC...",
        amountXLM: "5",
        asset: "native",
        memo: "test",
        network: "testnet"
      }
    });

    await putIdempotencyRecord("policy-rollback-operator", entryId, {
       xdrHash: "hash2",
       result: { ok: true }
    });

    const request = new NextRequest("http://localhost/api/policy/rollback", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: operatorCookie(),
      },
      body: JSON.stringify({ targetVersion: v2.version }),
    });

    const response = await POST(request);
    expect(response.status).toBe(200);
  });
});
