import { Keypair } from "@stellar/stellar-sdk";
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AgentAction, AuditEntry, SecurityEvaluation } from "@/lib/types/domain";

const evaluateSecurity = vi.fn<(action: AgentAction) => Promise<SecurityEvaluation>>();
const checkBlocklist = vi.fn();
const buildPaymentQuoteFromDecision = vi.fn();
const appendAuditEntry = vi.fn();
const stellarClientCalls = vi.fn();

vi.mock("@/lib/security/analyzer", () => ({
  evaluateSecurity: (action: AgentAction) => evaluateSecurity(action),
}));
vi.mock("@/lib/security/blocklist", () => ({
  checkBlocklist: (domain: string) => checkBlocklist(domain),
}));
vi.mock("@/lib/stellar/verify-payment-quote", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/stellar/verify-payment-quote")>()),
  buildPaymentQuoteFromDecision: (input: unknown) => buildPaymentQuoteFromDecision(input),
}));
vi.mock("@/lib/stellar/client", () => ({
  getHorizonServer: () => stellarClientCalls("getHorizonServer"),
  buildUnsignedPaymentTransaction: () => stellarClientCalls("buildUnsignedPaymentTransaction"),
  submitSignedTransactionXdr: () => stellarClientCalls("submitSignedTransactionXdr"),
}));
vi.mock("@/lib/storage/audit-store", () => ({
  appendAuditEntry: (userId: string, entry: AuditEntry) => appendAuditEntry(userId, entry),
  consumeUsage: vi.fn(async () => undefined),
  getDailyUsage: vi.fn(async () => ({ date: "2026-01-01", spentXLM: 0, toolCalls: 0 })),
}));

vi.mock("@/lib/storage/policy-store", async () => {
  const { defaultPolicyConfig } = await import("@/lib/policy/engine");
  return {
    getPolicyConfig: async () => ({ policy: { ...defaultPolicyConfig, allowedHours: undefined } }),
  };
});

import { POST } from "@/app/api/decision/route";
import { AUTH_COOKIE_KEY, createSessionToken } from "@/lib/auth/session";

const destination = Keypair.random().publicKey();

function operatorCookie() {
  process.env.FORTEXA_AUTH_SECRET = "integration-test-secret";
  const token = createSessionToken({
    email: "operator@fortexa.local",
    role: "operator",
    userId: "agreement-operator-id",
    expiresInSeconds: 120,
  });
  return `${AUTH_COOKIE_KEY}=${token}`;
}

function decisionRequest() {
  return new NextRequest("http://localhost/api/decision", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: operatorCookie() },
    body: JSON.stringify({
      action: {
        id: "agreement-action",
        name: "Research API payment",
        kind: "api_payment",
        target: "research-pro:query/alpha",
        domain: "api.safe-research.ai",
        amountXLM: 18,
        tool: "research-pro",
      },
      paymentQuoteInput: { destination, network: "testnet" },
    }),
  });
}

const cleanAnalyzer: SecurityEvaluation = {
  riskScore: 10,
  findings: [],
  analyzerStatus: { blocklistStatus: "success", isDegraded: false, degradationReasons: [] },
};

describe("/api/decision analyzer + blocklist agreement", () => {
  beforeEach(() => {
    evaluateSecurity.mockReset();
    checkBlocklist.mockReset();
    buildPaymentQuoteFromDecision.mockReset().mockReturnValue({ destination });
    appendAuditEntry.mockReset().mockImplementation(async (_u: string, entry: AuditEntry) => entry);
    stellarClientCalls.mockReset();
  });

  it("stores one allow and builds the quote when both checks allow", async () => {
    evaluateSecurity.mockResolvedValue(cleanAnalyzer);
    checkBlocklist.mockResolvedValue({ allow: true, reasonCode: null });

    const response = await POST(decisionRequest());
    expect(response.status).toBe(200);

    expect(appendAuditEntry).toHaveBeenCalledTimes(1);
    const stored = appendAuditEntry.mock.calls[0][1] as AuditEntry;
    expect(stored.decision).toBe("APPROVE");
    expect(stored.reasonCode).toBeUndefined();
    expect(buildPaymentQuoteFromDecision).toHaveBeenCalledTimes(1);
  });

  it("stores a deny with the analyzer reason code and builds no payment", async () => {
    evaluateSecurity.mockResolvedValue({
      ...cleanAnalyzer,
      riskScore: 45,
      findings: [
        {
          code: "PROMPT_INJECTION_PATTERN",
          title: "Prompt injection",
          detail: "flagged",
          severity: "high",
          scoreDelta: 35,
        },
      ],
    });
    checkBlocklist.mockResolvedValue({ allow: true, reasonCode: null });

    const response = await POST(decisionRequest());
    expect(response.status).toBe(200);

    const stored = appendAuditEntry.mock.calls[0][1] as AuditEntry;
    expect(stored.decision).toBe("BLOCK");
    expect(stored.reasonCode).toBe("PROMPT_INJECTION_PATTERN");
    expect(stored.paymentQuote).toBeUndefined();
    expect(buildPaymentQuoteFromDecision).not.toHaveBeenCalled();
    expect(stellarClientCalls).not.toHaveBeenCalled();
  });

  it("stores a deny with the blocklist reason code and builds no payment", async () => {
    evaluateSecurity.mockResolvedValue(cleanAnalyzer);
    checkBlocklist.mockResolvedValue({ allow: false, reasonCode: "BLOCKLIST_MATCH" });

    const response = await POST(decisionRequest());
    expect(response.status).toBe(200);

    const stored = appendAuditEntry.mock.calls[0][1] as AuditEntry;
    expect(stored.decision).toBe("BLOCK");
    expect(stored.reasonCode).toBe("BLOCKLIST_MATCH");
    expect(stored.paymentQuote).toBeUndefined();
    expect(buildPaymentQuoteFromDecision).not.toHaveBeenCalled();
    expect(stellarClientCalls).not.toHaveBeenCalled();
  });
});
