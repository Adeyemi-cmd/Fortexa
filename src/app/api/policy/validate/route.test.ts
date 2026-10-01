import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";

import { POST } from "@/app/api/policy/validate/route";

function makeValidateRequest(body: unknown) {
  return new NextRequest("http://localhost/api/policy/validate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const VALID_POLICY = {
  allowedDomains: ["api.example.com"],
  blockedDomains: ["malicious.com"],
  allowedTools: ["research-pro"],
  blockedTools: ["shadow-shell"],
  perTxCapXLM: 150,
  dailyCapXLM: 300,
  maxToolCallsPerDay: 10,
  riskThreshold: 80,
  allowedHours: { start: 6, end: 23 },
};

describe("/api/policy/validate route", () => {
  it("accepts a valid policy document with 200", async () => {
    const response = await POST(makeValidateRequest({ policy: VALID_POLICY }));

    expect(response.status).toBe(200);
    const payload = (await response.json()) as { valid: boolean; data?: unknown };
    expect(payload.valid).toBe(true);
    expect(payload.data).toBeDefined();
  });

  it("returns 400 with per-field errors for an invalid rule", async () => {
    const invalid = { ...VALID_POLICY, perTxCapXLM: -5 };
    const response = await POST(makeValidateRequest({ policy: invalid }));

    expect(response.status).toBe(400);
    const payload = (await response.json()) as {
      valid: boolean;
      errors?: string[];
      fieldErrors?: Record<string, string[]>;
    };

    expect(payload.valid).toBe(false);
    expect(payload.errors?.length).toBeGreaterThan(0);

    // The error strings are `path: message` lines for the offending field.
    expect(payload.errors?.some((line) => line.startsWith("perTxCapXLM: "))).toBe(true);

    // Per-field map is returned verbatim for the editor to render.
    expect(payload.fieldErrors?.perTxCapXLM?.length).toBeGreaterThan(0);
  });

  it("returns 400 field errors for an empty rule list", async () => {
    const invalid = { ...VALID_POLICY, allowedDomains: [] };
    const response = await POST(makeValidateRequest({ policy: invalid }));

    expect(response.status).toBe(400);
    const payload = (await response.json()) as {
      valid: boolean;
      fieldErrors?: Record<string, string[]>;
    };

    expect(payload.valid).toBe(false);
    expect(payload.fieldErrors?.allowedDomains?.length).toBeGreaterThan(0);
  });

  it("returns 422 with the duplicate rule identifier error", async () => {
    const invalid = {
      ...VALID_POLICY,
      allowedDomains: ["dup.example.com", "dup.example.com"],
    };
    const response = await POST(makeValidateRequest({ policy: invalid }));

    expect(response.status).toBe(422);
    const payload = (await response.json()) as {
      valid: boolean;
      errors?: string[];
      code?: string;
      field?: string;
      duplicateValue?: string;
      fieldErrors?: Record<string, string[]>;
    };

    expect(payload.valid).toBe(false);
    expect(payload.code).toBe("DUPLICATE_RULE_IDENTIFIER");
    expect(payload.field).toBe("allowedDomains");
    expect(payload.duplicateValue).toBe("dup.example.com");
    expect(payload.errors?.[0]).toContain('Duplicate rule identifier "dup.example.com"');
    expect(payload.fieldErrors?.allowedDomains?.[0]).toContain("dup.example.com");
  });

  it("returns 400 when no policy is provided", async () => {
    const response = await POST(makeValidateRequest({}));

    expect(response.status).toBe(400);
    const payload = (await response.json()) as { valid: boolean; errors?: string[] };
    expect(payload.valid).toBe(false);
    expect(payload.errors).toEqual(["No policy data provided"]);
  });

  it("returns 500 for a malformed JSON body", async () => {
    const response = await POST(makeValidateRequest("{not-json"));

    expect(response.status).toBe(500);
    const payload = (await response.json()) as { valid: boolean; errors?: string[] };
    expect(payload.valid).toBe(false);
    expect(payload.errors?.length).toBeGreaterThan(0);
  });
});
