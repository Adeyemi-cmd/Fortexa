import { describe, expect, it } from "vitest";

import { hasSensitiveField } from "@/lib/settings/save-safety";

describe("settings save safety", () => {
  it("blocks nested secret, session token, and network passphrase fields", () => {
    expect(hasSensitiveField({ policy: { apiSecret: "fixture-secret" } })).toBe(true);
    expect(hasSensitiveField({ auth: [{ sessionToken: "fixture-token" }] })).toBe(true);
    expect(hasSensitiveField({ networkPassphrase: "fixture-passphrase" })).toBe(true);
  });

  it("allows public policy fields", () => {
    expect(hasSensitiveField({ allowedDomains: ["example.com"], riskThreshold: 50 })).toBe(false);
  });
});
