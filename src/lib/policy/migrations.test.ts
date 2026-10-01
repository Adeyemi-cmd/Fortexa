import { describe, expect, it } from "vitest";

import { defaultPolicyConfig } from "@/lib/policy/engine";
import { parseStoredPolicy } from "@/lib/policy/migrations";

import currentValid from "./__fixtures__/policy-current-valid.json";
import malformedWrongTypes from "./__fixtures__/policy-malformed-types.json";
import midMigrationFailure from "./__fixtures__/policy-mid-migration-failure.json";
import olderMissingHours from "./__fixtures__/policy-older-missing-allowed-hours.json";
import unknownVersion from "./__fixtures__/policy-unknown-version.json";

describe("parseStoredPolicy smoke tests", () => {
  it("loads the current valid fixture without any migration", () => {
    const result = parseStoredPolicy(currentValid);

    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(`expected ok, received error: ${result.error}`);
    }

    expect(result.migrations).toEqual([]);
    expect(result.version).toBe(currentValid.schemaVersion);
    expect(result.policy.allowedHours).toEqual(defaultPolicyConfig.allowedHours);
    expect(result.policy.perTxCapXLM).toBe(120);
    expect(result.policy.allowedTools).toContain("research-pro");
  });

  it("migrates an older fixture missing the optional allowedHours field", () => {
    const result = parseStoredPolicy(olderMissingHours);

    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(`expected ok after migration, received error: ${result.error}`);
    }

    expect(result.migrations).toHaveLength(1);
    expect(result.migrations[0]).toMatchObject({
      field: "allowedHours",
      reason: "missing-optional-default",
      filledFrom: "defaultPolicyConfig",
    });

    expect(result.policy.allowedHours).toEqual(defaultPolicyConfig.allowedHours);

    // Persisted values are preserved as-is, never overwritten by defaults.
    expect(result.policy.perTxCapXLM).toBe(olderMissingHours.perTxCapXLM);
    expect(result.policy.dailyCapXLM).toBe(olderMissingHours.dailyCapXLM);
    expect(result.policy.riskThreshold).toBe(olderMissingHours.riskThreshold);
  });

  it("rejects a malformed fixture with a clear structured error", () => {
    const result = parseStoredPolicy(malformedWrongTypes);

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("expected malformed payload to be rejected");
    }

    expect(result.error.toLowerCase()).toContain("malformed");

    // Every surfaced issue has a non-empty path and message so operators can
    // act on them without guesswork.
    expect(result.issues.length).toBeGreaterThan(0);
    for (const issue of result.issues) {
      expect(issue.path.length).toBeGreaterThan(0);
      expect(issue.message.length).toBeGreaterThan(0);
    }

    const joined = result.error.toLowerCase();
    expect(joined).toContain("blockeddomains");
    expect(joined).toContain("pertxcapxlm");
    expect(joined).toContain("riskthreshold");

    // Nested paths must also surface so operators can pinpoint descendants.
    const issuePaths = result.issues.map((i) => i.path.toLowerCase());
    expect(issuePaths).toContain("allowedhours.start");
  });

  it("surfaces out-of-range but type-valid values as clear errors", () => {
    // perTxCapXLM must be positive, dailyCapXLM must be positive,
    // riskThreshold must be <= 100. None of those are in OPTIONAL_DEFAULTS
    // so migration must not occur; the helper must surface each constraint
    // failure individually.
    const result = parseStoredPolicy({
      allowedDomains: ["api.safe-research.ai"],
      blockedDomains: ["wallet-drainer.evil"],
      allowedTools: ["research-pro"],
      blockedTools: ["shadow-shell"],
      perTxCapXLM: -1,
      dailyCapXLM: 0,
      maxToolCallsPerDay: 8,
      riskThreshold: 250,
      allowedHours: { start: 0, end: 23 },
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("expected range-violating payload to be rejected");
    }

    const paths = result.issues.map((issue) => issue.path.toLowerCase());
    expect(paths).toContain("pertxcapxlm");
    expect(paths).toContain("dailycapxlm");
    expect(paths).toContain("riskthreshold");
  });

  it("refuses to migrate when missing optionals are mixed with other failures", () => {
    // allowedHours is missing (migratable) but perTxCapXLM is the wrong
    // type (cannot be migrated). The helper must surface both issues
    // without silently applying the default, preserving the guardrail that
    // migration never weakens strict validation.
    const result = parseStoredPolicy({
      allowedDomains: ["api.safe-research.ai"],
      blockedDomains: ["wallet-drainer.evil"],
      allowedTools: ["research-pro"],
      blockedTools: ["shadow-shell"],
      perTxCapXLM: "not-a-number",
      dailyCapXLM: 10,
      maxToolCallsPerDay: 5,
      riskThreshold: 50,
    });

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("expected mixed-failure payload to be rejected");
    }

    const paths = result.issues.map((issue) => issue.path.toLowerCase());
    expect(paths).toContain("pertxcapxlm");
    expect(paths).toContain("allowedhours");
  });

  it("returns ok for a minimum-viable valid payload", () => {
    const result = parseStoredPolicy({
      allowedDomains: ["api.safe-research.ai"],
      blockedDomains: ["wallet-drainer.evil"],
      allowedTools: ["research-pro"],
      blockedTools: ["shadow-shell"],
      perTxCapXLM: 1,
      dailyCapXLM: 1,
      maxToolCallsPerDay: 1,
      riskThreshold: 1,
      allowedHours: { start: 0, end: 23 },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(`expected ok, received error: ${result.error}`);
    }
    expect(result.migrations).toEqual([]);
  });

  it("returns a structured error when given non-object input", () => {
    const result = parseStoredPolicy("not-a-policy");

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("expected non-object input to be rejected");
    }

    expect(result.error.toLowerCase()).toContain("malformed");
    expect(result.issues.length).toBeGreaterThan(0);
  });

  it("rejects an unknown schema version without attempting migration", () => {
    const result = parseStoredPolicy(unknownVersion);

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("expected unknown version to be rejected");
    }

    expect(result.error.toLowerCase()).toContain("unknown policy schema version");
    expect(result.version).toBe(unknownVersion.schemaVersion);
  });

  it("rejects a document that fails mid-migration and reports the failing version", () => {
    const result = parseStoredPolicy(midMigrationFailure);

    expect(result.ok).toBe(false);
    if (result.ok) {
      throw new Error("expected mid-migration failure to be rejected");
    }

    expect(result.version).toBe(midMigrationFailure.schemaVersion);
    expect(result.issues.length).toBeGreaterThan(0);
  });

  it("rejects a document whose migration silently changes a rule type", () => {
    // allowedHours is missing and would be filled by the optional default,
    // but the raw document carries an array for allowedHours that the
    // schema would coerce to a different shape. The guard must reject it
    // rather than accept a silent type flip.
    const result = parseStoredPolicy({
      schemaVersion: 1,
      allowedDomains: ["api.safe-research.ai"],
      blockedDomains: ["wallet-drainer.evil"],
      allowedTools: ["research-pro"],
      blockedTools: ["shadow-shell"],
      perTxCapXLM: 50,
      dailyCapXLM: 200,
      maxToolCallsPerDay: 5,
      riskThreshold: 60,
      allowedHours: [6, 23],
    });

    expect(result.ok).toBe(false);
  });
});
