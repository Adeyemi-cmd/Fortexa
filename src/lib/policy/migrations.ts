import { z } from "zod";

import { defaultPolicyConfig } from "@/lib/policy/engine";
import type { PolicyConfig } from "@/lib/types/domain";
import { policyConfigSchema } from "@/lib/validation/schemas";

/**
 * Policy migration smoke-test helper.
 *
 * Goals:
 * - Verify that representative historical policy payloads still load after
 *   schema changes.
 * - Either accept them, migrate them via an explicit narrow set of
 *   documented default-fill steps, or reject them with a structured error
 *   an operator can act on.
 *
 * Behavior:
 * 1. Strict-parse the candidate against `policyConfigSchema`.
 * 2. If strict-parse fails and the only issues are missing documented
 *    optional fields (those with a safe default in `OPTIONAL_DEFAULTS`),
 *    fill them with the documented default and re-parse.
 * 3. If re-parse still fails, or if any non-optional / type-related issue
 *    is present, return a `{ ok: false, error, issues }` result describing
 *    every Zod issue.
 *
 * Guardrails:
 * - This helper is pure: it does not read or write `.fortexa/` policy
 *   files. Calls decide what to persist.
 * - It does not weaken `policyConfigSchema`. Migration only fills fields
 *   that are explicitly listed in `OPTIONAL_DEFAULTS`. Wrong-type or
 *   otherwise invalid values always surface as errors.
 *
 * Future schema changes: when adding a new optional field with a safe
 * default, register it in `OPTIONAL_DEFAULTS` and add a fixture under
 * `__fixtures__/` that exercises the unmigrated shape. Add a test asserting
 * that `parseStoredPolicy` migrates it cleanly.
 */

export type PolicyMigration = {
  field: string;
  reason: "missing-optional-default";
  filledFrom: "defaultPolicyConfig";
};

export type PolicyParseSuccess = {
  ok: true;
  policy: PolicyConfig;
  migrations: PolicyMigration[];
};

export type PolicyParseFailure = {
  ok: false;
  error: string;
  issues: { path: string; message: string }[];
};

export type PolicyParseResult = PolicyParseSuccess | PolicyParseFailure;

/**
 * Documented optional fields with safe defaults.
 *
 * Each entry must be safe to fill silently when an older stored payload
 * predates the field's introduction. Do not add fields whose absence is
 * potentially intentional or whose default could mask unsafe operator
 * intent — those belong as required fields with strict validation.
 */
const OPTIONAL_DEFAULTS: Record<string, unknown> = {
  allowedHours: defaultPolicyConfig.allowedHours,
};

function formatFailure(error: z.ZodError): PolicyParseFailure {
  const issues = error.issues.map((issue) => ({
    path: issue.path.map(String).join(".") || "<root>",
    message: issue.message,
  }));

  const summary = issues
    .map((issue) => `${issue.path}: ${issue.message}`)
    .join("; ");

  return {
    ok: false,
    error: `Stored policy payload is malformed. ${summary}`,
    issues,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Decide whether every top-level failing path is a documented optional
 * field that is entirely missing from the raw input. Returns the list of
 * fields we can migrate, or `null` when any issue is non-migratable.
 */
function findMigratableFields(
  raw: Record<string, unknown>,
  paths: Set<string>,
): string[] | null {
  const fields: string[] = [];

  for (const path of paths) {
    if (!(path in OPTIONAL_DEFAULTS) || path in raw) {
      return null;
    }
    fields.push(path);
  }

  return fields.length > 0 ? fields : null;
}

export function parseStoredPolicy(raw: unknown): PolicyParseResult {
  const strict = policyConfigSchema.safeParse(raw);
  if (strict.success) {
    return { ok: true, policy: strict.data, migrations: [] };
  }

  if (!isPlainObject(raw)) {
    return formatFailure(strict.error);
  }

  const issuePaths = new Set(
    strict.error.issues.map((issue) => {
      const head = issue.path[0];
      return head === undefined ? "" : String(head);
    }),
  );

  const migratableFields = findMigratableFields(raw, issuePaths);
  if (!migratableFields) {
    return formatFailure(strict.error);
  }

  const attempted: Record<string, unknown> = { ...raw };
  const migrations: PolicyMigration[] = [];

  for (const field of migratableFields) {
    attempted[field] = OPTIONAL_DEFAULTS[field];
    migrations.push({
      field,
      reason: "missing-optional-default",
      filledFrom: "defaultPolicyConfig",
    });
  }

  const migrated = policyConfigSchema.safeParse(attempted);
  if (migrated.success) {
    return { ok: true, policy: migrated.data, migrations };
  }

  return formatFailure(migrated.error);
}
