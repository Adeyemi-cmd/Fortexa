import { NextResponse } from "next/server";

import { DuplicateRuleError, validateNoDuplicateRules } from "@/lib/policy/engine";
import { policyConfigSchema } from "@/lib/validation/schemas";
import { toPublicValidationDetails } from "@/lib/validation/errors";

/**
 * POST /api/policy/validate
 *
 * Validates a policy JSON against the schema without saving.
 * This is the single source of truth for policy activation: the editor must
 * receive `valid: true` here before it may POST to /api/policy.
 *
 * Body: { policy: unknown }
 * Response:
 *   200 { valid: true, data }
 *   400 { valid: false, errors: string[], fieldErrors?: Record<string, string[]> }
 *   422 { valid: false, errors: string[], code, field, duplicateValue, fieldErrors }
 */
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { policy } = body;

    if (!policy) {
      return NextResponse.json(
        {
          valid: false,
          errors: ["No policy data provided"],
        },
        { status: 400 }
      );
    }

    // Validate against schema
    const result = policyConfigSchema.safeParse(policy);

    if (!result.success) {
      const details = toPublicValidationDetails(result.error);

      return NextResponse.json(
        {
          valid: false,
          errors: result.error.issues.map(
            (issue) => `${issue.path.join(".") || "root"}: ${issue.message}`,
          ),
          // Per-field errors keyed by path so the editor renders exactly
          // what the API returned without re-deriving anything.
          fieldErrors: details.fieldErrors,
        },
        { status: 400 }
      );
    }

    // Check for duplicate rule identifiers
    try {
      validateNoDuplicateRules(result.data);
    } catch (error) {
      if (error instanceof DuplicateRuleError) {
        return NextResponse.json(
          {
            valid: false,
            errors: [error.message],
            code: "DUPLICATE_RULE_IDENTIFIER",
            field: error.field,
            duplicateValue: error.value,
            fieldErrors: { [error.field]: [error.message] },
          },
          { status: 422 }
        );
      }
      throw error;
    }

    // Valid policy
    return NextResponse.json(
      {
        valid: true,
        data: result.data,
      },
      { status: 200 }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";

    return NextResponse.json(
      {
        valid: false,
        errors: [message],
      },
      { status: 500 }
    );
  }
}