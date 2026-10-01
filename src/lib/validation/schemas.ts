import { z } from "zod";

const actionKindSchema = z.enum([
  "api_payment",
  "tool_access",
  "transfer",
  "endpoint_call",
]);

const metadataValueSchema = z.union([z.string(), z.number(), z.boolean()]);

const agentActionShape = {
  id: z.string().min(1).max(120),
  name: z.string().min(3).max(200),
  kind: actionKindSchema,
  target: z.string().min(3).max(400),
  domain: z.string().min(3).max(255),
  amountXLM: z.number().positive().max(100000),
  tool: z.string().min(1).max(120).optional(),
  outputPreview: z.string().min(1).max(2000).optional(),
  metadata: z.record(z.string(), metadataValueSchema).optional(),
};

export const agentActionSchema = z.object(agentActionShape);

/**
 * Strict variant of the action schema used for untrusted model output: unknown
 * keys are rejected instead of silently stripped.
 */
const strictAgentActionSchema = z.strictObject(agentActionShape);

const stellarPublicKeySchema = z
  .string()
  .startsWith("G", { message: "Destination must be a Stellar public key." })
  .min(56)
  .max(56);

const paymentQuoteInputSchema = z.object({
  destination: stellarPublicKeySchema,
  memo: z.string().max(28).optional(),
  network: z.enum(["testnet"]).default("testnet"),
});

export const decisionRequestSchema = z
  .object({
    scenarioId: z.string().min(1).max(120).optional(),
    action: agentActionSchema.optional(),
    approvedByHuman: z.boolean().optional(),
    paymentQuoteInput: paymentQuoteInputSchema.optional(),
  })
  .refine((data) => Boolean(data.scenarioId || data.action), {
    message: "Either scenarioId or action is required.",
    path: ["scenarioId"],
  });

export const stellarSetupRequestSchema = z.object({
  provider: z.string().trim().min(1).max(60).optional(),
});

export const stellarBuildPaymentRequestSchema = z.object({
  auditEntryId: z.string().uuid(),
  destination: stellarPublicKeySchema,
  amountXLM: z
    .string()
    .regex(
      /^\d+(\.\d{1,7})?$/,
      "amountXLM must be a positive decimal string with up to 7 decimals",
    ),
  asset: z.enum(["native"]).default("native"),
  memo: z.string().max(28).optional(),
  network: z.enum(["testnet"]).default("testnet"),
});

export const stellarSubmitSignedRequestSchema = z.object({
  signedXdr: z.string().min(20).max(120000),
  idempotencyKey: z.string().min(8).max(255).optional(),
});

export const agentPlanRequestSchema = z.object({
  goal: z.string().min(5).max(2000),
  context: z.string().max(4000).optional(),
  destinationHint: z.string().startsWith("G").min(56).max(56).optional(),
});

/**
 * Strict schema for raw planner output.
 *
 * Model output must match this shape exactly before anything is stored or
 * evaluated: unknown keys are rejected and no coercion/casting is performed.
 * Any drift from the schema means the payload is ignored entirely instead of
 * partially influencing an agent plan.
 */
export const agentPlanSchema = z.strictObject({
  id: z.string().min(1).max(120),
  action: strictAgentActionSchema,
});

export const policyConfigSchema = z.object({
  allowedDomains: z.array(z.string().min(3)).min(1),
  blockedDomains: z.array(z.string().min(3)).min(1),
  allowedTools: z.array(z.string().min(1)).min(1),
  blockedTools: z.array(z.string().min(1)).min(1),
  perTxCapXLM: z.number().positive().max(1_000_000),
  dailyCapXLM: z.number().positive().max(1_000_000),
  maxToolCallsPerDay: z.number().int().positive().max(10_000),
  riskThreshold: z.number().int().min(1).max(100),
  allowedHours: z.object({
    start: z.number().int().min(0).max(23),
    end: z.number().int().min(0).max(23),
  }),
});

export const policyRollbackSchema = z.object({
  targetVersion: z.number().int().positive(),
});

export const policyRollbackPreviewSchema = z.object({
  targetVersion: z.number().int().positive(),
  includeAudit: z.boolean().optional(),
  auditSampleSize: z.number().int().min(1).max(10).optional(),
});

export const policySimulateRequestSchema = z.object({
  policy: policyConfigSchema,
  includeAudit: z.boolean().optional(),
  auditSampleSize: z.number().int().min(1).max(10).optional(),
});

export type AgentActionInput = z.infer<typeof agentActionSchema>;
export type AgentPlanInput = z.infer<typeof agentPlanSchema>;
export type DecisionRequestInput = z.infer<typeof decisionRequestSchema>;
export type AgentPlanRequestInput = z.infer<typeof agentPlanRequestSchema>;
export type PolicySimulateRequestInput = z.infer<typeof policySimulateRequestSchema>;