import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AgentAction, SecurityEvaluation } from "@/lib/types/domain";

const evaluateSecurity = vi.fn<(action: AgentAction) => Promise<SecurityEvaluation>>();
const checkBlocklist = vi.fn();

vi.mock("@/lib/security/analyzer", () => ({
  evaluateSecurity: (action: AgentAction) => evaluateSecurity(action),
}));
vi.mock("@/lib/security/blocklist", () => ({
  checkBlocklist: (domain: string) => checkBlocklist(domain),
}));

import { evaluateDecision } from "@/lib/decision/engine";
import { defaultPolicyConfig } from "@/lib/policy/engine";
import { defaultDailyUsage } from "@/lib/scenarios/seed";

const policy = { ...defaultPolicyConfig, allowedHours: undefined };

const action: AgentAction = {
  id: "agree-1",
  name: "Research API payment",
  kind: "api_payment",
  target: "research-pro:query/alpha",
  domain: "api.safe-research.ai",
  amountXLM: 18,
  tool: "research-pro",
};

function analyzerAllows(): SecurityEvaluation {
  return {
    riskScore: 10,
    findings: [],
    analyzerStatus: { blocklistStatus: "success", isDegraded: false, degradationReasons: [] },
  };
}

function analyzerDenies(): SecurityEvaluation {
  return {
    riskScore: 55,
    findings: [
      {
        code: "DOMAIN_REPUTATION_HIGH_RISK",
        title: "High-risk destination",
        detail: "flagged",
        severity: "high",
        scoreDelta: 45,
      },
    ],
    analyzerStatus: { blocklistStatus: "success", isDegraded: false, degradationReasons: [] },
  };
}

describe("evaluateDecision requires analyzer and blocklist agreement", () => {
  beforeEach(() => {
    evaluateSecurity.mockReset();
    checkBlocklist.mockReset();
  });

  it("approves only when both checks allow", async () => {
    evaluateSecurity.mockResolvedValue(analyzerAllows());
    checkBlocklist.mockResolvedValue({ allow: true, reasonCode: null });

    const result = await evaluateDecision(action, policy, defaultDailyUsage);

    expect(result.decision).toBe("APPROVE");
    expect(result.reasonCode).toBeUndefined();
    expect(evaluateSecurity).toHaveBeenCalledTimes(1);
    expect(checkBlocklist).toHaveBeenCalledWith(action.domain);
  });

  it("blocks with the analyzer reason code when only the analyzer denies", async () => {
    evaluateSecurity.mockResolvedValue(analyzerDenies());
    checkBlocklist.mockResolvedValue({ allow: true, reasonCode: null });

    const result = await evaluateDecision(action, policy, defaultDailyUsage);

    expect(result.decision).toBe("BLOCK");
    expect(result.reasonCode).toBe("DOMAIN_REPUTATION_HIGH_RISK");
  });

  it("blocks with the blocklist reason code when only the blocklist denies", async () => {
    evaluateSecurity.mockResolvedValue(analyzerAllows());
    checkBlocklist.mockResolvedValue({ allow: false, reasonCode: "BLOCKLIST_MATCH" });

    const result = await evaluateDecision(action, policy, defaultDailyUsage);

    expect(result.decision).toBe("BLOCK");
    expect(result.reasonCode).toBe("BLOCKLIST_MATCH");
  });
});
