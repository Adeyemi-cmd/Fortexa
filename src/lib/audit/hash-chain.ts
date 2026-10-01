import { createHash } from "node:crypto";

import type { AuditEntry } from "@/lib/types/domain";

export const GENESIS_HASH = "0".repeat(64);

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(obj)
        .sort()
        .map((k) => [k, canonicalize(obj[k])])
    );
  }
  return value ?? null;
}

/**
 * Produces a deterministic SHA-256 hex digest over the entry's meaningful fields
 * and the previousHash that links it to the prior entry. Object keys are sorted
 * recursively so DB-stored and file-stored entries produce the same hash.
 */
export function computeEntryHash(
  entry: Omit<AuditEntry, "entryHash"> & { previousHash: string }
): string {
  const input = {
    id: entry.id,
    timestamp: entry.timestamp,
    action: entry.action,
    decision: entry.decision,
    explanation: entry.explanation,
    triggeredPolicies: entry.triggeredPolicies,
    riskFindings: entry.riskFindings,
    stellarTxHash: entry.stellarTxHash ?? null,
    previousHash: entry.previousHash,
  };

  return createHash("sha256")
    .update(JSON.stringify(canonicalize(input)), "utf8")
    .digest("hex");
}

export type ChainVerificationResult =
  | { valid: true; checkedCount: number; legacyCount: number }
  | {
      valid: false;
      reason: string;
      entryId?: string;
      index?: number;
      checkedCount: number;
      legacyCount: number;
    };

/**
 * Maximum number of rows a single audit export may contain. Shared by every
 * export format so JSON and CSV never disagree about what is exportable.
 */
export const DEFAULT_MAX_CHAIN_ROWS = 10_000;

/** Error raised when an export must be refused instead of written. */
export class AuditChainError extends Error {
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(
    code: string,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AuditChainError";
    this.code = code;
    this.details = details;
  }
}

/** The verified chain bundle returned by {@link verifyAuditChain}. */
export interface VerifiedChain {
  entries: AuditEntry[];
  boundaries: ChainBoundaries;
  result: ChainVerificationResult;
}

/** Hashes that identify the expected boundaries of an exported chain. */
export interface ChainBoundaries {
  firstEntryHash?: string;
  lastEntryHash?: string;
}

/** Returns the boundary hashes for an export, omitting them for legacy-only data. */
export function getChainBoundaries(entries: AuditEntry[]): ChainBoundaries {
  const hashed = [...entries]
    .filter((entry) => Boolean(entry.entryHash && entry.previousHash))
    .sort((a, b) =>
      a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0,
    );

  const firstEntryHash = hashed[0]?.entryHash;
  const lastEntryHash = hashed.at(-1)?.entryHash;
  return firstEntryHash && lastEntryHash
    ? { firstEntryHash, lastEntryHash }
    : {};
}

/**
 * Verifies the integrity of an audit hash chain.
 *
 * Entries are sorted chronologically before verification so the caller does not
 * need to pre-sort. Entries without entryHash/previousHash are treated as
 * legacy (pre-chain) entries and skipped gracefully without breaking the
 * verification of newer hashed entries.
 *
 * Returns { valid: false } when:
 *  - a hashed entry's previousHash does not match the prior hashed entry's hash
 *    (detects reordering or deletion)
 *  - a hashed entry's entryHash does not match a fresh recomputation
 *    (detects field modification)
 *  - an optional boundary hash does not match the first or last hashed entry
 *    (detects deletion at either edge of an exported chain)
 */
export function verifyHashChain(
  entries: AuditEntry[],
  boundaries?: ChainBoundaries,
): ChainVerificationResult {
  const sorted = [...entries].sort((a, b) =>
    a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0
  );

  let expectedPreviousHash = GENESIS_HASH;
  let checkedCount = 0;
  let legacyCount = 0;
  let firstHashedEntryHash: string | undefined;
  let lastHashedEntryHash: string | undefined;

  for (let i = 0; i < sorted.length; i++) {
    const entry = sorted[i]!;

    if (!entry.entryHash || !entry.previousHash) {
      legacyCount++;
      continue;
    }

    // A declared first boundary identifies the beginning of an exported
    // segment, which may legitimately follow entries omitted by a filter.
    const isFirstHashedEntry = firstHashedEntryHash === undefined;
    const previousHashValid = isFirstHashedEntry
      ? boundaries?.firstEntryHash !== undefined || entry.previousHash === GENESIS_HASH
      : entry.previousHash === expectedPreviousHash;
    if (!previousHashValid) {
      return {
        valid: false,
        reason:
          "previousHash mismatch — entry may be reordered or a prior entry was deleted",
        entryId: entry.id,
        index: i,
        checkedCount,
        legacyCount,
      };
    }

    const recomputed = computeEntryHash({ ...entry, previousHash: entry.previousHash });
    if (entry.entryHash !== recomputed) {
      return {
        valid: false,
        reason: "entryHash mismatch — entry content may have been modified",
        entryId: entry.id,
        index: i,
        checkedCount,
        legacyCount,
      };
    }

    expectedPreviousHash = entry.entryHash;
    firstHashedEntryHash ??= entry.entryHash;
    lastHashedEntryHash = entry.entryHash;
    checkedCount++;
  }

  if (
    boundaries?.firstEntryHash !== undefined &&
    firstHashedEntryHash !== boundaries.firstEntryHash
  ) {
    return {
      valid: false,
      reason:
        "chain start boundary mismatch — the first exported record may have been deleted",
      entryId: sorted.find((entry) => entry.entryHash)?.id,
      checkedCount,
      legacyCount,
    };
  }

  if (
    boundaries?.lastEntryHash !== undefined &&
    lastHashedEntryHash !== boundaries.lastEntryHash
  ) {
    return {
      valid: false,
      reason:
        "chain end boundary mismatch — the last exported record may have been deleted",
      entryId: sorted.findLast((entry) => entry.entryHash)?.id,
      checkedCount,
      legacyCount,
    };
  }

  return { valid: true, checkedCount, legacyCount };
}

/**
 * Single entry point for verifiers that must agree with each other (the audit
 * export route and the integrity route).
 *
 * The row cap is enforced before verification so an over-cap export is refused
 * without hashing every row, and the returned `boundaries` are the exact ones
 * the chain was verified against so callers can echo them in the response.
 *
 * Throws {@link AuditChainError} with code `audit_chain_row_cap_exceeded` when
 * the row cap is exceeded. A broken chain is reported through `result.valid`
 * rather than thrown, so callers choose how to surface the verifier's reason.
 */
export function verifyAuditChain(
  entries: AuditEntry[],
  options: { boundaries?: ChainBoundaries; maxRows?: number } = {},
): VerifiedChain {
  const maxRows = options.maxRows ?? DEFAULT_MAX_CHAIN_ROWS;
  if (entries.length > maxRows) {
    throw new AuditChainError(
      "audit_chain_row_cap_exceeded",
      `Audit chain exceeds the maximum of ${maxRows} rows.`,
      { maxRows, rowCount: entries.length },
    );
  }

  const boundaries = options.boundaries ?? getChainBoundaries(entries);
  const result = verifyHashChain(entries, boundaries);
  return { entries, boundaries, result };
}
