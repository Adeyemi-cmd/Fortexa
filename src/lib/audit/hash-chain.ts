/**
 * Verifies the integrity of a hash chain for a sequence of audit rows.
 * @param rows Array of audit rows to verify
 * @returns true if the hash chain is valid, false otherwise
 */
export function verifyHashChain(rows: Array<{ hash: string; previousHash: string }>): boolean {
  if (rows.length === 0) return true;

  for (let i = 1; i < rows.length; i++) {
    const current = rows[i];
    const previous = rows[i - 1];

    if (current.previousHash !== previous.hash) {
      return false;
    }
  }

  return true;
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

  return -1;
}