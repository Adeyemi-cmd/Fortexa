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
 * Finds the index of the first broken link in a hash chain.
 * @param rows Array of audit rows to check
 * @returns The index of the first broken row, or -1 if chain is valid
 */
export function findBrokenLinkIndex(rows: Array<{ hash: string; previousHash: string }>): number {
  if (rows.length < 2) return -1;

  for (let i = 1; i < rows.length; i++) {
    const current = rows[i];
    const previous = rows[i - 1];

    if (current.previousHash !== previous.hash) {
      return i;
    }
  }

  return -1;
}