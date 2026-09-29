import { promises as fs } from "node:fs";

import { runWithDatabase } from "@/lib/storage/db";
import { getFortexaStorePath } from "@/lib/storage/paths";
import {
  STELLAR_PUBLIC_NETWORK_PASSPHRASE,
  STELLAR_TESTNET_NETWORK_PASSPHRASE,
} from "@/lib/stellar/network";

function clean(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : null;
}

/**
 * Read-only policy store check.
 *
 * getPolicyConfig() silently bootstraps default policy rows when storage is
 * empty, so it can never tell us the store is missing. This check reads the
 * persisted state without creating anything.
 */
export async function loadPolicyStore(
  env: NodeJS.ProcessEnv = process.env,
): Promise<boolean> {
  const db = await runWithDatabase("readiness-policy-store", async (pool) => {
    const result = await pool.query<{ version: number }>(
      "SELECT version FROM fortexa_policy_state WHERE id = 1",
    );
    return result.rows.length > 0;
  });

  if (db.available) {
    return db.value === true;
  }

  // A configured database that is unreachable must not silently pass via the
  // file fallback.
  if (clean(env.DATABASE_URL)) {
    return false;
  }

  try {
    const raw = await fs.readFile(getFortexaStorePath("policy.json"), "utf8");
    const parsed = JSON.parse(raw) as { policy?: unknown; version?: unknown };
    return Boolean(parsed.policy) && typeof parsed.version === "number";
  } catch {
    return false;
  }
}

export function getConfiguredPassphrase(
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  return clean(env.STELLAR_NETWORK_PASSPHRASE);
}

/**
 * The passphrase this deployment is supposed to use.
 * FORTEXA_EXPECTED_NETWORK_PASSPHRASE wins when set; otherwise production
 * expects the public network and everything else expects testnet.
 */
export function getExpectedPassphrase(
  env: NodeJS.ProcessEnv = process.env,
): string {
  return (
    clean(env.FORTEXA_EXPECTED_NETWORK_PASSPHRASE) ??
    (env.NODE_ENV === "production"
      ? STELLAR_PUBLIC_NETWORK_PASSPHRASE
      : STELLAR_TESTNET_NETWORK_PASSPHRASE)
  );
}
