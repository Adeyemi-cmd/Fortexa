import { createHash, randomUUID } from "node:crypto";

import { Keypair } from "@stellar/stellar-sdk";

import { normalizeWalletPublicKey } from "@/lib/auth/wallet-role";
import {
  clearSharedChallenges,
  isSharedSecurityStateEnabled,
  takeSharedChallenge,
  writeSharedChallenge,
} from "@/lib/security/shared-security-state";

const SEP53_PREFIX = "Stellar Signed Message:\n";

export type WalletChallengeRecord = {
  id: string;
  publicKey: string;
  message: string;
  expiresAtMs: number;
};

type StoredChallenge = WalletChallengeRecord & {
  consumed: boolean;
};

const challenges = new Map<string, StoredChallenge>();
const challengeVerificationLocks = new Map<string, Promise<void>>();

async function withChallengeVerificationLock<T>(challengeId: string, operation: () => Promise<T>): Promise<T> {
  const previous = challengeVerificationLocks.get(challengeId) ?? Promise.resolve();
  let release: (() => void) | undefined;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });

  const queued = previous.then(() => current);
  challengeVerificationLocks.set(challengeId, queued);
  await previous;

  try {
    return await operation();
  } finally {
    release?.();
    if (challengeVerificationLocks.get(challengeId) === queued) {
      challengeVerificationLocks.delete(challengeId);
    }
  }
}

/**
 * Whether a challenge is expired at `nowMs`.
 *
 * Expiry is **inclusive**: a challenge whose `expiresAtMs` equals the current
 * time is already expired. `expiresAtMs` is the first instant at which the
 * challenge is no longer valid, not the last instant at which it still is.
 * Exclusive comparison (`<`) would leave a one-millisecond window in which a
 * challenge past its stated deadline still authenticates, so the boundary is
 * closed on the expired side.
 */
export function isChallengeExpired(expiresAtMs: number, nowMs: number = Date.now()) {
  return expiresAtMs <= nowMs;
}

function getChallengeTtlSeconds() {
  const parsed = Number(process.env.FORTEXA_AUTH_CHALLENGE_TTL_SECONDS ?? 300);
  if (!Number.isFinite(parsed) || parsed < 30) {
    return 300;
  }
  return Math.floor(parsed);
}

export function buildChallengeMessage(input: {
  challengeId: string;
  publicKey: string;
  expiresAtMs: number;
}) {
  const expiresAt = new Date(input.expiresAtMs).toISOString();
  return [
    "Fortexa wallet login",
    `Challenge: ${input.challengeId}`,
    `Wallet: ${input.publicKey}`,
    `Expires: ${expiresAt}`,
  ].join("\n");
}

export function hashSep53Message(message: string) {
  const payload = Buffer.concat([
    Buffer.from(SEP53_PREFIX, "utf8"),
    Buffer.from(message, "utf8"),
  ]);
  return createHash("sha256").update(payload).digest();
}

export function verifyWalletSignature(publicKey: string, message: string, signatureBase64: string) {
  try {
    const keypair = Keypair.fromPublicKey(normalizeWalletPublicKey(publicKey));
    const signature = Buffer.from(signatureBase64, "base64");
    if (signature.length !== 64) {
      return false;
    }

    return keypair.verify(hashSep53Message(message), signature);
  } catch {
    return false;
  }
}

async function takeChallenge(challengeId: string): Promise<StoredChallenge | undefined> {
  if (isSharedSecurityStateEnabled()) {
    const shared = await takeSharedChallenge(challengeId);
    if (!shared) return undefined;
    return {
      id: challengeId,
      publicKey: shared.publicKey,
      message: shared.message,
      expiresAtMs: shared.expiresAtMs,
      consumed: shared.consumed,
    };
  }

  const challenge = challenges.get(challengeId);
  challenges.delete(challengeId);
  return challenge;
}

async function writeChallenge(record: StoredChallenge, ttlSeconds: number) {
  if (isSharedSecurityStateEnabled()) {
    await writeSharedChallenge(record.id, {
      publicKey: record.publicKey,
      message: record.message,
      expiresAtMs: record.expiresAtMs,
      consumed: record.consumed,
    }, ttlSeconds);
  } else {
    challenges.set(record.id, record);
  }
}

export async function createWalletChallenge(publicKey: string, clock: () => number = Date.now): Promise<WalletChallengeRecord> {
  const normalizedKey = normalizeWalletPublicKey(publicKey);
  const challengeId = randomUUID();
  const ttlSeconds = getChallengeTtlSeconds();
  const expiresAtMs = clock() + ttlSeconds * 1000;
  const message = buildChallengeMessage({
    challengeId,
    publicKey: normalizedKey,
    expiresAtMs,
  });

  const record: StoredChallenge = {
    id: challengeId,
    publicKey: normalizedKey,
    message,
    expiresAtMs,
    consumed: false,
  };

  await writeChallenge(record, ttlSeconds);

  return {
    id: record.id,
    publicKey: record.publicKey,
    message: record.message,
    expiresAtMs: record.expiresAtMs,
  };
}

export type ChallengeVerificationResult =
  | { ok: true; challenge: WalletChallengeRecord }
  | { ok: false; code: "missing" | "expired" | "replayed" | "wallet_mismatch" | "invalid_signature" };

export async function verifyWalletChallenge(input: {
  challengeId: string;
  publicKey: string;
  signature: string;
}, clock: () => number = Date.now): Promise<ChallengeVerificationResult> {
  return withChallengeVerificationLock(input.challengeId, async () => {
    const normalizedKey = normalizeWalletPublicKey(input.publicKey);
    const challenge = await takeChallenge(input.challengeId);

    if (!challenge) {
      return { ok: false, code: "missing" };
    }

    // The record has already been removed, including for every failure below.
    if (isChallengeExpired(challenge.expiresAtMs, clock())) {
      return { ok: false, code: "expired" };
    }

    if (challenge.publicKey !== normalizedKey) {
      return { ok: false, code: "wallet_mismatch" };
    }

    if (challenge.consumed) {
      return { ok: false, code: "replayed" };
    }

    if (!verifyWalletSignature(normalizedKey, challenge.message, input.signature)) {
      return { ok: false, code: "invalid_signature" };
    }

    return {
      ok: true,
      challenge: {
        id: challenge.id,
        publicKey: challenge.publicKey,
        message: challenge.message,
        expiresAtMs: challenge.expiresAtMs,
      },
    };
  });
}

export async function resetWalletChallengeStore() {
  challenges.clear();
  await clearSharedChallenges();
}
