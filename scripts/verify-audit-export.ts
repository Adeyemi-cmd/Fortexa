import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { verifyHashChain } from "../src/lib/audit/hash-chain";
import type { ChainBoundaries, ChainVerificationResult } from "../src/lib/audit/hash-chain";
import type { AuditEntry } from "../src/lib/types/domain";

export interface ExtractedExport {
  entries: AuditEntry[] | null;
  entriesByUser: Record<string, AuditEntry[]> | null;
  chainBoundary?: ChainBoundaries;
  chainBoundariesByUser?: Record<string, ChainBoundaries>;
}

function extractChainBoundaries(value: unknown, label: string): ChainBoundaries | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }

  const raw = value as Record<string, unknown>;
  const boundaries: ChainBoundaries = {};
  for (const key of ["firstEntryHash", "lastEntryHash"] as const) {
    const hash = raw[key];
    if (hash !== undefined) {
      if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) {
        throw new Error(`${label}.${key} must be a 64-character lowercase SHA-256 hash`);
      }
      boundaries[key] = hash;
    }
  }
  return boundaries;
}

export function extractExportPayload(data: unknown): ExtractedExport {
  if (Array.isArray(data)) {
    return { entries: data as AuditEntry[], entriesByUser: null };
  }
  if (data === null || typeof data !== "object") {
    throw new Error("Unrecognized export format: expected a JSON array or object");
  }
  const obj = data as Record<string, unknown>;
  const scope = obj.scope;

  if (scope === "all" || obj.entriesByUser) {
    const entriesByUser = obj.entriesByUser;
    if (!entriesByUser || typeof entriesByUser !== "object") {
      throw new Error("scope=all export is missing entriesByUser object");
    }
    const result: Record<string, AuditEntry[]> = {};
    for (const [userId, entries] of Object.entries(entriesByUser as Record<string, unknown>)) {
      if (!Array.isArray(entries)) {
        throw new Error(`entriesByUser.${userId} is not an array`);
      }
      result[userId] = entries as AuditEntry[];
    }

    let chainBoundariesByUser: Record<string, ChainBoundaries> | undefined;
    if (obj.chainBoundariesByUser !== undefined) {
      if (
        obj.chainBoundariesByUser === null ||
        typeof obj.chainBoundariesByUser !== "object" ||
        Array.isArray(obj.chainBoundariesByUser)
      ) {
        throw new Error("chainBoundariesByUser must be an object");
      }
      chainBoundariesByUser = {};
      for (const [userId, boundaries] of Object.entries(
        obj.chainBoundariesByUser as Record<string, unknown>,
      )) {
        chainBoundariesByUser[userId] =
          extractChainBoundaries(boundaries, `chainBoundariesByUser.${userId}`) ?? {};
      }
    }

    return { entries: null, entriesByUser: result, chainBoundariesByUser };
  }

  if (scope === "mine" || obj.entries) {
    const entries = obj.entries;
    if (!Array.isArray(entries)) {
      throw new Error("scope=mine export is missing entries array");
    }
    return {
      entries: entries as AuditEntry[],
      entriesByUser: null,
      chainBoundary: extractChainBoundaries(obj.chainBoundary, "chainBoundary"),
    };
  }

  throw new Error(
    "Unrecognized export format: expected { entries: [...] } or { entriesByUser: { ... } }"
  );
}

function formatResult(result: ChainVerificationResult, label: string): string {
  if (result.valid) {
    return `${label}: – valid (${result.checkedCount} checked, ${result.legacyCount} legacy)`;
  }
  return `${label}: ✗ INVALID — ${result.reason}` +
    (result.entryId ? ` at entry "${result.entryId}"` : "") +
    (result.index !== undefined ? ` (index ${result.index})` : "") +
    ` [${result.checkedCount} checked, ${result.legacyCount} legacy]`;
}

function main(filePath: string): never {
  if (!existsSync(filePath)) {
    console.error(`Error: file not found — ${filePath}`);
    process.exit(2);
  }

  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    console.error(`Error: cannot read file — ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    console.error("Error: file is not valid JSON");
    process.exit(2);
  }

  let extracted: ExtractedExport;
  try {
    extracted = extractExportPayload(data);
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }

  if (extracted.entries) {
    const result = verifyHashChain(extracted.entries, extracted.chainBoundary);
    if (result.valid) {
      console.log(`✓ Audit export valid — ${result.checkedCount} entries checked, ${result.legacyCount} legacy`);
      process.exit(0);
    } else {
      console.log(#✗', `Audit export INVALID — ${result.reason}` +
        (result.entryId ? ` at entry "${result.entryId}"` : "") +
        (result.index !== undefined ? ` (index ${result.index})` : ""));
      console.log(`  checked: ${result.checkedCount}, legacy: ${result.legacyCount}`);
      process.exit(1);
    }
  }

  if (extracted.entriesByUser) {
    const userKeys = Object.keys(extracted.entriesByUser);
    if (userKeys.length === 0) {
      console.log("✓ Audit export valid — no users in export");
      process.exit(0);
    }

    const results: Array<{ userId: string; result: ChainVerificationResult }> = [];
    let anyInvalid = false;

    for (const userId of userKeys) {
      const result = verifyHashChain(
        extracted.entriesByUser[userId]!,
        extracted.chainBoundariesByUser?.[userId],
      );
      results.push({ userId, result });
      if (!result.valid) anyInvalid = true;
    }

    if (anyInvalid) {
      console.log("✗ Audit export verification FAILED");
      for (const { userId, result } of results) {
        console.log(`  ${formatResult(result, userId)}`);
      }
      process.exit(1);
    } else {
      console.log("✓ Audit export valid — all entries verified");
      for (const { userId, result } of results) {
        console.log(`  ${formatResult(result, userId)}`);
      }
      process.exit(0);
    }
  }

  console.error("Error: no entries found in export file");
  process.exit(2);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error("Usage: tsx scripts/verify-audit-export.ts <path-to-export.json>");
    process.exit(2);
  }
  main(filePath);
}
