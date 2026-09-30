const SENSITIVE_KEYS = new Set([
  "signature",
  "signedxdr",
  "xdr",
  "authorization",
  "cookie",
  "fortexa_session",
  "groq_api_key",
  "secret",
  "token",
]);

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEYS.has(key.toLowerCase());
}

const METRIC_TEXT_SENSITIVE_KEYS = new Set([...SENSITIVE_KEYS, "destination", "memo"]);

const SENSITIVE_PAIR_PATTERN = new RegExp(
  `\\b(${[...METRIC_TEXT_SENSITIVE_KEYS].join("|")})(\\s*[:=]\\s*)("[^"]*"|'[^']*'|[^\\s,;]+)`,
  "gi"
);

const WALLET_PATTERN = /G[A-Z2-7]{55}/g;
const BEARER_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]+/g;

export function redactMetricText(text: string): string {
  if (typeof text !== "string" || text.length === 0) {
    return "";
  }

  return text
    .replace(/\r\n|\n|\r/g, " ")
    .replace(SENSITIVE_PAIR_PATTERN, (_match, key: string, separator: string) => `${key}${separator}[REDACTED]`)
    .replace(WALLET_PATTERN, "[REDACTED]")
    .replace(BEARER_PATTERN, "Bearer [REDACTED]");
}

export function redactSensitiveFields<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map(redactSensitiveFields) as unknown as T;
  }

  if (value !== null && typeof value === "object") {
    const redacted: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (isSensitiveKey(key)) {
        redacted[key] = "[REDACTED]";
      } else {
        redacted[key] = redactSensitiveFields(val);
      }
    }
    return redacted as T;
  }

  return value;
}
