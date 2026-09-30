const fs = require('fs');
let analyzerContent = fs.readFileSync('src/lib/security/analyzer.ts', 'utf8');

const replacement = `async function fetchBlocklistWithTimeout(): Promise<{
  blocklist: string[];
  status: { blocked: boolean; timedOut: boolean; error?: string };
}> {
  try {
    const controller = new AbortController();
    const { blocklistTimeoutMs } = getAnalyzerConfig();
    const timeoutId = setTimeout(() => controller.abort(), blocklistTimeoutMs);

    try {
      const blocklist = await fetchBlocklist();
      clearTimeout(timeoutId);
      const health = getBlocklistHealth();
      if (health.lastError) {
        return {
          blocklist,
          status: {
            blocked: true,
            timedOut: false,
            error: health.lastError,
          },
        };
      }
      return { blocklist, status: { blocked: false, timedOut: false } };
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (err) {
    const isTimeout = err instanceof Error && err.name === "AbortError";
    const health = getBlocklistHealth();
    const blocklist = [];
    return { 
      blocklist, 
      status: { 
        blocked: true, 
        timedOut: isTimeout || /abort|timeout/i.test(health.lastError || ""), 
        error: health.lastError || "Blocklist fetch failed" 
      } 
    };
  }
}

`;

const prefix = analyzerContent.split('async function fetchBlocklistWithTimeout()')[0];
const suffix = 'export async function evaluateSecurity' + analyzerContent.split('export async function evaluateSecurity')[1];

fs.writeFileSync('src/lib/security/analyzer.ts', prefix + replacement + suffix);

let useAuthSession = fs.readFileSync('src/lib/auth/use-auth-session.ts', 'utf8');
useAuthSession = useAuthSession.replace('import { useEffect, useState } from "react";', 'import { useCallback, useEffect, useState } from "react";');
useAuthSession = useAuthSession.replace('const refresh = async () => {', 'const refresh = useCallback(async () => {');
useAuthSession = useAuthSession.replace(/  \}, \[\]\);\n\n  useEffect\(\(\) => \{/g, '  };\n\n  useEffect(() => {');
fs.writeFileSync('src/lib/auth/use-auth-session.ts', useAuthSession);

let routeTest = fs.readFileSync('src/app/api/audit/export/route.test.ts', 'utf8');
routeTest = routeTest.replace(/const response = await GET\(request\);/g, 'const response = await GET(req);');
routeTest = routeTest.replace(/const response = await GET\(req\);\n\n    const response = await GET\(req\);/g, 'const response = await GET(req);');
fs.writeFileSync('src/app/api/audit/export/route.test.ts', routeTest);

let submitRouteTest = fs.readFileSync('src/app/api/stellar/submit-signed/route.test.ts', 'utf8');
submitRouteTest = submitRouteTest.replace(/global\.MOCK_SESSION_PUBLIC_KEY/g, '(globalThis as any).MOCK_SESSION_PUBLIC_KEY');
submitRouteTest = submitRouteTest.replace('const actual = await importOriginal();', 'const actual = await importOriginal<typeof import("@/lib/stellar/client")>();');
fs.writeFileSync('src/app/api/stellar/submit-signed/route.test.ts', submitRouteTest);

let metrics = fs.readFileSync('src/lib/observability/metrics.ts', 'utf8');
metrics = metrics.replace('| "source_wallet_mismatch";', '| "source_wallet_mismatch"\n  | "signer_wallet_mismatch";');
fs.writeFileSync('src/lib/observability/metrics.ts', metrics);

let productionTest = fs.readFileSync('src/lib/readiness/production.test.ts', 'utf8');
productionTest = productionTest.replace(/checkProductionReadiness\(\n\s*\{\n/g, 'checkProductionReadiness(\n      {\n        NODE_ENV: "test",\n');
productionTest = productionTest.replace(/checkProductionReadiness\(\{\}/g, 'checkProductionReadiness({ NODE_ENV: "test" }');
fs.writeFileSync('src/lib/readiness/production.test.ts', productionTest);

