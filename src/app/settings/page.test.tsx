import { Networks } from "@stellar/stellar-sdk";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import SettingsPage from "@/app/settings/page";

vi.mock("next/headers", () => ({
  cookies: async () => ({ get: () => undefined }),
}));

vi.mock("@/lib/auth/use-auth-session", () => ({
  useAuthSession: () => ({ isOperator: true, loading: false }),
}));

const originalHorizon = process.env.STELLAR_HORIZON_URL;
const originalPassphrase = process.env.STELLAR_NETWORK_PASSPHRASE;

afterEach(() => {
  vi.unstubAllGlobals();
  if (originalHorizon === undefined) delete process.env.STELLAR_HORIZON_URL;
  else process.env.STELLAR_HORIZON_URL = originalHorizon;
  if (originalPassphrase === undefined) delete process.env.STELLAR_NETWORK_PASSPHRASE;
  else process.env.STELLAR_NETWORK_PASSPHRASE = originalPassphrase;
});

describe("settings page network", () => {
  it("shows the server network and public passphrase without browser storage or a session", async () => {
    process.env.STELLAR_HORIZON_URL = "https://horizon.stellar.org";
    process.env.STELLAR_NETWORK_PASSPHRASE = Networks.PUBLIC;
    const setItem = vi.fn();
    vi.stubGlobal("localStorage", { setItem });
    vi.stubGlobal("sessionStorage", { setItem });

    const html = renderToStaticMarkup(
      await SettingsPage({ searchParams: Promise.resolve({ tab: "policies" }) }),
    );

    expect(html).toContain("Network: public");
    expect(html).toContain(Networks.PUBLIC);
    expect(html).toContain("Configuration valid: yes");
    expect(setItem).not.toHaveBeenCalled();
  });

  it("shows a mismatch and disables save when server settings disagree", async () => {
    process.env.STELLAR_HORIZON_URL = "https://horizon.stellar.org";
    process.env.STELLAR_NETWORK_PASSPHRASE = Networks.TESTNET;

    const html = renderToStaticMarkup(
      await SettingsPage({ searchParams: Promise.resolve({ tab: "policies" }) }),
    );

    expect(html).toContain("Network mismatch");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Save Policy<\/button>/);
  });
});
