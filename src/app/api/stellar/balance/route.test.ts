import { Networks } from "@stellar/stellar-sdk";
import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "@/app/api/stellar/balance/route";

vi.mock("@/lib/auth/require-auth", () => ({
  requireAuth: () => ({ ok: true, session: { userId: "fixture-user" } }),
}));
vi.mock("@/lib/storage/user-wallet-store", () => ({
  getUserWallet: async () => ({ publicKey: "GFIXTURE", source: "external", provider: "fixture" }),
  upsertUserWallet: vi.fn(),
}));
vi.mock("@/lib/stellar/client", () => ({
  getNativeBalance: async () => "5.0",
}));

const previousHorizon = process.env.STELLAR_HORIZON_URL;
const previousPassphrase = process.env.STELLAR_NETWORK_PASSPHRASE;

afterEach(() => {
  if (previousHorizon === undefined) delete process.env.STELLAR_HORIZON_URL;
  else process.env.STELLAR_HORIZON_URL = previousHorizon;
  if (previousPassphrase === undefined) delete process.env.STELLAR_NETWORK_PASSPHRASE;
  else process.env.STELLAR_NETWORK_PASSPHRASE = previousPassphrase;
});

describe("wallet network display", () => {
  it("reports the server public network instead of a fixed testnet label", async () => {
    process.env.STELLAR_HORIZON_URL = "https://horizon.stellar.org";
    process.env.STELLAR_NETWORK_PASSPHRASE = Networks.PUBLIC;

    const response = await GET(new NextRequest("http://localhost/api/stellar/balance"));
    expect(response.status).toBe(200);
    expect((await response.json()).network).toBe("public");
  });
});
