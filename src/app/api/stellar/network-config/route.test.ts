import { Networks } from "@stellar/stellar-sdk";
import { afterEach, describe, expect, it } from "vitest";

import { GET } from "@/app/api/stellar/network-config/route";
import { getStellarNetworkFingerprint } from "@/lib/stellar/network-config";

const previousHorizon = process.env.STELLAR_HORIZON_URL;
const previousPassphrase = process.env.STELLAR_NETWORK_PASSPHRASE;

afterEach(() => {
  if (previousHorizon === undefined) delete process.env.STELLAR_HORIZON_URL;
  else process.env.STELLAR_HORIZON_URL = previousHorizon;
  if (previousPassphrase === undefined) delete process.env.STELLAR_NETWORK_PASSPHRASE;
  else process.env.STELLAR_NETWORK_PASSPHRASE = previousPassphrase;
});

describe("server network snapshot", () => {
  it("returns a public, uncached fingerprint without a session", async () => {
    process.env.STELLAR_HORIZON_URL = "https://horizon.stellar.org";
    process.env.STELLAR_NETWORK_PASSPHRASE = Networks.PUBLIC;

    const response = GET();
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      profile: "public",
      fingerprint: getStellarNetworkFingerprint(),
      valid: true,
    });
  });
});
