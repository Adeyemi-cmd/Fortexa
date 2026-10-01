import { NextRequest, NextResponse } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { getRequestLogContext, logWarn } from "@/lib/observability/logger";
import { STELLAR_PUBLIC_NETWORK_PASSPHRASE } from "@/lib/stellar/network";
import { getStellarNetworkPassphrase } from "@/lib/stellar/network-config";

export async function POST(request: NextRequest) {
  const auth = requireAuth(request);

  if (!auth.ok) {
    return auth.response;
  }

  if (getStellarNetworkPassphrase() === STELLAR_PUBLIC_NETWORK_PASSPHRASE) {
    logWarn("Stellar funding refused on public network", getRequestLogContext(request, "/api/stellar/fund"));
    return NextResponse.json(
      { error: "Stellar funding is disabled on the public network." },
      { status: 403 }
    );
  }

  return NextResponse.json(
    { error: "Friendbot funding has been removed from this project." },
    { status: 410 }
  );
}
