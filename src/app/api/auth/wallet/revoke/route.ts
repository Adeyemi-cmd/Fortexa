import { NextRequest, NextResponse } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { revokeUserSessions } from "@/lib/auth/session-store";
import { consumeRateLimit, rateLimitHeaders } from "@/lib/security/rate-limit";
import { revokeUserWallet } from "@/lib/storage/user-wallet-store";

export async function DELETE(request: NextRequest) {
  const rate = await consumeRateLimit(request, {
    key: "stellar-wallet-revoke",
    limit: 10,
    windowMs: 60_000,
  });

  if (!rate.ok) {
    return NextResponse.json(
      { error: "Rate limit exceeded for wallet revocation." },
      { status: 429, headers: rateLimitHeaders(rate) }
    );
  }

  try {
    const auth = requireAuth(request, { allowedRoles: ["operator"] });

    if (!auth.ok) {
      return auth.response;
    }

    const userId = auth.session.userId;

    await revokeUserWallet(userId);
    revokeUserSessions(userId);

    return NextResponse.json(
      {
        ok: true,
        message: "Session wallet mapping has been successfully revoked.",
      },
      { headers: rateLimitHeaders(rate) }
    );
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to revoke wallet mapping." },
      { status: 500, headers: rateLimitHeaders(rate) }
    );
  }
}
