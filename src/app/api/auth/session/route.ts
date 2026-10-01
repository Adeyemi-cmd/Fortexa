import { NextRequest, NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { securityHeadersForRequest } from "@/lib/security/headers";

export async function GET(request: NextRequest) {
  const session = await getActiveSessionFromRequest(request);

  if (!session) {
    return NextResponse.json(
      { authenticated: false },
      { status: 200, headers: securityHeadersForRequest(request, { noStore: true }) },
    );
  }

  return NextResponse.json(
    {
      authenticated: true,
      user: {
        email: session.email,
        role: session.role,
        userId: session.userId,
        exp: session.exp,
      },
    },
    { headers: securityHeadersForRequest(request, { noStore: true }) },
  );
}
