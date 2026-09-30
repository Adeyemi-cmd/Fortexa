import { NextRequest, NextResponse } from "next/server";

import { requireAuth } from "@/lib/auth/require-auth";
import { isAddressBlocklisted } from "@/lib/security/blocklist";
import { stellarPublicKeySchema } from "@/lib/validation/schemas";

export async function POST(request: NextRequest) {
  const auth = requireAuth(request);

  if (!auth.ok) {
    return auth.response;
  }

  const body = (await request.json().catch(() => ({}))) as { destination?: unknown };
  const destination = stellarPublicKeySchema.safeParse(body?.destination);

  if (destination.success && (await isAddressBlocklisted(destination.data))) {
    return NextResponse.json({ error: "Destination is blocklisted." }, { status: 403 });
  }

  return NextResponse.json(
    { error: "Friendbot funding has been removed from this project." },
    { status: 410 }
  );
}
