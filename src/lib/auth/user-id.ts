import { randomUUID } from "node:crypto";

import type { NextRequest } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { findUserWalletByPublicKey, isUserWalletRevoked } from "@/lib/storage/user-wallet-store";

export const USER_COOKIE_KEY = "fortexa_user_id";

/** Loads the user id already bound to this wallet, or allocates a new one. */
export async function userIdForWallet(publicKey: string): Promise<string> {
  const existing = await findUserWalletByPublicKey(publicKey);
  if (existing && !(await isUserWalletRevoked(existing.userId))) {
    return existing.userId;
  }

  return randomUUID();
}

export function getOrCreateUserId(request: NextRequest) {
  const session = getSessionFromRequest(request);

  if (session) {
    return {
      userId: session.userId,
      shouldSetCookie: false,
    };
  }

  const cookieUserId = request.cookies.get(USER_COOKIE_KEY)?.value;

  if (cookieUserId) {
    return {
      userId: cookieUserId,
      shouldSetCookie: false,
    };
  }

  return {
    userId: randomUUID(),
    shouldSetCookie: true,
  };
}
