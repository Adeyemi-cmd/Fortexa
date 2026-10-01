const STELLAR_PUBLIC_KEY_REGEX = /^G[A-Z2-7]{55}$/u;

import { getUserWallet } from "@/lib/storage/user-wallet-store";

export async function getWalletFromSession(session: { userId?: string }) {
  if (!session.userId) {
    return null;
  }

  const wallet = await getUserWallet(session.userId);
  if (!wallet || "expired" in wallet) {
    return null;
  }

  const publicKey = wallet.publicKey.trim().toUpperCase();
  return STELLAR_PUBLIC_KEY_REGEX.test(publicKey) ? publicKey : null;
}
