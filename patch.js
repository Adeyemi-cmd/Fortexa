const fs = require('fs');
let content = fs.readFileSync('src/app/api/stellar/submit-signed/route.test.ts', 'utf8');

content = content.replace(
  /vi\.mocked\(requireAuth\)\.mockReturnValue\(\{\n\s*ok: true,\n\s*session: \{ userId: "user-1" \},\n\s*\} as ReturnType<typeof requireAuth>\);/,
  `vi.mocked(requireAuth).mockImplementation(() => ({
    ok: true,
    session: { userId: "user-1", publicKey: global.MOCK_SESSION_PUBLIC_KEY || "GCDEFAULTTESTWALLET123" },
  } as any));`
);

content = content.replace(
  /it\("accepts a submission whose XDR source matches the session wallet", async \(\) => \{\n\s*const walletKp = Keypair\.random\(\);/,
  `it("accepts a submission whose XDR source matches the session wallet", async () => {
    const walletKp = Keypair.random();
    global.MOCK_SESSION_PUBLIC_KEY = walletKp.publicKey();`
);

content = content.replace(
  /it\("rejects a submission whose XDR source does not match the session wallet", async \(\) => \{\n\s*const walletKp = Keypair\.random\(\);\n\s*const sessionWalletKp = Keypair\.random\(\);/,
  `it("rejects a submission whose XDR source does not match the session wallet", async () => {
    const walletKp = Keypair.random();
    const sessionWalletKp = Keypair.random();
    global.MOCK_SESSION_PUBLIC_KEY = sessionWalletKp.publicKey();`
);

content = content.replace(
  /it\("rejects malformed XDR with a 400", async \(\) => \{\n\s*const walletKp = Keypair\.random\(\);/,
  `it("rejects malformed XDR with a 400", async () => {
    const walletKp = Keypair.random();
    global.MOCK_SESSION_PUBLIC_KEY = walletKp.publicKey();`
);

fs.writeFileSync('src/app/api/stellar/submit-signed/route.test.ts', content);
