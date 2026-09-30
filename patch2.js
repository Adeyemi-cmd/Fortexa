const fs = require('fs');
let content = fs.readFileSync('src/app/api/stellar/submit-signed/route.test.ts', 'utf8');

content = content.replace(
  /it\("rejects malformed XDR with a 400", async \(\) => \{\n\s*const walletKp = Keypair\.random\(\);\n\s*global\.MOCK_SESSION_PUBLIC_KEY = walletKp\.publicKey\(\);\n\s*vi\.mocked\(getUserWallet\)\.mockResolvedValue\(\{\n\s*userId: "user-1",\n\s*publicKey: walletKp\.publicKey\(\),\n\s*source: "external",\n\s*createdAt: new Date\(\)\.toISOString\(\),\n\s*\}\);\n\n\s*const request = new NextRequest\("http:\/\/localhost\/api\/stellar\/submit-signed", \{\n\s*method: "POST",\n\s*body: JSON\.stringify\(\{ signedXdr: "not-an-xdr" \}\),\n\s*\}\);\n\n\s*const response = await POST\(request\);\n\s*const body = await response\.json\(\);\n\n\s*expect\(response\.status\)\.toBe\(403\);/m,
  function(match) {
    return match.replace('toBe(403)', 'toBe(400)');
  }
);

fs.writeFileSync('src/app/api/stellar/submit-signed/route.test.ts', content);
