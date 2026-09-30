const fs = require('fs');
let content = fs.readFileSync('src/app/api/auth/refresh/route.test.ts', 'utf8');

content = content.replace(
  /import \{ POST \} from "@\/app\/api\/auth\/refresh\/route";/,
  `import { POST } from "@/app/api/auth/refresh/route";\nimport { upsertUserWallet } from "@/lib/storage/user-wallet-store";`
);

content = content.replace(
  /userId: "refresh-operator",/,
  `userId: "refresh-operator",\n    publicKey: "GCDEFAULTTESTWALLET123",`
);

content = content.replace(
  /it\("returns 200 and rotates for authenticated user", async \(\) => \{/,
  `it("returns 200 and rotates for authenticated user", async () => {\n    await upsertUserWallet("refresh-operator", { publicKey: "GCDEFAULTTESTWALLET123", source: "external" });`
);

fs.writeFileSync('src/app/api/auth/refresh/route.test.ts', content);
