const fs = require('fs');
let content = fs.readFileSync('src/app/api/stellar/submit-signed-idempotency.test.ts', 'utf8');

content = content.replace(
  /userId: OPERATOR_USER_ID,/,
  `userId: OPERATOR_USER_ID,\n    publicKey: OPERATOR_WALLET_KEYPAIR.publicKey(),`
);

fs.writeFileSync('src/app/api/stellar/submit-signed-idempotency.test.ts', content);
