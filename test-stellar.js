const { Keypair, TransactionBuilder, Networks, Asset, Operation } = require("@stellar/stellar-sdk");
const kp = Keypair.random();
const tx = new TransactionBuilder(new (require("@stellar/stellar-sdk").Account)(kp.publicKey(), "1"), { fee: "100", networkPassphrase: Networks.TESTNET })
  .addOperation(Operation.payment({ destination: kp.publicKey(), asset: Asset.native(), amount: "1" }))
  .setTimeout(0)
  .build();
tx.sign(kp);
console.log("Decorated signatures:", tx.signatures.length);
// How to verify?
// checkSignature(kp.publicKey()) ? No, let's see what's available
console.log("Has checkSignature?", typeof tx.checkSignature === 'function' ? 'Yes' : 'No');
