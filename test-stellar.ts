import { Keypair, TransactionBuilder, Networks, Asset, Operation, Account } from "@stellar/stellar-sdk";
const kp = Keypair.random();
const tx = new TransactionBuilder(new Account(kp.publicKey(), "1"), { fee: "100", networkPassphrase: Networks.TESTNET })
  .addOperation(Operation.payment({ destination: kp.publicKey(), asset: Asset.native(), amount: "1" }))
  .setTimeout(0)
  .build();
tx.sign(kp);
console.log("Decorated signatures:", tx.signatures.length);
try {
  const isValid = kp.verify(tx.hash(), tx.signatures[0].signature());
  console.log("isValid:", isValid);
} catch (e) {
  console.log(e);
}
