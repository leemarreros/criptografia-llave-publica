var {
  hash,
  createIdentity,
  sign,
  recover,
  recoverPublicKey,
} = require("eth-crypto");

// 1 - Alice creates her identity (public and private keys)
const alice = createIdentity();

// 2 - Alice writes a message and hashes it
const message = "Hello Bob, this message is from Alice.";
const hashedMessage = hash.keccak256(message);

// 3 - Alice signs the message with her private key
const signature = sign(alice.privateKey, hashedMessage);

// Alice sends the message and signature to Bob
console.log("Signature:", signature);
console.log("Hashed Message:", hashedMessage);

// ETHEREUM ADDRESS
// 4 - Recover the Ethereum address from the signature and hashed message
const addressRecovered = recover(signature, hashedMessage);

// Bob checks if the recovered address matches Alice's Ethereum address
if (addressRecovered === alice.address) {
  console.log(`Message from Alice: ${message}`);
} else {
  console.log("Message verification failed!");
}

// PUBLIC KEY
// 4 - Recover the public key from the signature and hashed message
const publicKeyRecovered = recoverPublicKey(signature, hash.keccak256(message));

// Bob checks if the recovered public key matches Alice's public key
if (publicKeyRecovered === alice.publicKey) {
  console.log(`Message from Alice: ${message}`);
} else {
  console.log("Message verification failed!");
}
