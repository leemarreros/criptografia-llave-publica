var { encryptWithPublicKey, decryptWithPrivateKey } = require("eth-crypto");
var { ec } = require("elliptic");

const EC = new ec("secp256k1");
// 1 - Bob generate a key pair
const bobKeyPair = EC.genKeyPair();

async function encryptDecryptMessage() {
  const message = "Hello Bob, this is a confidential message";

  // 2 - Alice encrypts a message using Bob's public key
  const encryptedMessage = await encryptWithPublicKey(
    bobKeyPair.getPublic("hex"),
    message
  );

  // Anybody is able to see the encrypted message across the network
  console.log("Encrypted message", encryptedMessage);
  // Encrypted message { ... }

  // 3 - Bob decrypts the message using his private key
  const decryptedMessage = await decryptWithPrivateKey(
    bobKeyPair.getPrivate("hex"),
    encryptedMessage
  );

  console.log(decryptedMessage);
  // Output: Hello Bob, this is a confidential message
}

encryptDecryptMessage();
