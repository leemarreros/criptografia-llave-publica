var { ec } = require("elliptic");
var { randomBytes } = require("crypto");
var { keccak_256 } = require("js-sha3");

// // 1 - Initialize the secp256k1 curve
const curve = new ec("secp256k1");

// 2 - Generating entropy
const entropy = randomBytes(32);
// 621afc7ac8821faa8fb484d9e3a68ba13b6171f01246f8d5f6bc1947e7d5cc8b

// 3 - Generate a new key pair
// (Another way of creating a private and public key)
const keyPair = curve.genKeyPair({ entropy });

// publicKey = "04" + Point X + Point Y
// Concatenate X and Y coordinates
const xEllipticCurve = keyPair.getPublic().getX();
const yEllipticCurve = keyPair.getPublic().getY();
const publicKey =
  "04" + xEllipticCurve.toString("hex") + yEllipticCurve.toString("hex");

// Or the equivalent:
// const publicKey = keyPair.getPublic("hex");

// const hash = keccak_256(Buffer.from(publicKey, "hex").slice(1));
const hash = keccak_256(
  Buffer.from(
    "049d4b0a9f4cbdeeb35a328a71d19d0f184665017b6c4a77b3e23e8edcbc850921da6a7859df1797ed2dbda698cbd6f16b62be58fd85d05b1bbb3e9547c8f81127",
    "hex"
  ).slice(1)
);
// NOTE:
// - .slice(1) removes the first byte from the 'publicKey'
// - that first byte removed is "0x04" that was added previously

const address = "0x" + hash.slice(-40);

console.log(address);
