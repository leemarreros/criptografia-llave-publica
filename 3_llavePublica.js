var { ec } = require("elliptic");

// From all elliptic curves, we use secp256k1
const curve = new ec("secp256k1");

// Any private key (d)
const pk = "e0eaab0558cac71f5b7efb11668f324000a76ab3843d2e5becfb201cbec97adc";

// Formula: d * G mod p
// 'mul()' method does the modulo operation with 'p'
const publicKey = curve.g.mul(pk);

// This result has the "04" at the beginning that states that both x and y
// coordinates are included
console.log("Public Key:", publicKey.encode("hex"));
// Public Key: 049d4b0a9f4cbdeeb35a328a71d19d0f184665017b6c4a77b3e23e8edcbc850921da6a7859df1797ed2dbda698cbd6f16b62be58fd85d05b1bbb3e9547c8f81127

// Only the x coordinate
console.log("Public key (x):", publicKey.getX().toString(16));
// Public key (x): 9d4b0a9f4cbdeeb35a328a71d19d0f184665017b6c4a77b3e23e8edcbc850921

// Only the y coordinate
console.log("Public key (y):", publicKey.getY().toString(16));
// Public key (y): da6a7859df1797ed2dbda698cbd6f16b62be58fd85d05b1bbb3e9547c8f81127
