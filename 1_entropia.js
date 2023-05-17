var { randomBytes, pbkdf2 } = require("crypto");
var { generate } = require("generate-password");

const entropia = randomBytes(32);

// pbkdf2
// passowrd based key derivation function 2

var password = generate({
  length: 20,
  numbers: true,
  symbols: true,
  uppercase: true,
  lowercase: true,
});
var salt = entropia.toString("hex");
var iterations = 100000;
var keyLength = 32;
var hashFunction = "sha256";

pbkdf2(
  password,
  salt,
  iterations,
  keyLength,
  hashFunction,
  (err, derivedKey) => {
    console.log(derivedKey.toString("hex"));
  }
);

var { ec } = require("elliptic");
const curve = new ec("secp256k1");

// genera key pair
const keyPair = curve.genKeyPair();
const privateKey = keyPair.getPrivate("hex");
console.log("EC", privateKey);

// Ethers.js
const ethers = require("ethers");
const randomWallet = ethers.Wallet.createRandom();
console.log("Ethers", randomWallet.privateKey);
