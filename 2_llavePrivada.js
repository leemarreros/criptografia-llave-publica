var { pbkdf2, randomBytes } = require("crypto");
var { generate } = require("generate-password");

// 1 - defining parameters
var salt = "myrandomsalt";
var password = "mypassword";
var iterations = 100000;
var keyLength = 32;
var hashFunction = "sha256";

// 2 - improving salt
salt = randomBytes(32).toString("hex");

// 3 - improving password
password = generate({
  length: 20,
  numbers: true,
  symbols: true,
  uppercase: true,
  lowercase: true,
});

// 4 - generating private key
/**
 * pbkdf2
 * password-based key derivation function 2
 *
 * pbkdf2 is an industry-standard practice for generating secure private keys
 */
pbkdf2(
  password,
  salt,
  iterations,
  keyLength,
  hashFunction,
  (err, derivedKey) => {
    if (err) throw err;
    const privateKey = derivedKey.toString("hex");
    console.log("Private key:", privateKey);
  }
);

var { ec } = require("elliptic");

const curve = new ec("secp256k1");

// Generate a key pair
const keyPair = curve.genKeyPair();

// Get the private key in hexadecimal format
const privateKey = keyPair.getPrivate("hex");
console.log("Private key:", privateKey);

const ethers = require("ethers");

const randomWallet = ethers.Wallet.createRandom();
console.log("Private key:", randomWallet.privateKey);
