/**
 * 
1- La llave pública es un par (x, y) que corresponde a un punto en la curva elíptica. x e y se concatenan después de 04 para crear la llave pública

2- Aplicar el algoritmo keccack256 sobre la publicKey

3- Solo nos importan los últimos 20 bytes o los últimos 40 caracteres

4- Le agregamos 0x inicialmente
 */
var { ec } = require("elliptic");

const curve = new ec("secp256k1");

// 1
const keyPair = curve.genKeyPair();
const xCoor = keyPair.getPublic().getX();
const yCoor = keyPair.getPublic().getY();
const publicKey = "04" + xCoor.toString("hex") + yCoor.toString("hex");

// 2
var { keccak256 } = require("js-sha3");
// const hash = keccak256(Buffer.from(publicKey, "hex")).slice(1);
const hash = keccak256(
  Buffer.from(
    "049d4b0a9f4cbdeeb35a328a71d19d0f184665017b6c4a77b3e23e8edcbc850921da6a7859df1797ed2dbda698cbd6f16b62be58fd85d05b1bbb3e9547c8f81127",
    "hex"
  )
).slice(1);

// 3 y 4
const address = "0x" + hash.slice(-40);

console.log("Ethereum address", address);
