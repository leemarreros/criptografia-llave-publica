/**
Alice quiere enviar un mensaje a Bob. En este caso, Alice quiere probar que ella escribió ese mensaje y también que el mensaje que Bob recibirá es el mismo que Alice pretendía.

1. Alice generará una llave pública y privada. Mantiene su llave privada y comparte su llave pública con cualquiera, incluido Bob.
2. Alice crea un hash del mensaje usando el algoritmo keccak256
3. Alice firma el mensaje cifrado con su llave privada para crear la firma. Esta firma se envía junto con el mensaje cifrado a cualquier persona, incluido Bob.
4. Bob podrá recuperar la dirección de Ethereum o la llave pública de Alice a partir de la firma y el mensaje cifrado.
 */
var {
  hash,
  createIdentity,
  sign,
  recover,
  recoverPublicKey,
} = require("eth-crypto");

// 1
const alice = createIdentity();
console.log("PUblic Key Alice", alice.publicKey);
const message = "Quiero comprobar que fui Yo, Alice";

// 2
const hashedMessage = hash.keccak256(message);

// 3
const signature = sign(alice.privateKey, hashedMessage);

console.log("Hash del mensaje", hashedMessage);
console.log("Frima digital", signature);

// Bob
// 4
const publicKeyRecovered = recoverPublicKey(signature, hashedMessage);
console.log("Llave publica recuperada de la firma", publicKeyRecovered);

console.log(alice.publicKey == publicKeyRecovered);
