var crypto = require("crypto");

// Generando una sal (entropía)
const altoEntropia = crypto.randomBytes(32);

// Usaremos este valor para generar una llave privada
console.log(altoEntropia.toString("hex"));
