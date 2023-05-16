# CRIPTOGRAFÍA DE LLAVE PÚBLICA (UNA FORMA DE CIFRADO ASIMÉTRICO)

Las llaves privadas y las llaves públicas son componentes esenciales en el mundo de las criptomonedas como Bitcoin y Ethereum para acceder a sus activos digitales. Comprender lo que significan y cómo se crean es crucial para cualquiera que quiera participar en el mundo de la tecnología blockchain.

Las llaves privadas son como contraseñas que le permiten administrar sus activos digitales dentro de la cadena de bloques. Las llaves públicas se utilizan para verificar las firmas digitales y para derivar la dirección de Ethereum. Al usar las direcciones de Ethereum, puede interactuar con varias aplicaciones creadas sobre cadenas de bloques. En esta sección nos sumergiremos en esos conceptos.

## ¿Qué es una llave privada?

Una llave privada es una contraseña especial que permite el acceso a sus activos. No se puede restablecer, funciona como una firma digital y debe ser difícil de crear.

### Es una contraseña

Una llave privada es como una contraseña especial que le permite controlar su dinero en la cadena de bloques. De la misma manera que usa una contraseña para acceder a una caja fuerte, al usar su llave privada puede acceder a su dinero y asegurarse de que solo usted pueda usarlo.

### Acceso a tu reino

Quien tenga su llave privada, podrá disponer de los activos asociados a esa llave privada. Tus bienes están a voluntad de la otra persona. De aquí podemos entender la frase "no tus llaves, no tu criptografía".

### No se puede restablecer

Las llaves privadas son como contraseñas que no se pueden restablecer. Tienen un carácter insustituible y la necesidad de salvaguardarlos se vuelve muy importante.

### Firma digital

Una llave privada funciona como una firma digital porque se usa para autenticar y autorizar transacciones en una cadena de bloques. Prueba la propiedad de la dirección de Ethereum asociada a ella.

### Difícil creación

El proceso de creación de una llave privada debe ser criptográficamente seguro. Por lo tanto, debe utilizar los algoritmos más avanzados en la generación de valores aleatorios.

### Ejemplo de llave privada

Se compone de una secuencia aleatoria de caracteres. Cuanto más aleatorio, más seguro. Tiene 64 letras.

```
// Ejemplo de llave privada:
621afc7ac8821faa8fb484d9e3a68ba13b6171f01246f8d5f6bc1947e7d5cc8b
```

### Características de una llave privada

- Tiene un tamaño de 32 bytes porque es la entrada de `secp256k1` que es una especie de curva elíptica que se usa en Ethereum para crear una llave pública a partir de una llave privada.

- 32 bytes es lo mismo que 256 bits (1 byte = 8 bits)

  ```
  // 256 bits - cada posición puede tener 0 o 1
  1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
  ```

- Normalmente se representa en valores hexadecimales. Aquí, un solo carácter está representado por 4 bits. Eso significa que una llave privada de 256 bits tendrá 64 caracteres (4 bits = 1 carácter)

  ```
  // longitud de llave privada hexadecimal = 64
  3a44cf0f69716237725da985f003f8de05bc8efc5dcd9430caf2a6d2cd7d98b7
  ```

- En informática, un `nibble` es una unidad de datos que consta de 4 bits y está en formato hexadecimal. Hay un total de 64 "nibbles" en una llave privada. Cada `nibble` tiene 16 valores posibles, como `0 - 9` y `A - F`. Aquí hay una lista de todas las combinaciones posibles de un `nibble`:

  | binario | hexadecimal |
  | ------- | ----------- |
  | 0000    | 0           |
  | 0001    | 1           |
  | 0010    | 2           |
  | 0011    | 3           |
  | 0100    | 4           |
  | 0101    | 5           |
  | 0110    | 6           |
  | 0111    | 7           |
  | 1000    | 8           |
  | 1001    | 9           |
  | 1010    | A           |
  | 1011    | B           |
  | 1100    | C           |
  | 1101    | D           |
  | 1110    | E           |
  | 1111    | F           |

### Seguridad

En lo que respecta a una llave privada, se considera que cuanto más aleatoria sea la llave privada, más segura. Aleatorio significa que sus caracteres son muy diferentes entre sí.

Para crear una llave privada fuerte (aleatoria e impredecible), podríamos usar una sal. La sal es una fuente adicional de aleatoriedad que en criptografía se conoce como entropía. Esta ayuda adicional conduce a la creación de llaves privadas con alta entropía. También se podría usar una contraseña encima de la sal para agregar más entropía.

## ¿Qué es la entropía?

La entropía es una medida de la aleatoriedad o imprevisibilidad de los datos. Una entropía alta significa que los datos son muy difíciles de predecir o adivinar, mientras que una entropía baja significa que los datos son más predecibles y fáciles de adivinar. Al crear llaves privadas, la entropía necesaria para la creación debe ser lo suficientemente alta como para garantizar que la llave privada sea altamente segura.

Ejemplos de llaves privadas con baja entropía:

- Patrones repetitivos:

```javascript
const privateKey =
  "11111111111111111111111111111111111111111111111111111111111111111";
```

- Secuencias predecibles:

```javascript
const llave privada = "1234567890123456789012345678901234567890123456789012345678901234";

const privateKey = "ABCD00000000000000000000000000000000000000000000000000000000000000";
```

### ¿Cómo crear alta entropía?

La entropía no es necesariamente una cantidad o un tamaño. Sin embargo, por lo general, 32 bytes aleatorios tienen suficiente entropía para generar una llave privada segura que es difícil de adivinar o de fuerza bruta.

Hay algunas bibliotecas que nos ayudan a agregar una sal (más entropía) como fuente para crear llaves privadas. Revisaremos la biblioteca `crypto`.

```Javascript
importar {randomBytes} de "crypto";

// Generando una sal (entropía)
const entropía = randomBytes(32);
```

Esa entropía se usará más adelante como entrada para crear una llave privada con alta entropía.

## ¿Por qué una llave privada tiene 32 bytes (256 bits)?

Debido a que es la entrada del algoritmo de curva elíptica `secp256k1`, proporciona un gran grupo de llaves, facilita la realización de operaciones bit a bit, es compatible con otros sistemas y su memoria es eficiente, usable y segura.

### Entrada para `secp256k1`

La criptografía de curva elíptica más utilizada en Bitcoin y Ethereum es `secp256k1`. Este algoritmo se utiliza para calcular una llave pública a partir de una llave privada. El tipo de entrada esperada en ese algoritmo es una llave privada de 32 bytes.

### Piscina grande

Una llave privada de 32 bytes proporciona `2^256` combinaciones posibles, lo que crea un enorme grupo de llaves privadas. Dicha cantidad es mayor que la cantidad de átomos en el universo observable.

### Más fácil de operar

32 bytes es una potencia de 2, lo que significa que es más fácil realizar una operación bit a bit en la llave

### Compatible con otros sistemas

Otros algoritmos criptográficos utilizan una llave privada de 32 bytes, lo que facilita la integración con otros sistemas.

### Memoria eficiente

32 bytes es lo suficientemente pequeño para que las computadoras los almacenen en la memoria y no afecta el rendimiento o los requisitos de almacenamiento en comparación con una llave de mayor tamaño.

### Seguro y utilizable

Hay un equilibrio entre seguridad y usabilidad. Una llave más grande podría ralentizar las operaciones y aumentar los requisitos de almacenamiento.

## ¿Todas las llaves privadas son válidas?

Más probable es que sí. Las posibilidades de generar llaves privadas no válidas son prácticamente nulas. Para ser más precisos, la llave privada debe estar en el rango de `1` a `n - 1` donde `n` es el orden de la curva elíptica. Orden en la curva elíptica significa el número de puntos en la curva. `n` es un número primo y básicamente es una restricción dentro del algoritmo `secp256k1` y cuando se usa un número mayor que el orden `n`, la llave pública no sería correcta y podría comprometer su seguridad.

De acuerdo con [Standards for Efficient Cryptography Group](http://www.secg.org/sec2-v2.pdf) (p.9) con respecto a la curva elíptica `secp256k1`, el orden `n` es igual a ` FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` que es bastante grande y casi cualquier número de 32 bytes será más pequeño que él.

Sin embargo, una llave privada válida no significa que sea una llave privada segura. Normalmente, una llave con más entropía haría que la llave fuera más segura.

## ¿Cómo crear llaves privadas?

Usaremos el módulo [crypto](https://nodejs.org/api/crypto.html) integrado de nodejs. Dentro de esta biblioteca, hay un método llamado `pbkdf2` que significa `función de derivación de llave basada en contraseña 2`. Este método toma varios parámetros como `contraseña`, `salt`, `número de iteraciones`, `longitud de llave` y tipo de `función hash` para crear una llave privada. Este método `pbkdf2` es determinista, lo que significa que, dados los mismos parámetros, obtendrá el mismo resultado. Este método `pbkdf2` es una práctica estándar de la industria para generar llaves privadas seguras.

Veamos cómo implementarlo:

1. Primero, definimos `salt`, `contraseña`, `número de iteraciones`, `longitud de llave` y tipo de `función hash`. Todos estos parámetros añaden más entropía y hacen más segura la generación de una llave privada:

   1. `salt`: se usa para prevenir ataques mediante el uso de tablas precalculadas
   2. `contraseña`: agrega un secreto específico del usuario al proceso de obtención de llaves
   3. `número de iteraciones` - recomendado al menos 10.000 veces. Fortalece la llave derivada
   4. `longitud de la llave`: necesitamos una salida de 32 bytes, ya que representará nuestra llave privada
   5. `función hash`: por lo general, el `sha256` se usa ampliamente porque es resistente a las colisiones y ha sido bien estudiado

2. Se recomienda usar una `sal` fuerte para agregar más entropía. Para eso, usaremos `randomBytes`. El método `randomBytes` genera "datos pseudoaleatorios criptográficamente sólidos". Por lo general, una entropía de 32 bytes de tamaño es lo suficientemente buena para crear suficiente imprevisibilidad y eso es exactamente lo que `randomBytes(32)` produce.
3. Usaremos otra biblioteca ([generate-password](https://www.npmjs.com/package/generate-password)) para crear contraseñas seguras para evitar ataques de fuerza bruta
4. Con la ayuda del método `pbkdf2` de la biblioteca `crypto`, obtuvimos nuestra llave privada fuerte

```javascript
import { pbkdf2, randomBytes } from "crypto";
import { generate } from "generate-password";

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
```

Ahora que tenemos nuestra llave privada, encontraremos una forma de crear una llave pública a partir de la llave privada. Para comprender mejor este proceso, hablaremos sobre qué es una curva elíptica y cómo se usa una curva en la creación de una llave pública a partir de una llave privada.

## La curva elíptica `secp256k1`

La criptografía de curva elíptica (ECC) es un tipo de criptografía de llave pública y se basa en las propiedades que tienen las curvas elípticas.

### Ecuación

Una curva elíptica genérica tiene la siguiente ecuación: `y^2 = x^3 + ax + b` donde `a` y `b` son constantes. La curva es simétrica alrededor del eje x y tiene un punto en el infinito. El ECC utilizado en Bitcoin y Ethereum (`secp256k1`) es una implementación específica de esa ecuación. Tiene los siguientes valores: `y^2 = x^3 + 7`. Se parece a esto:

![curva-elíptica](https://github.com/leemarreros/criptografia-llave-publica/assets/3300958/74431d6a-19c1-486f-b24b-44e55ed78fb6)

Tenga en cuenta que para averiguar la llave pública, la ecuación ECC `y^2 = x^3 + 7` no se usa directamente. Se utiliza para definir la propia curva sobre la que se produce la multiplicación escalar de puntos y también para garantizar que la llave pública resultante esté en la curva.

### Tamaño de llave

Una de las principales ventajas de ECC sobre RSA (otro sistema de criptografía de llave pública) es que ECC proporciona un alto nivel de seguridad con una llave más pequeña en comparación con RSA. En RSA, el tamaño de llave requerido suele ser de 2048 o 3072 bits, mientras que en ECC se requiere una llave de 256 bits. Eso hace que ECC sea más eficiente y rápido para las operaciones criptográficas sin sacrificar la seguridad.

![image-20230418105134816](https://github.com/leemarreros/criptografia-llave-publica/assets/3300958/460c9684-5732-4810-829f-e2142090abdf)

### Otras curvas

De todas las curvas elípticas, se eligió `secp256k1` para su uso en Bitcoin y otras criptomonedas. Otras curvas que se consideraron son `secp256r1` y `secp384f1`. El primero tiene un tamaño de llave más grande y no es tan rápido como para la multiplicación escalar. El segundo requiere muchos más recursos computacionales y es lento para la multiplicación escalar.

### irrompible

No hay vulnerabilidades conocidas para descifrar el cifrado hasta el momento. La curva `secp256k1` ofrece un buen equilibrio entre seguridad, rendimiento y tamaño de llave.

Intentar descifrar la llave privada de la llave pública es prácticamente imposible utilizando cualquier método conocido. Un atacante necesitaría probar `2^256` posibles llaves privadas. Eso no es factible usando ningún método computacional. Incluso si una computadora pudiera probar un billón de llaves por segundo, todavía tomaría miles de millones de años adivinar una llave privada.

## ¿Cómo crear una llave pública?

En el contexto de la criptografía de llave pública, la llave pública se deriva de la llave privada. Este proceso implica el uso de la ecuación de la curva elíptica `secp256k1` de forma indirecta. Podemos usar la siguiente fórmula para encontrar la llave pública de la llave privada:

```
P = (d * G) mod p
P: la llave pública
d: la llave privada
G: el punto base de la ECC
p: valor máximo de la llave pública resultante
```

Simplemente, esto significa que la llave pública es el resultado de "multiplicar" una llave privada por una constante `G`. Sobre ese resultado, aplicamos `mod p` para que nunca pase de `p`. Para ser más exactos, el término correcto para "multiplicar" es la multiplicación de puntos en la curva definida por la ecuación `y^2 = x^3 + 7`.

Veamos un proceso paso a paso de cómo sucede esto:

1. Esta curva tiene un punto de partida definido como `G(x, y)`. Se llama el punto base de la curva elíptica. Es fijo y acordado por todas las partes que utilizan esta curva. Los valores de las coordenadas G son los siguientes:

   `x = 55066263022277343669578718895168534326250603453777594175500187360389116729240`

   `y = 32670510020758816978083085130507043184471273380659243275938904335757337482424`

2. Definimos `p` como el valor máximo para envolver las llaves públicas resultantes. Hacemos eso para obtener el tamaño correcto para las llaves públicas. La forma de envolver un valor alrededor de `p` es aplicar `mod p` a ese valor. Veamos el valor de `p`:

   `p = 115792089237316195423570985008687907853269984665640564039457584007908834671663`

   Con respecto a la ecuación `y^2 = x^3 + 7` y `p`, podemos decir que todos los puntos `(x, y)` en la curva deben tener coordenadas que sean números enteros módulo p. En otras palabras, la curva solo incluye puntos que podrían incluirse dentro de `p`.

3. Nos dan una llave privada `d` que haremos multiplicación escalar de puntos por 'G'. A partir de ese resultado, aplicaremos `mod p` para que el resultado se mantenga dentro de `p`. Llegaremos a la llave pública.

4. La multiplicación escalar de puntos se realiza sobre la curva. Empiezas con una `G` y luego te mueves a lo largo de la curva hasta completar la multiplicación. El punto final estará en la curva y tendrá una coordenada `x` e `y`.

Hagámoslo en código ahora:

```Javascript
import { ec } from "elliptic";

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
```

Una vez que obtengamos la llave pública de la llave privada, podremos derivar la dirección de Ethereum de la llave pública. Veamos eso ahora.

## ¿Qué pasa con las direcciones de Ethereum?

La dirección de Ethereum se crea después de la llave privada y la llave pública. Sigamos estos pasos para llegar a la dirección de Ethereum comenzando con la llave pública.

1. En el algoritmo de curva elíptica, la llave pública es un par `(x, y)` que corresponde a un punto en la curva elíptica. `x` e `y` se concatenan después de `04` para crear la llave pública. <u>Nota</u>: Ese `04` deberá eliminarse más tarde. El `04` indica que la llave pública no está comprimida, lo que significa que las coordenadas `x` e `y` de la llave pública están incluidas en la cadena de llave pública.

   ```javascript
   import { ec } from "elliptic";
   import { randomBytes } from "crypto";
   import { keccak_256 } from "js-sha3";

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
   const publicKey = "04" + xEllipticCurve.toString("hex") + yEllipticCurve.toString("hex");

   // Or the equivalent:
   // const publicKey = keyPair.getPublic("hex");
   ```

2. El siguiente paso sería aplicar el algoritmo `keccack256` sobre la `publicKey`. Usaremos la biblioteca `js-sha3` que tiene el algoritmo `keccack256` para hash. Muchas otras bibliotecas tienen el mismo algoritmo.

   ```javascript
   import { keccak_256 } from "js-sha3";
   const hash = keccak_256(Buffer.from(publicKey, "hex").slice(1)); 

   // NOTE:
   // - .slice(1) removes the first byte from the 'publicKey'
   // - that first byte removed is "0x04" that was added previously
   ```

3. Una vez que obtenemos el `hash`, solo nos importan los últimos 20 bytes o los últimos 40 caracteres. Además, dado que está en formato hexadecimal, le agregamos `0x` inicialmente. Esa dirección sería una dirección de Ethereum derivada de la llave pública, que también se deriva de una llave privada.

   ```javascript
   const address = "0x" + hash.slice(-40);
   ```

## ¿Cómo se utilizan las llaves públicas y privadas para enviar información a través de la red?

Las llaves privadas y públicas son herramientas importantes para proteger las comunicaciones y transacciones digitales. Con ellos, puede asegurarse de que el destinatario deseado acceda a sus mensajes y transacciones. Además, lo ayudan a mantener su información confidencial a salvo de posibles atacantes.

Estudiaremos dos casos donde se utilizan llaves públicas y privadas:

1. Llaves públicas y privadas para el cifrado/descifrado
2. Llaves Públicas y Privadas para Firmas Digitales

### Llaves públicas y privadas para cifrado/descifrado

Supongamos que Alice quiere enviar un mensaje secreto a Bob. Este mensaje debe ser confidencial y nadie más podría leerlo. Este mensaje viajará por Internet. Cualquiera podrá ver el mensaje pero nadie podrá entenderlo. Veamos cómo funciona el proceso de cifrado y descifrado:

1. Bob generará una llave pública y privada. Él guarda su llave privada para sí mismo. Comparte su llave pública con todos, incluida Alice.
2. Alice cifrará el mensaje secreto utilizando la llave pública de Bob. Este mensaje cifrado se envía a través de Internet y un nybode es capaz de verlo.
3. Bob recibirá el mensaje encriptado. Sin embargo, él será el único en descifrar el mensaje utilizando su llave privada que solo él conoce.

Implementemos este proceso en código:

Para cifrar y descifrar usaremos la biblioteca `eth-crypto` porque proporciona dos métodos útiles llamados `encryptWithPublicKey` y `decryptWithPrivateKey`. La biblioteca `elliptic` solo se usa para generar la llave pública y privada, pero cualquier otra biblioteca que genere esas llaves sería suficiente.

```javascript
import { encryptWithPublicKey, decryptWithPrivateKey } from "eth-crypto";
import { ec } from "elliptic";

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
```

### Llaves Públicas y Privadas para Firmas Digitales

Supongamos que Alice quiere enviar un mensaje a Bob. En este caso, Alice quiere probar que ella escribió ese mensaje y también que el mensaje que Bob recibirá es el mismo que Alice pretendía. No es necesariamente importante si alguien puede ver el mensaje que se envía. Es más importante probar que Alice realmente lo está enviando. Veamos cómo ayuda una sinatura digital:

1. Alice generará una llave pública y privada. Mantiene su llave privada y comparte su llave pública con cualquiera, incluido Bob.
2. Alice crea un hash del mensaje usando el algoritmo `keccak256`
3. Alice firma el mensaje cifrado con su llave privada para crear la firma. Esta firma se envía junto con el mensaje cifrado a cualquier persona, incluido Bob.
4. Bob podrá recuperar la dirección de Ethereum o la llave pública de Alice a partir de la firma y el mensaje cifrado.

Vamos a implementarlo en código:

Para esta biblioteca también usaremos la biblioteca `eth-crypto`. Para crear la llave pública y privada, existe un método útil llamado `createIdentity`. Para crear la firma usaremos `sign`. Los métodos `recover` y `recoverPublicKey` nos ayudan a obtener la dirección de Ethereum o la llave pública de la firma y el mensaje cifrado, respectivamente.

```javascript
import {
    hash,
    createIdentity,
    sign,
    recover,
    recoverPublicKey,
} from "eth-crypto";

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
```
