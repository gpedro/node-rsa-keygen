node-rsa-keygen
===============

Generates a RSA keypair using native OpenSSL library.

History
-------
As from node 0.11 the `crypto` library has `publicEncrypt` and `privateDecrypt` functions, we don't need to rely on any external libraries for public-key cryptography.

Usage
----
Install the library:
```
npm install --save rsa-keygen
```

```javascript
var rsaKeygen = require('rsa-keygen');
var keys = rsaKeygen.generate();
```

Example
-------
```javascript
var crypto = require('crypto');
var rsaKeygen = require('rsa-keygen');

var keys = rsaKeygen.generate();

var result = crypto.publicEncrypt({
    key: keys.public_key
}, new Buffer('Hello world!'));
// <Crypted Buffer>

var plaintext = crypto.privateDecrypt({
    key: keys.private_key
}, result);
// Hello world!
```
