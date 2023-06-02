# evit-gm-crypt

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

基于`javascript`和[`TypedArray`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray)的国密加密算法实现。

Implement of Chinese encrypt algorithm in JavaScript and [TypedArray](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray).

为了兼容浏览器环境和node.je环境，这里我们使用了[TextEncoder](https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder)和[Base64.js](https://github.com/beatgammit/base64-js)。

Here we use [TextEncoder](https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder) and [Base64.js](https://github.com/beatgammit/base64-js) for both browser and node.js environment.

由于使用了`TextEncoder`，所以暂时不支持`Edge`。Node.js版本最低为8，建议使用最新的LTS版本。

Because of using `TextEncoder`， this code cannot run in `Edge` browser. `Node.js`‘s version should at least be 8, and the newest LTS version is recommended.

新增特性
 - 与[`openssl_encrypt`](https://www.php.net/manual/en/function.openssl-encrypt.php)和[`openssl_decrypt`](https://www.php.net/manual/en/function.openssl-decrypt.php)保持一致性，当密码长度小于16时，静默填充NUL；当密码长度大于16时，静默截断。
 - 要使用openssl国密算法，openssl库需 >= 1.1.1

## Roadmap

- [x] SM4
- [x] SM3
- [ ] SM2

## Documentation

### Install

```
npm install evit-gm-crypt
```

### SM4

#### Init

```js
const SM4 = require('gm-sm4').sm4

let sm4Config = {
  // encrypt/decypt main key; cannot be omitted
  key: 'JeF8U9wHFOMfs2Y8',

  // optional; can be 'cbc' or 'ecb'
  mode: 'cbc', // default

  // optional; when use cbc mode, it's necessary
  iv: 'UISwD9fW6cFh9SNS', // default is null

  // optional: this is the cipher data's type; Can be 'base64' or 'text'
  cipherType: 'base64' // default is base64
}

let sm4 = new SM4(sm4Config)
```

#### Encrypt

```js
let plaintext = '中国国密加解密算法'
let ciphertext = sm4.encrypt(plaintext)
// ciphertext's result is 'j/+HgSpv8RZQI2YtSq0L1RnemiSokMm1VvLHSTt245U='
```

#### Decrypt

```js
let ciphertext = 'j/+HgSpv8RZQI2YtSq0L1RnemiSokMm1VvLHSTt245U='
let plaintext = sm4.decrypt(ciphertext)
// plaintext's result is '中国国密加解密算法'
```


## License

[MIT](LICENSE)
