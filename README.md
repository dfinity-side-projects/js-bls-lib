[![NPM Package](https://img.shields.io/npm/v/bls-lib.svg?style=flat-square)](https://www.npmjs.org/package/bls-lib)
[![Build Status](https://img.shields.io/travis/dfinity/js-bls-lib.svg?branch=master&style=flat-square)](https://travis-ci.org/dfinity/js-bls-lib)
[![Coverage Status](https://img.shields.io/coveralls/dfinity/js-bls-lib.svg?style=flat-square)](https://coveralls.io/r/dfinity/js-bls-lib)


[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

# Synopsis

This libary provides primitives for creating and verifying [BLS threshold signatures](https://en.wikipedia.org/wiki/Boneh–Lynn–Shacham) in Webassembly with a JS API. All the hard work is done by [herumi/bls](https://github.com/herumi/bls). This wraps the bls C++ code which is compiled to Webassembly for easier use.

## Installation
`npm install bls-lib`

## Usage

```javascript

const bls = require('bls-lib')
bls.onModuleInit(() => {
  bls.init()

  const sec = bls.secretKey()
  const pub = bls.publicKey()
  const sig = bls.signature()

  bls.secretKeySetByCSPRNG(sec)
  const msg = 'hello world'
  bls.sign(sig, sec, msg)

  bls.getPublicKey(pub, sec)

  const v = bls.verify(sig, pub, msg)
  // v === true

  bls.free(sec)
  bls.free(sig)
  bls.free(pub)
})
```

# Examples
[./examples/](./examples/)

# API
[./docs/](./docs/index.md)

# Dependents
* [verifiable secret sharing](https://github.com/dfinity/vss)
* [distributed key generation](https://github.com/dfinity/dkg)

# Building

First install the dependencies [emscripten](https://github.com/kripken/emscripten) and [ninja](ninja-build.org)

```
 git clone --recursive https://github.com/dfinity/js-bls-lib.git
 cd js-bls-lib/build
 ninja
```

## License

[**(C) 2017 DFINITY STIFTUNG**](http://dfinity.network)

[MPL-2.0][LICENSE]

[LICENSE]: https://tldrlegal.com/license/mozilla-public-license-2.0-(mpl-2)

![image](https://user-images.githubusercontent.com/6457089/32753794-10f4cbc2-c883-11e7-8dcf-ff8088b38f9f.png)
