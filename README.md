# SYNOPSIS 
[![NPM Package](https://img.shields.io/npm/v/bls-lib.svg?style=flat-square)](https://www.npmjs.org/package/bls-lib)
[![Build Status](https://img.shields.io/travis/wanderer/bls-lib.svg?branch=master&style=flat-square)](https://travis-ci.org/wanderer/bls-lib)
[![Coverage Status](https://img.shields.io/coveralls/wanderer/bls-lib.svg?style=flat-square)](https://coveralls.io/r/wanderer/bls-lib)


[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)  

This libary provides primitives for creating and verifying [BLS threshold signatures](https://en.wikipedia.org/wiki/Boneh–Lynn–Shacham). All the hard work is done by [herumi/bls](https://github.com/herumi/bls). This wraps the bls C++ code which is compiled to Webassembly for easier use.

# INSTALL
`npm install bls-lib`

# USAGE

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

# EXAMPLES
[./examples/](./examples/)

# API
[./docs/](./docs/index.md)

# BUILDING

First install the dependancies [emscripten](https://github.com/kripken/emscripten) and [ninja](ninja-build.org)

```
 git clone --recursive https://github.com/wanderer/bls-lib.git 
 cd bls-lib/build
 ninja
```

# LICENSE
[MPL-2.0](https://tldrlegal.com/license/mozilla-public-license-2.0-(mpl-2))
