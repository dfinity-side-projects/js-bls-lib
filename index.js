const nop = require('nop')
const mod = require('./build/bls_lib.js')

let init = false
let initCb = nop

exports.mod = mod

/**
 * takes a callback that is called once the module is setup
 * @params {Function} cb - the callback tobe called once the module is intailized
 */
exports.onModuleInit = function (cb) {
  if (init) {
    cb()
  } else {
    init = true
    initCb = cb
  }
}

/**
 * the FP254BNB curve
 */
exports.MCLBN_CURVE_FP254BNB = 0

/**
 * the FP382_1 curve
 */
exports.MCLBN_CURVE_FP382_1 = 1

/**
 * the FP382_2 curve
 */
exports.MCLBN_CURVE_FP382_2 = 2

const MCLBN_FP_UNIT_SIZE = 6
const FR_SIZE = MCLBN_FP_UNIT_SIZE * 8
const ID_SIZE = FR_SIZE
const G1_SIZE = FR_SIZE * 3
const G2_SIZE = FR_SIZE * 3 * 2

mod.onRuntimeInitialized = function () {
  /**
   * intailizes the libary to use a given curve
   * @param {number} curve - the curves that can be used are MCLBN_CURVE_FP254BNB, MCLBN_CURVE_FP382_1 or MCLBN_CURVE_FP382_2
   */
  exports.init = function (curve = exports.MCLBN_CURVE_FP254BNB) {
    return mod._blsInit(curve, MCLBN_FP_UNIT_SIZE)
  }

  /**
   * allocates a secret key
   * @returns {number} the pointer to the key
   */
  exports.secretKey = function () {
    return mod._malloc(FR_SIZE)
  }

  /**
   * allocates a secret key
   * @returns {number} the pointer to the key
   */
  exports.publicKey = function () {
    return mod._malloc(G2_SIZE)
  }

  /**
   * allocates a signature
   * @returns {number} the pointer to the signture
   */
  exports.signature = function () {
    return mod._malloc(G1_SIZE)
  }

  /**
   * frees a pointer
   */
  exports.free = function (x) {
    mod._free(x)
  }

  /**
   * frees an array of pointers
   */
  exports.freeArray = function (a) {
    a.forEach(el => mod._free(el))
  }

  /**
   * creates an ID from an int to use in with threshold groups
   * @param {number} sk - a pointer to the secret key, secret key stuct is used to hold the id
   * @param {number} n - a int repsenting the ID. n cannot be zero.
   */
  exports.idSetInt = function (sk, n) {
    if (n === 0) {
      throw new Error('id cannot be zero')
    }
    mod._blsIdSetInt(sk, n)
  }

  /**
   * creates an ID from an int and returns a pointer to it
   * @param {number} n - a int repsenting the ID. n cannot be zero.
   * @return {number}
   */
  exports.idImportFromInt = function (n) {
    const sk = exports.secretKey()
    exports.idSetInt(sk, n)
    return sk
  }

  /**
   * creates an ID from an int and returns a pointer to it
   * @param {number} n - a int repsenting the ID. n cannot be zero.
   * @return {number}
   */
  exports.idImport = function (n) {
    if (Number.isInteger(n)) {
      return exports.idImportFromInt(n)
    } else {
      const sk = exports.secretKey()
      mod._blsHashToSecretKey(sk, n)
      return sk
    }
  }

  /**
   * signs a message
   * @param {number} sig - a pointer to the a signature
   * @param {number} sk - a pointer to the secret key
   * @param {TypedArray|String} msg - the message to sign
   */
  exports.sign = wrapInput(mod._blsSign)

  /**
   * verifies a signature
   * @param {number} sig - a pointer to the a signature
   * @param {number} pk - a pointer to the secret key
   * @param {TypedArray|String} msg - the message that was signed
   * @returns {Boolean}
   */
  exports.verify = returnBool(wrapInput(mod._blsVerify))

  /**
   * given a pointer to a public key this returns 64 byte Int8Array containing the key
   * @param {number} pk - a pointer to the secret key
   * @return {TypedArray}
   */
  exports.publicKeyExport = wrapOutput(mod._blsPublicKeySerialize, 64)

  /**
   * given a pointer to a secret key this returns 32 byte Int8Array containing the key
   * @param {number} pk - a pointer to the secret key
   * @return {TypedArray}
   */
  exports.secretKeyExport = wrapOutput(mod._blsSecretKeySerialize, 32)

  /**
   * given a pointer to a signature this returns 32 byte Int8Array containing the signature
   * @param {number} pk - a pointer to the secret key
   * @return {TypedArray}
   */
  exports.signatureExport = wrapOutput(mod._blsSignatureSerialize, 32)

  /**
   * generates a secret key given a seed phrase.
   * @param {number} sk - a pointer to a secret key
   * @param {String|TypedArray} seed - the seed phrase
   */
  exports.hashToSecretKey = wrapInput(mod._blsHashToSecretKey)

  /**
   * write a secretKey to memory
   * @param {number} sk - a pointer to a secret key
   * @param {TypedArray} array - the secret key as a 32 byte TypedArray
   */
  exports.secretKeyDeserialize = wrapInput(mod._blsSecretKeyDeserialize)

  /**
   * write a secretKey to memory and returns a pointer to it
   * @param {number} sk - a pointer to a secret key
   * @param {TypedArray} array - the secret key as a 32 byte TypedArray
   * @return {Number}
   */
  exports.secretKeyImport = function (buf) {
    const sk = exports.secretKey()
    exports.secretKeyDeserialize(sk, buf)
    return sk
  }

  /**
   * write a publicKey to memory
   * @param {number} sk - a pointer to a public key
   * @param {TypedArray} array - the secret key as a 64 byte TypedArray
   */
  exports.publicKeyDeserialize = wrapInput(mod._blsPublicKeyDeserialize)

  /**
   * write a publicKey to memory and returns a pointer to it
   * @param {TypedArray} array - the secret key as a 64 byte TypedArray
   * @return {Number}
   */
  exports.publicKeyImport = function (buf) {
    const pk = exports.publicKey()
    exports.publicKeyDeserialize(pk, buf)
    return pk
  }

  /**
   * write a signature to memory
   * @param {number} sig - a pointer to a signature
   * @param {TypedArray} array - the signature as a 32 byte TypedArray
   */
  exports.signatureDeserialize = wrapInput(mod._blsSignatureDeserialize)

  /**
   * write a signature to memory and returns a pointer to it
   * @param {TypedArray} array - the signature as a 32 byte TypedArray
   * @return {Number}
   */
  exports.signatureImport = function (buf) {
    const sig = exports.signature()
    exports.signatureDeserialize(sig, buf)
    return sig
  }

  /**
   * Initialize a secret key by a Cryptographically Secure Pseudo Random Number Generator
   * @param {TypedArray} array - the secret key as a TypedArray
   */
  exports.secretKeySetByCSPRNG = mod._blsSecretKeySetByCSPRNG

  /**
   * Create a public key from the secret key
   * @param {TypedArray} array - the public key as a TypedArray
   * @param {TypedArray} array - the secret key as a TypedArray
   */
  exports.getPublicKey = mod._blsGetPublicKey

  /**
   * Recovers a secret key for a group given the groups secret keys shares and the groups ids
   * @param {number} sk - a pointer to a secret key that will be generated
   * @param {Array<number>} sksArray - an array of pointers to the groups secret key shares. The length of the array should be the threshold number for the group
   * @param {Array<numbers>} idArrah - an array of pointers to ids in the groups. The length of the array should be the threshold number for the group
   */
  exports.secretKeyRecover = wrapRecover(mod._blsSecretKeyRecover, FR_SIZE, ID_SIZE)

  /**
   * Recovers a public key for a group given the groups public keys shares and the groups ids
   * @param {number} pk - a pointer to a public key that will be generated
   * @param {Array<number>} pksArray - an array of pointers to the groups public key shares. The length of the array should be the threshold number for the group
   * @param {Array<numbers>} idArrah - an array of pointers to ids in the groups. The length of the array should be the threshold number for the group
   */
  exports.publicKeyRecover = wrapRecover(mod._blsPublicKeyRecover, G2_SIZE, ID_SIZE)

  /**
   * Recovers a signature for a group given the groups public keys shares and the groups ids
   * @param {number} sig - a pointer to the signature that will be generated
   * @param {Array<number>} sigArray - an array of pointers to signature shares. The length of the array should be the threshold number for the group
   * @param {Array<numbers>} idArrah - an array of pointers to ids in the groups. The length of the array should be the threshold number for the group
   */
  exports.signatureRecover = wrapRecover(mod._blsSignatureRecover, G1_SIZE, ID_SIZE)

  /**
   * Creates a secket key share for a group member given the groups members id (which is a the secret key) and array of master secret keys
   * @param {number} skshare - a pointer to a secret key that will be generated
   * @param {Array<number>} msk - an array of master secret keys. The number of keys is the threshould of the group.
   * @param {number} id - the id of the member
   */
  exports.secretKeyShare = wrapKeyShare(mod._blsSecretKeyShare, FR_SIZE)

  /**
   * Creates a public key share for a group member given the groups members id (which is a the secret key) and array of master public keys
   * @param {number} pkshare - a pointer to a secret key that will be generated
   * @param {Array<number>} mpk - an array of master public keys. The number of keys is the threshould of the group.
   * @param {number} id - the id of the member
   */
  exports.publicKeyShare = wrapKeyShare(mod._blsPublicKeyShare, G2_SIZE)

  /**
   * Take two publicKeys and adds them together. pubkey1 = pubkey1 + pubkey2
   * @param {number} pubkey1 - a pointer to a public key
   * @param {number} pubkey2 - a pointer to a public key
   */
  exports.publicKeyAdd = mod._blsPublicKeyAdd

  /**
   * Take two secretKeys and adds them together. seckey1 = seckey1 + seckey2
   * @param {number} seckey1 - a pointer to a secret key
   * @param {number} seckey2 - a pointer to a secret key
   */
  exports.secretKeyAdd = mod._blsSecretKeyAdd

  /**
   * Take two publicKeys and tests thier equality
   * @param {number} pubkey1 - a pointer to a public key
   * @param {number} pubkey2 - a pointer to a public key
   * return {Boolean}
   */
  exports.publicKeyIsEqual = returnBool(mod._blsPublicKeyIsEqual)

  /**
   * Does Diffie–Hellman key exchange
   * @param {number} sharedSecretKey - a pointer to a secretKey that will be populated with the shared secret
   * @param {number} secretKey - a pointer to a secret key
   * @param {number} pubkey - a pointer to a public key
   */
  exports.dhKeyExchange = mod._blsDHKeyExchange

  initCb()
}

function returnBool (func) {
  return function () {
    return func.apply(null, arguments) === 1
  }
}

function wrapInput (func) {
  return function () {
    const args = [...arguments]
    let buf = args.pop()
    if (typeof buf === 'string') {
      buf = Buffer.from(buf)
    }
    const pos = mod._malloc(buf.length)

    mod.HEAP8.set(buf, pos)
    let r = func(...args, pos, buf.length)
    mod._free(pos)
    return r
  }
}

function wrapOutput (func, size) {
  return function (x) {
    const pos = mod._malloc(size)
    const n = func(pos, size, x)
    const a = mod.HEAP8.slice(pos, pos + n)
    mod._free(pos)
    return a
  }
}

function wrapKeyShare (func, dataSize) {
  return function (x, vec, id) {
    const k = vec.length
    const p = mod._malloc(dataSize * k)
    for (let i = 0; i < k; i++) {
      mod._memcpy(p + i * dataSize, vec[i], dataSize)
    }
    const r = func(x, p, k, id)
    mod._free(p)
    return r
  }
}

function wrapRecover (func, dataSize, idDataSize) {
  return function (x, vec, idVec) {
    const n = vec.length
    const p = mod._malloc(dataSize * n)
    const q = mod._malloc(idDataSize * n)
    for (let i = 0; i < n; i++) {
      mod._memcpy(p + i * dataSize, vec[i], dataSize)
      mod._memcpy(q + i * idDataSize, idVec[i], idDataSize)
    }
    const r = func(x, p, q, n)
    mod._free(q)
    mod._free(p)
    return r
  }
}
