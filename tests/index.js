const tape = require('tape')
const shuffle = require('array-shuffle')
const bls = require('../index.js')

bls.onModuleInit(() => {
  tape('basic', t => {
    t.plan(2)
    bls.onModuleInit(() => {
      t.pass(true)
      bls.init()
      const sec = bls.secretKey()
      const pub = bls.publicKey()
      const sig = bls.signature()

      const secString = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      const secArray = Buffer.from(secString, 'hex')
      bls.secretKeyDeserialize(sec, secArray)

      const pubString = '7ca19ff032c22a00b3d79d8961495af4c6c93c9c2b62bd7279570fcc2ca8d120fc75fd16f55ded79f6392a0769496817cded4760ed658d62627b9e6852b1100d'

      bls.publicKeyDeserialize(pub, Buffer.from(pubString, 'hex'))

      const msg = 'test'
      bls.sign(sig, sec, msg)

      const v = bls.verify(sig, pub, msg)
      t.equals(v, 1)
    })
  })

  tape('verify', t => {
    bls.init()
    const sec = bls.secretKey()
    const pub = bls.publicKey()
    const sig = bls.signature()

    bls.secretKeySetByCSPRNG(sec)
    const msg = Buffer.from('hello world')
    bls.sign(sig, sec, msg)

    bls.getPublicKey(pub, sec)

    const v = bls.verify(sig, pub, msg)
    t.equals(v, 1)

    bls.free(sec)
    bls.free(sig)
    bls.free(pub)

    t.end()
  })

  tape('import/export', t => {
    bls.init()
    const sec = bls.secretKey()
    let sig = bls.signature()
    let pub = bls.publicKey()

    const secString = 'a3d34923c039a45a50bfb6bc0943c77589a23cd27d7118c1bede0c61d6bab108'
    let secArray = Buffer.from(secString, 'hex')
    bls.secretKeyDeserialize(sec, secArray)

    secArray = bls.secretKeySerialize(sec)
    t.equals(Buffer.from(secArray).toString('hex'), secString)

    bls.getPublicKey(pub, sec)
    const pubArray = bls.publicKeySerialize(pub)

    secArray = bls.secretKeySerialize(sec)

    const msg = 'hello world'
    bls.sign(sig, sec, msg)

    const sigArray = bls.signatureSerialize(sig)

    bls.free(sec)
    bls.free(sig)
    bls.free(pub)

    // recover
    sig = bls.signature()
    pub = bls.publicKey()

    bls.signatureDeserialize(sig, sigArray)
    bls.publicKeyDeserialize(pub, pubArray)

    const v = bls.verify(sig, pub, msg)
    t.equals(v, 1)

    bls.free(sec)
    bls.free(sig)
    bls.free(pub)

    t.end()
  })

  tape('shares', t => {
    bls.init()
    const numOfPlayers = 5
    const threshold = 3

    const masterSecretKey = []
    const masterPublicKey = []

    const ids = []
    const secretKeys = []
    const publicKeys = []
    const sigs = []
    const msg = 'hello world'

    // set up master key share
    for (let i = 0; i < threshold; i++) {
      const sk = bls.secretKey()
      bls.secretKeySetByCSPRNG(sk)
      masterSecretKey.push(sk)

      const pk = bls.publicKey()
      bls.getPublicKey(pk, sk)

      masterPublicKey.push(pk)
    }

    const masterSig = bls.signature()
    bls.sign(masterSig, masterSecretKey[0], msg)

    // key sharing
    for (let i = 0; i < numOfPlayers; i++) {
      const id = bls.secretKey()
      bls.secretKeySetByCSPRNG(id)
      ids.push(id)

      const sk = bls.secretKey()
      bls.secretKeyShare(sk, masterSecretKey, id)
      secretKeys.push(sk)

      const pk = bls.publicKey()
      bls.publicKeyShare(pk, masterPublicKey, id)
      publicKeys.push(pk)

      const pk2 = bls.publicKey()
      bls.getPublicKey(pk2, sk)

      const pubArray1 = bls.publicKeySerialize(pk)
      const pubArray2 = bls.publicKeySerialize(pk2)
      bls.free(pk2)
      t.equals(Buffer.from(pubArray2).toString('hex'), Buffer.from(pubArray1).toString('hex'), 'public keys should be equals')

      const sig = bls.signature()
      bls.sign(sig, sk, msg)

      sigs.push(sig)
      const r = bls.verify(sig, pk, msg)

      t.equals(r, 1, 'should verify')
    }

    // recover
    const subIds = []
    const subSecretKeys = []
    const subPubs = []
    const subSigs = []

    let indexes = new Array(numOfPlayers).fill(0).map((el, i) => i)
    indexes = shuffle(indexes)
    for (let i = 0; i < threshold; i++) {
      const index = indexes[i]
      subIds.push(ids[index])
      subSecretKeys.push(secretKeys[index])
      subPubs.push(publicKeys[index])
      subSigs.push(sigs[index])
    }

    const sk = bls.secretKey()
    const pk = bls.publicKey()
    const sig = bls.signature()

    bls.secretKeyRecover(sk, subSecretKeys, subIds)
    bls.publicKeyRecover(pk, subPubs, subIds)
    bls.signatureRecover(sig, subSigs, subIds)

    const secArray = bls.secretKeySerialize(sk)
    const masterSk = bls.secretKeySerialize(masterSecretKey[0])

    t.equals(Buffer.from(secArray).toString('hex'), Buffer.from(masterSk).toString('hex'), 'should recover master SK')

    const publicKey = bls.publicKeySerialize(pk)
    const masterPk = bls.publicKeySerialize(masterPublicKey[0])

    t.equals(Buffer.from(publicKey).toString('hex'), Buffer.from(masterPk).toString('hex'), 'should recover master PK')

    const signature = bls.signatureSerialize(sig)
    const sMasterSig = bls.signatureSerialize(masterSig)
    t.equals(Buffer.from(signature).toString('hex'), Buffer.from(sMasterSig).toString('hex'), 'signature should be the same as master')

    bls.free(sig)
    bls.free(pk)
    bls.free(sk)

    for (let i = 0; i < numOfPlayers; i++) {
      bls.free(ids[i])
      bls.free(secretKeys[i])
      bls.free(publicKeys[i])
      bls.free(sigs[i])
    }

    t.end()
  })
})
