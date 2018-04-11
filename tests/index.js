const tape = require('tape')
const shuffle = require('array-shuffle')
const bls = require('../index.js')

bls.onModuleInit(() => {
  tape('basic', t => {
    t.plan(2)
    bls.onModuleInit(() => {
      t.pass(true)
      bls.init()
      const sig = bls.signature()

      const secString = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      const secArray = Buffer.from(secString, 'hex')
      const sec = bls.secretKeyImport(secArray)

      const pubString = 'cd995480d3287eb8626b1a40b224ed9ada052cae3472665eba297b9785929a1f8ecee5b65dd580f12f239a7183490c4470595ec73cde697cb92d15f1b666c597'

      const pub = bls.publicKeyImport(Buffer.from(pubString, 'hex'))

      const msg = 'test'
      bls.sign(sig, sec, msg)

      const v = bls.verify(sig, pub, msg)
      t.equals(v, true)
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
    t.equals(v, true)

    bls.free(sec)
    bls.free(sig)
    bls.free(pub)

    t.end()
  })

  tape('import/export', t => {
    bls.init()
    let sig = bls.signature()
    let pub = bls.publicKey()

    const secString = 'a3d34923c039a45a50bfb6bc0943c77589a23cd27d7118c1bede0c61d6bab108'
    let secArray = Buffer.from(secString, 'hex')
    const sec = bls.secretKeyImport(secArray)

    secArray = bls.secretKeyExport(sec)
    t.equals(Buffer.from(secArray).toString('hex'), secString)

    bls.getPublicKey(pub, sec)
    const pubArray = bls.publicKeyExport(pub)

    secArray = bls.secretKeyExport(sec)

    const msg = 'hello world'
    bls.sign(sig, sec, msg)

    const sigArray = bls.signatureExport(sig)

    bls.free(sec)
    bls.free(sig)
    bls.free(pub)

    // recover
    sig = bls.signatureImport(sigArray)
    pub = bls.publicKeyImport(pubArray)

    const v = bls.verify(sig, pub, msg)
    t.equals(v, true)

    bls.free(sec)
    bls.free(sig)
    bls.free(pub)

    t.end()
  })

  tape('bad import', t => {
    bls.init()
    t.plan(1)
    try {
      bls.secretKeyImport(new Uint8Array([1, 2, 3]))
    } catch (e) {
      t.pass(true)
    }
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

      const pubArray1 = bls.publicKeyExport(pk)
      const pubArray2 = bls.publicKeyExport(pk2)
      bls.free(pk2)
      t.equals(Buffer.from(pubArray2).toString('hex'), Buffer.from(pubArray1).toString('hex'), 'public keys should be equals')

      const sig = bls.signature()
      bls.sign(sig, sk, msg)

      sigs.push(sig)
      const r = bls.verify(sig, pk, msg)

      t.equals(r, true, 'should verify')
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

    const secArray = bls.secretKeyExport(sk)
    const masterSk = bls.secretKeyExport(masterSecretKey[0])

    t.equals(Buffer.from(secArray).toString('hex'), Buffer.from(masterSk).toString('hex'), 'should recover master SK')

    const publicKey = bls.publicKeyExport(pk)
    const masterPk = bls.publicKeyExport(masterPublicKey[0])

    t.equals(Buffer.from(publicKey).toString('hex'), Buffer.from(masterPk).toString('hex'), 'should recover master PK')

    const signature = bls.signatureExport(sig)
    const sMasterSig = bls.signatureExport(masterSig)
    t.equals(Buffer.from(signature).toString('hex'), Buffer.from(sMasterSig).toString('hex'), 'signature should be the same as master')

    bls.free(sig)
    bls.free(pk)
    bls.free(sk)

    bls.freeArray(ids)
    bls.freeArray(secretKeys)
    bls.freeArray(publicKeys)
    bls.freeArray(sigs)

    t.end()
  })

  tape('int ids', t => {
    bls.init()
    t.plan(3)
    const sec = bls.idImport(7)
    const sec2 = bls.idImport(Buffer.from([7]))

    const secKey = bls.secretKeyExport(sec)
    const secKey2 = bls.secretKeyExport(sec2)
    const expected = new Uint8Array(32)
    expected[0] = 7
    t.deepEqual(secKey, expected)
    t.notEqual(secKey2, expected)

    try {
      bls.idSetInt(sec, 0)
    } catch (e) {
      t.pass('shouldnt accept 0 as an id')
    }
    t.end()
  })
})
