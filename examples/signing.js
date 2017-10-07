const bls = require('../')

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
  console.log(v)

  bls.free(sec)
  bls.free(sig)
  bls.free(pub)
})
