const bls = require('../')

bls.onModuleInit(() => {
  bls.init()

  const sec = bls.secretKey()
  const pub = bls.publicKey()
  const sig = bls.signature()

  bls.secretKeySetByCSPRNG(sec)
  bls.getPublicKey(pub, sec)

  const start = new Date()
  const msg = Buffer.from('hello world')
  bls.sign(sig, sec, msg)

  const v = bls.verify(sig, pub, msg)

  const end = new Date()
  const time = end.getTime() - start.getTime()
  console.log('finished in', time, 'ms')
  console.log(v)

  bls.free(sec)
  bls.free(sig)
  bls.free(pub)
})
