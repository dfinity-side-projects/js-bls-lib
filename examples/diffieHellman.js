const bls = require('../')

bls.onModuleInit(() => {
  bls.init()

  const sk1 = bls.secretKey()
  const sk2 = bls.secretKey()

  const pk1 = bls.publicKey()
  const pk2 = bls.publicKey()

  bls.getPublicKey(pk1, sk1)
  bls.getPublicKey(pk2, sk2)

  const out1 = bls.publicKey()
  const out2 = bls.publicKey()

  bls.dhKeyExchange(out1, sk1, pk2)
  bls.dhKeyExchange(out2, sk2, pk1)

  const r = bls.publicKeyIsEqual(out1, out2)
  console.log(r)
})
