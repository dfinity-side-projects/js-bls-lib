const bls = require('../')

bls.onModuleInit(() => {
  bls.init()

  const sk1 = bls.secretKey()
  const sk2 = bls.secretKey()

  const pk1 = bls.publicKey()
  const pk2 = bls.publicKey()

  bls.getPublicKey(pk1, sk1)
  bls.getPublicKey(pk2, sk2)

  bls.publicKeyAdd(pk1, pk2)

  bls.secretKeyAdd(sk1, sk2)

  const pk3 = bls.publicKey()
  bls.getPublicKey(pk3, sk1)

  const r = bls.publicKeyIsEqual(pk3, pk1)
  console.log(r)

  bls.freeArray([sk1, sk2, pk1, pk2, pk3])
})
