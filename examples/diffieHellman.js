const bls = require('../')

// Diffie–Hellman key exchange
bls.onModuleInit(() => {
  bls.init()

  const sk1 = bls.secretKey()
  const sk2 = bls.secretKey()

  const pk1 = bls.publicKey()
  const pk2 = bls.publicKey()

  bls.getPublicKey(pk1, sk1)
  bls.getPublicKey(pk2, sk2)

  const sharedSec1 = bls.publicKey()
  const sharedSec2 = bls.publicKey()

  bls.dhKeyExchange(sharedSec1, sk1, pk2)
  bls.dhKeyExchange(sharedSec2, sk2, pk1)

  const r = bls.publicKeyIsEqual(sharedSec1, sharedSec2)
  console.log(r)

  bls.freeArray([sk1, sk2, pk1, pk2, sharedSec2, sharedSec1])
})
