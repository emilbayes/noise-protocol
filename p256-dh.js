const crypto = require('crypto')
const sodium = require('sodium-universal')
const assert = require('nanoassert')

// prime used in 'prime256v1'
const prime = Buffer.from(
  'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
  'hex'
)
const DHLEN = 32
const PKLEN = 33 // first byte is parity byte
const SKLEN = 32
const ALG = 'p256'
const SEEDLEN = 32

module.exports = () => ({
  DHLEN,
  PKLEN,
  SKLEN,
  SEEDLEN,
  ALG,
  generateKeypair,
  generateSeedKeypair,
  dh
})

function generateKeypair (pk, sk) {
  assert(pk.byteLength === PKLEN)
  assert(sk.byteLength === SKLEN)

  const ecdh = crypto.createECDH('prime256v1')

  while (true) {
    const pair = ecdh.generateKeys()
    const p = Buffer.from(prime)
    sodium.sodium_sub(p, pair.subarray(33))
    const res = sodium.sodium_compare(pair.subarray(33), p)
    if (res > 0) break
  }

  pk.fill(ecdh.getPublicKey(null, 'compressed'))
  sk.fill(ecdh.getPrivateKey())
}

function generateSeedKeypair (pk, sk, seed) {
  assert(pk.byteLength === PKLEN)
  assert(sk.byteLength === SKLEN)
  assert(seed.byteLength === SKLEN)

  const ecdh = crypto.createECDH('prime256v1')
  const seedHash = crypto.createHash('sha512-256').update(seed).digest()
  ecdh.setPrivateKey(seedHash)

  pk.fill(ecdh.getPublicKey(null, 'compressed'))
  sk.fill(ecdh.getPrivateKey())
}

function dh (output, lsk, pk) {
  const ecdh = crypto.createECDH('prime256v1')
  ecdh.setPrivateKey(lsk)
  output.fill(ecdh.computeSecret(pk))
}
