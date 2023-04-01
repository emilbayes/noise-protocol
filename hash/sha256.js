/* eslint-disable camelcase */
const { sodium_malloc, sodium_memzero } = require('sodium-universal/memory')
const { crypto_generichash_batch } = require('sodium-universal/crypto_generichash')

const assert = require('nanoassert')
const hmacSHA256 = require('crypto-js/hmac-sha256')

const HASHLEN = 32
const BLOCKLEN = 64
const ALG = 'SHA256'

const TempKey = sodium_malloc(HASHLEN)
const Byte0x01 = new Uint8Array([0x01])
const Byte0x02 = new Uint8Array([0x02])
const Byte0x03 = new Uint8Array([0x03])

module.exports = ({ dh }) => {
  return {
    HASHLEN,
    BLOCKLEN,
    ALG,
    hash,
    hkdf
  }

  function hkdf (out1, out2, out3, chainingKey, inputKeyMaterial) {
    assert(out1.byteLength === HASHLEN)
    assert(out2.byteLength === HASHLEN)
    assert(out3 == null ? true : out3.byteLength === HASHLEN)
    assert(chainingKey.byteLength === HASHLEN)

    sodium_memzero(TempKey)
    hmac(TempKey, chainingKey, [inputKeyMaterial])
    hmac(out1, TempKey, [Byte0x01])
    hmac(out2, TempKey, [out1, Byte0x02])

    if (out3 != null) {
      hmac(out3, TempKey, [out2, Byte0x03])
    }

    sodium_memzero(TempKey)
  }
}

function hash (out, data) {
  assert(out.byteLength === HASHLEN)
  assert(Array.isArray(data))

  crypto_generichash_batch(out, data)
}

function hmac (out, key, data) {
  const res = hmacSHA256(data.toString(), key.toString())
  out.set(Buffer.from(res.toString(), 'hex'))
}
