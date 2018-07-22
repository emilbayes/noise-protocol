var sodium = require('sodium-native')
var assert = require('nanoassert')

var KEYLEN = 32
var NONCELEN = 8
var TAGLEN = 16

module.exports = {
  KEYLEN,
  NONCELEN,
  TAGLEN,
  encrypt,
  decrypt,
  rekey
}

var ElongatedNonce = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
sodium.sodium_memzero(ElongatedNonce)
function encrypt (out, k, n, ad, plaintext) {
  assert(out.byteLength === plaintext.byteLength + TAGLEN)
  assert(k.byteLength === KEYLEN)
  assert(n.byteLength === NONCELEN)
  assert(ad == null ? true : Buffer.isBuffer(ad))
  sodium.sodium_memzero(ElongatedNonce)

  ElongatedNonce.set(n, 16)
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(out, plaintext, ad, null, ElongatedNonce, k)
  sodium.sodium_memzero(ElongatedNonce)
}

function decrypt (out, k, n, ad, ciphertext) {
  assert(out.byteLength === ciphertext.byteLength - TAGLEN)
  assert(k.byteLength === KEYLEN)
  assert(n.byteLength === NONCELEN)
  assert(ad == null ? true : Buffer.isBuffer(ad))
  sodium.sodium_memzero(ElongatedNonce)

  ElongatedNonce.set(n, 16)
  sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(out, null, ciphertext, ad, ElongatedNonce, k)
  sodium.sodium_memzero(ElongatedNonce)
}

var maxnonce = Buffer.alloc(8, 0xff)
var zerolen = Buffer.alloc(0)
var zeros = Buffer.alloc(32, 0)

var IntermediateKey = sodium.sodium_malloc(KEYLEN + TAGLEN)
sodium.sodium_memzero(IntermediateKey)
function rekey (out, k) {
  assert(out.byteLength === KEYLEN)
  assert(k.byteLength === KEYLEN)
  sodium.sodium_memzero(IntermediateKey)

  IntermediateKey.set(k)
  encrypt(IntermediateKey, k, maxnonce, zerolen, zeros)
  out.set(IntermediateKey.subarray(0, KEYLEN))
  sodium.sodium_memzero(IntermediateKey)
}
