var sodium = require('sodium-native')
var assert = require('nanoassert')
var cipher = require('./cipher')

var STATELEN = cipher.KEYLEN + cipher.NONCELEN
var NONCELEN = cipher.NONCELEN

module.exports = {
  STATELEN,
  NONCELEN,
  initializeKey,
  hasKey,
  setNonce,
  encryptWithAd,
  decryptWithAd,
  rekey
}

var KEY_BEGIN = 0
var KEY_END = cipher.KEYLEN
var NONCE_BEGIN = KEY_END
var NONCE_END = NONCE_BEGIN + cipher.NONCELEN

function initializeKey (state, key) {
  assert(state.byteLength === STATELEN)
  assert(key == null ? true : key.byteLength === cipher.KEYLEN)

  if (key == null) {
    sodium.sodium_memzero(state.subarray(KEY_BEGIN, KEY_END))
    return
  }

  state.set(key)
  sodium.sodium_memzero(state.subarray(NONCE_BEGIN, NONCE_END))
}

function hasKey (state) {
  assert(state.byteLength === STATELEN)
  return sodium.sodium_is_zero(state.subarray(KEY_BEGIN, KEY_END))
}

function setNonce (state, nonce) {
  assert(state.byteLength === STATELEN)
  assert(nonce.byteLength === NONCELEN)

  state.set(nonce, NONCE_BEGIN)
}

var maxnonce = Buffer.alloc(8, 0xff)
function encryptWithAd (state, out, ad, plaintext) {
  assert(state.byteLength === STATELEN)

  var n = state.subarray(NONCE_BEGIN, NONCE_END)
  if (sodium.sodium_memcmp(n, maxnonce)) throw new Error('Nonce overflow')

  if (hasKey(state) === false) {
    out.set(plaintext)
    return
  }

  cipher.encrypt(
    out,
    state.subarray(KEY_BEGIN, KEY_END),
    n,
    ad,
    plaintext
  )

  sodium.sodium_increment(n)
  if (sodium.sodium_memcmp(n, maxnonce)) throw new Error()
}

function decryptWithAd (state, out, ad, ciphertext) {
  assert(state.byteLength === STATELEN)

  var n = state.subarray(NONCE_BEGIN, NONCE_END)
  if (sodium.sodium_memcmp(n, maxnonce)) throw new Error('Nonce overflow')

  if (hasKey(state) === false) {
    out.set(ciphertext)
    return
  }

  cipher.decrypt(
    out,
    state.subarray(KEY_BEGIN, KEY_END),
    n,
    ad,
    ciphertext
  )

  sodium.sodium_increment(n)
}

function rekey (state) {
  assert(state.byteLength === STATELEN)

  var k = state.subarray(KEY_BEGIN, KEY_END)
  cipher.rekey(k, k)
}
