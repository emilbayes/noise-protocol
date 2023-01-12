/* eslint-disable camelcase */
const { sodium_malloc, sodium_memzero } = require('sodium-universal/memory')
const assert = require('nanoassert')

module.exports = ({ hash, cipherState }) => {
  const STATELEN = hash.HASHLEN + hash.HASHLEN + cipherState.STATELEN
  const HASHLEN = hash.HASHLEN

  const CHAINING_KEY_BEGIN = 0
  const CHAINING_KEY_END = hash.HASHLEN
  const HASH_BEGIN = CHAINING_KEY_END
  const HASH_END = HASH_BEGIN + hash.HASHLEN
  const CIPHER_BEGIN = HASH_END
  const CIPHER_END = CIPHER_BEGIN + cipherState.STATELEN

  function initializeSymmetric (state, protocolName) {
    assert(state.byteLength === STATELEN)
    assert(protocolName.byteLength != null)

    sodium_memzero(state)
    if (protocolName.byteLength <= HASHLEN) state.set(protocolName, HASH_BEGIN)
    else hash.hash(state.subarray(HASH_BEGIN, HASH_END), [protocolName])

    state.subarray(CHAINING_KEY_BEGIN, CHAINING_KEY_END).set(state.subarray(HASH_BEGIN, HASH_END))

    cipherState.initializeKey(state.subarray(CIPHER_BEGIN, CIPHER_END), null)
  }

  const TempKey = sodium_malloc(HASHLEN)
  function mixKey (state, inputKeyMaterial, dhlen, pklen) {
    assert(state.byteLength === STATELEN)
    assert(inputKeyMaterial.byteLength != null)

    hash.hkdf(
      state.subarray(CHAINING_KEY_BEGIN, CHAINING_KEY_END),
      TempKey,
      null,
      state.subarray(CHAINING_KEY_BEGIN, CHAINING_KEY_END),
      inputKeyMaterial,
      dhlen,
      pklen
    )

    // HASHLEN is always 64 here, so we truncate to 32 bytes per the spec
    cipherState.initializeKey(state.subarray(CIPHER_BEGIN, CIPHER_END), TempKey.subarray(0, 32))
    sodium_memzero(TempKey)
  }

  function mixHash (state, data) {
    assert(state.byteLength === STATELEN)

    const h = state.subarray(HASH_BEGIN, HASH_END)

    hash.hash(h, [h, data])
  }

  const TempHash = sodium_malloc(HASHLEN)
  function mixKeyAndHash (state, inputKeyMaterial, dhlen, pklen) {
    assert(state.byteLength === STATELEN)
    assert(inputKeyMaterial.byteLength != null)

    hash.hkdf(
      state.subarray(CHAINING_KEY_BEGIN, CHAINING_KEY_END),
      TempHash,
      TempKey,
      state.subarray(CHAINING_KEY_BEGIN, CHAINING_KEY_END),
      inputKeyMaterial,
      dhlen,
      pklen
    )

    mixHash(state, TempHash)
    sodium_memzero(TempHash)

    // HASHLEN is always 64 here, so we truncate to 32 bytes per the spec
    cipherState.initializeKey(state.subarray(CIPHER_BEGIN, CIPHER_END), TempKey.subarray(0, 32))
    sodium_memzero(TempKey)
  }

  function getHandshakeHash (state, out) {
    assert(state.byteLength === STATELEN)
    assert(out.byteLength === HASHLEN)

    out.set(state.subarray(HASH_BEGIN, HASH_END))
  }

  // ciphertext is the output here
  function encryptAndHash (state, ciphertext, plaintext) {
    assert(state.byteLength === STATELEN)
    assert(ciphertext.byteLength != null)
    assert(plaintext.byteLength != null)

    const cstate = state.subarray(CIPHER_BEGIN, CIPHER_END)
    const h = state.subarray(HASH_BEGIN, HASH_END)

    cipherState.encryptWithAd(cstate, ciphertext, h, plaintext)
    encryptAndHash.bytesRead = cipherState.encryptWithAd.bytesRead
    encryptAndHash.bytesWritten = cipherState.encryptWithAd.bytesWritten
    mixHash(state, ciphertext.subarray(0, encryptAndHash.bytesWritten))
  }
  encryptAndHash.bytesRead = 0
  encryptAndHash.bytesWritten = 0

  // plaintext is the output here
  function decryptAndHash (state, plaintext, ciphertext) {
    assert(state.byteLength === STATELEN)
    assert(plaintext.byteLength != null)
    assert(ciphertext.byteLength != null)

    const cstate = state.subarray(CIPHER_BEGIN, CIPHER_END)
    const h = state.subarray(HASH_BEGIN, HASH_END)

    cipherState.decryptWithAd(cstate, plaintext, h, ciphertext)
    decryptAndHash.bytesRead = cipherState.decryptWithAd.bytesRead
    decryptAndHash.bytesWritten = cipherState.decryptWithAd.bytesWritten
    mixHash(state, ciphertext.subarray(0, decryptAndHash.bytesRead))
  }
  decryptAndHash.bytesRead = 0
  decryptAndHash.bytesWritten = 0

  const TempKey1 = sodium_malloc(HASHLEN)
  const TempKey2 = sodium_malloc(HASHLEN)
  const zerolen = new Uint8Array(0)
  function split (state, cipherstate1, cipherstate2, dhlen, pklen) {
    assert(state.byteLength === STATELEN)
    assert(cipherstate1.byteLength === cipherState.STATELEN)
    assert(cipherstate2.byteLength === cipherState.STATELEN)

    hash.hkdf(
      TempKey1,
      TempKey2,
      null,
      state.subarray(CHAINING_KEY_BEGIN, CHAINING_KEY_END),
      zerolen,
      dhlen,
      pklen
    )

    // HASHLEN is always 64 here, so we truncate to 32 bytes per the spec
    cipherState.initializeKey(cipherstate1, TempKey1.subarray(0, 32))
    cipherState.initializeKey(cipherstate2, TempKey2.subarray(0, 32))
    sodium_memzero(TempKey1)
    sodium_memzero(TempKey2)
  }

  function _hasKey (state) {
    return cipherState.hasKey(state.subarray(CIPHER_BEGIN, CIPHER_END))
  }

  return {
    STATELEN,
    initializeSymmetric,
    mixKey,
    mixHash,
    mixKeyAndHash,
    getHandshakeHash,
    encryptAndHash,
    decryptAndHash,
    split,
    _hasKey
  }
}
