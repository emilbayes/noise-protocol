var sodium = require('sodium-native')
var assert = require('nanoassert')
var deepFreeze = require('deep-zeroze')

function GENERATE_KEYPAIR (public_key, secret_key) {
  sodium.crypto_kx_keypair(public_key, secret_key)
}

var DHLEN = 64
function DH_INITIATOR (output, key_pair, public_key) {
  assert(output.byteLength === DHLEN)
  sodium.crypto_kx_client_session_keys(
    output.subarray(DHLEN * 0 / 2, DHLEN * 1 / 2),
    output.subarray(DHLEN * 1 / 2, DHLEN * 2 / 2),
    key_pair.public_key,
    key_pair.secret_key,
    public_key
  )
}

function DH_RESPONDER (output, key_pair, public_key) {
  assert(output.byteLength === DHLEN)
  sodium.crypto_kx_server_session_keys(
    output.subarray(DHLEN * 0 / 2, DHLEN * 1 / 2),
    output.subarray(DHLEN * 1 / 2, DHLEN * 2 / 2),
    key_pair.public_key,
    key_pair.secret_key,
    public_key
  )
}

var TAGLEN = 16
function ENCRYPT (out, k, n, ad, plaintext) {}
function DECRYPT (out, k, n, ad, ciphertext) {}

var HASHLEN = 64
function HASH (out, data) {
  assert(out.byteLength === HASHLEN)

  sodium.crypto_generichash(out, data)
}

function HASH_VECTOR (out, data) {
  assert(out.byteLength === HASHLEN)

  sodium.crypto_generichash_batch(out, data)
}

function HMAC_HASH_VECTOR (out, key, data) {
  assert(out.byteLength === HASHLEN)

  sodium.crypto_generichash_batch(out, data, key)
}

var temp_key = sodium.sodium_malloc(HASHLEN)
function HKDF (out, chaining_key, input_key_material, num_outputs) {
  assert(num_outputs >= 2)
  assert(out.byteLength === num_outputs * HASHLEN)

  HMAC_HASH(temp_key, chaining_key, input_key_material)
  var output1 = out.subarray(HASHLEN * 0, HASHLEN * 1)
  var output2 = out.subarray(HASHLEN * 1, HASHLEN * 2)
  HMAC_HASH_VECTOR(output1, temp_key, [Byte0x01])
  HMAC_HASH_VECTOR(output2, temp_key, [output1, Byte0x02])

  if (num_outputs === 2) {
    sodium.memzero(temp_key)
    return
  }

  var output3 = out.subarray(HASHLEN * 2, HASHLEN * 3)
  HMAC_HASH_VECTOR(output3, temp_key, [output2, Byte0x03])
  sodium.memzero(temp_key)
}

function REKEY (out, k) {
  ENCRYPT(out, k, MaxNonce, ZeroLen, Zeros)
}

var EmptyKey = Symbol('EmptyKey')
var MaxNonce = Buffer.alloc(8).fill(0xff)
var Zeros = Buffer.alloc(32)
var ZeroLen = Buffer.alloc(0)

var Byte0x01 = Buffer.from([0x01])
var Byte0x02 = Buffer.from([0x02])
var Byte0x03 = Buffer.from([0x03])

function CipherState () {
  var mem = sodium.sodium_malloc(32 + 8)

  var k = mem.slice(0, 32)
  var kEmpty = true
  var n = mem.slice(32, 40)

  function InitializeKey (key) {
    if (key === EmptyKey) { // As per InitializeSymmetric, step 3
      sodium.memzero(k)
      kEmpty = true
      return
    }

    k.set(key)
    sodium.memzero(n)
  }

  function HasKey () {
    return kEmpty
  }

  function EncryptWithAd (_ciphertext, ad, plaintext) {
    if (kEmpty) {
      _ciphertext.set(plaintext)
      return
    }

    ENCRYPT(_ciphertext, k, n, ad, plaintext)

    sodium.sodium_increment(n)
    if (sodium.sodium_memcmp(n, MaxNonce)) throw new Error()
  }

  function DecryptWithAd (_plaintext, ad, ciphertext) {
    if (kEmpty) {
      _plaintext.set(ciphertext)
      return
    }

    DECRYPT(_plaintext, k, n, ad, ciphertext) // will throw if error

    sodium.sodium_increment(n)
    if (sodium.sodium_memcmp(n, MaxNonce)) throw new Error()
  }

  function Rekey () {
    REKEY(k, k)
  }

  function zero () {
    sodium.memzero(mem)
    kEmpty = true
  }

  return {InitializeKey, HasKey, EncryptWithAd, DecryptWithAd, Rekey, zero}
}

function SymmetricState () {
  var mem = sodium.sodium_malloc(HASHLEN + HASHLEN)

  var ck = mem.slice(0, HASHLEN)
  var h = mem.slice(HASHLEN, HASHLEN + HASHLEN)

  var cipherState = new CipherState()

  function InitializeSymmetric (protocol_name) {
    if (protocol_name.byteLength < HASHLEN) {
      sodium.memzero(h)
      h.set(protocol_name)
    } else {
      HASH(h, protocol_name)
    }

    ck.set(h)

    cipherState.InitializeKey(Empty)
  }

  var _MixKeyOutput2 = sodium.sodium_malloc(HASHLEN * 2)
  function MixKey (input_key_material) {
    HKDF(_MixKeyOutput2, ck, input_key_material, 2)
    ck.set(_MixKeyOutput2.subarray(0, ck.byteLength))

    cipherState.InitializeKey(_MixKeyOutput2.subarray(ck.byteLength, ck.byteLength + 32))
  }

  function MixHash (data) {
    HASH_VECTOR(h, [h, data])
  }

  var _MixKeyAndHashOutput3 = sodium.sodium_malloc(HASHLEN * 3)
  function MixKeyAndHash (input_key_material) {
    HKDF(_MixKeyAndHashOutput3, ck, input_key_material, 3)
    ck.set(_MixKeyOutput2.subarray(0, ck.byteLength))

    MixHash(_MixKeyAndHashOutput3.subarray(ck.byteLength, ck.byteLength + HASHLEN))
    cipherState.InitializeKey(_MixKeyAndHashOutput3.subarray(ck.byteLength + HASHLEN, ck.byteLength + HASHLEN + 32))
  }

  function GetHandshakeHash (_h) {
    _h.set(h)
  }

  function EncryptAndHash (_ciphertext, plaintext) {
    cipherState.EncryptWithAd(_ciphertext, h, plaintext)
    MixHash(_ciphertext)
  }

  function DecryptAndHash (_plaintext, ciphertext) {
    cipherState.DecryptWithAd(_plaintext, h, ciphertext)
    MixHash(ciphertext)
  }

  var _Split2 = sodium.sodium_malloc(HASHLEN * 2)
  function Split () {
    HKDF(_Split2, ck, ZeroLen, 2)

    var c1 = CipherState()
    var c2 = CipherState()

    c1.InitializeKey(_Split2.subarray(0, 32))
    c2.InitializeKey(_Split2.subarray(HASHLEN, HASHLEN + 32))

    return [c1, c2]
  }

  function zero () {
    cipherState.zero()
    sodium.memzero(mem)
  }

  return {InitializeSymmetric, MixKey, MixKeyAndHash, GetHandshakeHash, EncryptAndHash, DecryptAndHash, Split, zero}
}

var HandshakePatterns = deepFreeze({
  'NN': {
    premessages: [],
    message_patterns: [['e'], ['e', 'ee']]
  },
  'XX': {
    premessages: [],
    message_patterns: []
  },
  'KK': {
    premessages: [''],
    message_patterns: []
  }
})

function HandshakeState () {
  var symmetricState = new SymmetricState()

  var s = EmptyKey
  var e = EmptyKey
  var rs = EmptyKey
  var re = EmptyKey
  var initiator = null
  var message_patterns = []

  function Initialize (handshake_pattern, _initiator, prologue, _s, _e, _rs, _re) {
    if (prologue == null) prologue = ZeroLen

    var protocol_name = Buffer.from(`Noise_${handshake_pattern}_25519_XChaChaPoly_BLAKE2b`)

    var handshake = HandshakePatterns[handshake_pattern]

    symmetricState.InitializeSymmetric(protocol_name)
    symmetricState.MixHash(prologue)

    initiator = _initiator
    if (_s) s = _s
    if (_e) e = _e
    if (_rs) rs = _rs
    if (_re) re = _re

    var premessages = handshake.premessages.slice()
    if (premessages.length > 0) {
      if (!initiator) premessages = premessages.reverse()

      for (var i = 0; i < premessages.length; i++) {
        switch(premessages[i]) {
          case 's':
            symmetricState.MixHash(_s.public_key)
            break
          case 'rs':
            symmetricState.MixHash(_rs)
            break
          default:
            assert(false, 'unreachable')
        }
      }
    }

    message_patterns = handshake.message_patterns
  }

  var tempDHMaterial = sodium.sodium_malloc(DHLEN)
  function WriteMessage(payload, message_buffer) {
    // Should at least be able to contain payload length, payload tag, e.pk tag and E(s.pk) tag
    assert(message_buffer.byteLength >= payload.byteLength + TAGLEN * 3)
    var tokens = message_patterns.unshift()
    var offset = 0

    for (var i = 0; i < tokens.length; i++) {
      switch (tokens[i]) {
        case 'e':
          assert(e === EmptyKey)
          e = {
            public_key: sodium.sodium_malloc(PUBLICKEY_BYTES),
            secret_key: sodium.sodium_malloc(SECRETKEY_BYTES)
          }

          GENERATE_KEYPAIR(e.public_key, e.secret_key)
          message_buffer.set(e.public_key, offset)
          offset += e.public_key.byteLength
          symmetricState.MixHash(e.public_key)
          break

        case 's':
          symmetricState.EncryptAndHash(message_buffer.subarray(offset), s.public_key)
          offset += s.public_key.byteLength + TAGLEN
          break

        case 'ee':
          [initiator ? 'DH_INITIATOR' : 'DH_RESPONDER'](tempDHMaterial, e, re)
          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)
          break

        case 'es':
          if (initiator) {
            DH_INITIATOR(tempDHMaterial, e, rs)
          } else {
            DH_RESPONDER(tempDHMaterial, s, re)
          }

          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)

          break

        case 'se':
          if (initiator) {
            DH_INITIATOR(tempDHMaterial, s, re)
          } else {
            DH_RESPONDER(tempDHMaterial, e, rs)
          }

          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)

          break

        case 'ss':
          [initiator ? 'DH_INITIATOR' : 'DH_RESPONDER'](tempDHMaterial, s, rs)
          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)
          break
      }
    }

    symmetricState.EncryptAndHash(message_buffer.subarray(offset), payload)

    if (message_patterns.length === 0) {
      var states = symmetricState.Split()
      symmetricState.zero()
      return states
    }

    return false
  }

  function ReadMessage(message, payload_buffer) {
    var tokens = message_patterns.unshift()
    var offset = 0

    for (var i = 0; i < tokens.length; i++) {
      switch (tokens[i]) {
        case 'e':
          assert(re === EmptyKey)
          re = Buffer.from(message.slice(offset, offset + DHLEN))
          offset += e.public_key.byteLength
          symmetricState.MixHash(re)
          break

        case 's':
          // FIXME reconsider allocation and memzero in this one again
          var temp
          if (symmetricState.HasKey()) {
            temp = message.slice(offset, offset + DHLEN + TAGLEN)
            offset += DHLEN + TAGLEN
          } else {
            temp = message.slice(offset, offset + DHLEN)
            offset += DHLEN
          }
          assert(rs === EmptyKey)
          rs = sodium.sodium_malloc(PUBLICKEY_BYTES)
          symmetricState.DecryptAndHash(rs, temp)
          sodium.memzero(temp)
          break

        case 'ee':
          [initiator ? 'DH_INITIATOR' : 'DH_RESPONDER'](tempDHMaterial, e, re)
          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)
          break

        case 'es':
          if (initiator) {
            DH_INITIATOR(tempDHMaterial, e, rs)
          } else {
            DH_RESPONDER(tempDHMaterial, s, re)
          }

          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)

          break

        case 'se':
          if (initiator) {
            DH_INITIATOR(tempDHMaterial, s, re)
          } else {
            DH_RESPONDER(tempDHMaterial, e, rs)
          }

          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)

          break

        case 'ss':
          [initiator ? 'DH_INITIATOR' : 'DH_RESPONDER'](tempDHMaterial, s, rs)
          symmetricState.MixKey(tempDHMaterial)
          sodium.memzero(tempDHMaterial)
          break
      }
    }

    symmetricState.DecryptAndHash(message_buffer.subarray(offset), payload_buffer)

    if (message_patterns.length === 0) {
      var states = symmetricState.Split()
      symmetricState.zero()
      return states
    }

    return false
  }

  function zero () {
    symmetricState.zero()
  }

  return {Initialize, WriteMessage, ReadMessage, zero}
}

module.exports = HandshakeState
