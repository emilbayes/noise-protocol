var sodium = require('sodium-native')
var assert = require('nanoassert')
var symmetricState = require('./symmetric-state')
var cipherState = require('./cipher-state')
var dh = require('./dh')

var PKLEN = dh.PKLEN
var SKLEN = dh.SKLEN

module.exports = {
  initialize,
  writeMessage,
  readMessage,
  SKLEN,
  PKLEN
}

function HandshakeState () {
  this.symmetricState = sodium.sodium_malloc(symmetricState.STATELEN)

  this.initiator = null

  this.spk = null
  this.ssk = null

  this.epk = null
  this.esk = null

  this.rs = null
  this.re = null

  this.messagePatterns = null
}

var PATTERNS = Object.freeze({
  NN: {
    premessages: {
      initiator: [],
      responder: []
    },
    messagePatterns: [
      [true, 'e'],
      [false, 'e', 'ee']
    ]
  },
  XX: {
    premessages: {
      initiator: [],
      responder: []
    },
    messagePatterns: [
      [true, 'e'],
      [false, 'e', 'ee', 's', 'es'],
      [true, 's', 'se']
    ]
  },
  KK: {
    premessages: {
      initiator: ['s'],
      responder: ['s']
    },
    messagePatterns: [
      [true, 'e', 'es', 'ss'],
      [false, 'e', 'ee', 'se']
    ]
  }
})

function initialize (handshakePattern, initiator, prologue, s, e, rs, re) {
  assert(Object.keys(PATTERNS).includes(handshakePattern))
  assert(typeof initiator === 'boolean')
  assert(prologue.byteLength != null)

  assert(s == null ? true : s.publicKey.byteLength === dh.PKLEN)
  assert(s == null ? true : s.secretKey.byteLength === dh.SKLEN)

  assert(e == null ? true : e.publicKey.byteLength === dh.PKLEN)
  assert(e == null ? true : e.secretKey.byteLength === dh.SKLEN)

  assert(rs == null ? true : rs.byteLength === dh.PKLEN)
  assert(re == null ? true : re.byteLength === dh.PKLEN)

  var state = new HandshakeState()

  var protocolName = Buffer.from(`Noise_${handshakePattern}_25519_XChaChaPoly_BLAKE2b`)

  symmetricState.initializeSymmetric(state.symmetricState, protocolName)
  symmetricState.mixHash(state.symmetricState, prologue)

  state.initiator = initiator

  if (s != null) {
    state.spk = s.publicKey
    state.ssk = s.secretKey
  }

  if (e != null) {
    state.epk = e.publicKey
    state.esk = e.secretKey
  }

  if (rs != null) state.rs = rs
  if (re != null) state.re = re

  // hashing
  var pat = PATTERNS[handshakePattern]

  for (var initiatorToken of pat.premessages.initiator) {
    switch (initiatorToken) {
      case 'e':
        assert(state.initiator ? state.epk.byteLength != null : state.re.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initiator ? state.epk : state.re)
        break
      case 's':
        assert(state.initiator ? state.spk.byteLength != null : state.rs.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initiator ? state.spk : state.rs)
        break
      default:
        throw new Error('Invalid premessage pattern for initiator')
    }
  }

  for (var responderToken of pat.premessages.responder) {
    switch (responderToken) {
      case 'e':
        assert(state.initiator ? state.re.byteLength != null : state.epk.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initiator ? state.re : state.epk)
        break
      case 's':
        assert(state.initiator ? state.rs.byteLength != null : state.spk.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initiator ? state.rs : state.spk)
        break
      default:
        throw new Error('Invalid premessage pattern for responder')
    }
  }

  state.messagePatterns = clone(pat.messagePatterns)

  return state
}

var DhResult = sodium.sodium_malloc(dh.DHLEN)
function writeMessage (state, payload, messageBuffer) {
  assert(state instanceof HandshakeState)
  assert(payload.byteLength != null)
  assert(messageBuffer.byteLength != null)

  var mpat = state.messagePatterns.shift()
  var moffset = 0

  assert(mpat.shift() === state.initiator)

  for (var token of mpat) {
    switch (token) {
      case 'e':
        assert(state.epk == null)
        assert(state.esk == null)

        state.epk = sodium.sodium_malloc(dh.PKLEN)
        state.esk = sodium.sodium_malloc(dh.SKLEN)

        dh.generateKeypair(state.epk, state.esk)

        messageBuffer.set(state.epk, moffset)
        moffset += state.epk.byteLength

        symmetricState.mixHash(state.symmetricState, state.epk)

        break

      case 's':
        assert(state.spk.byteLength === dh.PKLEN)

        symmetricState.encryptAndHash(state.symmetricState, messageBuffer.subarray(moffset), state.spk)
        moffset += symmetricState.encryptAndHash.bytes

        break

      case 'ee':
        dh[state.initiator ? 'initiator' : 'responder'](DhResult, state.epk, state.esk, state.re)
        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break
      case 'es':
        if (state.initiator) dh.initiator(DhResult, state.epk, state.esk, state.rs)
        else dh.responder(DhResult, state.spk, state.ssk, state.re)

        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break
      case 'se':
        if (state.initiator) dh.initiator(DhResult, state.spk, state.ssk, state.re)
        else dh.responder(DhResult, state.epk, state.esk, state.rs)

        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break
      case 'ss':
        dh[state.initiator ? 'initiator' : 'responder'](DhResult, state.spk, state.ssk, state.rs)

        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break

      default:
        throw new Error('Invalid message pattern')
    }
  }

  symmetricState.encryptAndHash(state.symmetricState, messageBuffer.subarray(moffset), payload)
  moffset += symmetricState.encryptAndHash.bytes

  writeMessage.bytes = moffset

  if (state.messagePatterns.length === 0) {
    var tx = sodium.sodium_malloc(cipherState.STATELEN)
    var rx = sodium.sodium_malloc(cipherState.STATELEN)
    symmetricState.split(state.symmetricState, tx, rx)

    return {tx, rx}
  }
}
writeMessage.bytes = 0

function readMessage (state, message, payloadBuffer) {
  assert(state instanceof HandshakeState)
  assert(message.byteLength != null)
  assert(payloadBuffer.byteLength != null)

  var mpat = state.messagePatterns.shift()
  var moffset = 0

  assert(mpat.shift() === !state.initiator)

  for (var token of mpat) {
    switch (token) {
      case 'e':
        assert(state.re == null)
        assert(message.byteLength - moffset >= dh.PKLEN)

        // PKLEN instead of DHLEN since they are different in out case
        state.re = sodium.sodium_malloc(dh.PKLEN)
        state.re.set(message.subarray(moffset, moffset + dh.PKLEN))
        moffset += dh.PKLEN

        symmetricState.mixHash(state.symmetricState, state.re)

        break

      case 's':
        assert(state.rs.byteLength == null)
        state.rs = sodium.sodium_malloc(dh.PKLEN)

        var bytes = 0
        if (symmetricState.hasKey(state.symmetricState)) {
          bytes = dh.PKLEN + 16
        } else {
          bytes = dh.PKLEN
        }

        assert(message.byteLength - moffset >= bytes)

        symmetricState.decryptAndHash(
          state.symmetricState,
          state.rs,
          message.subarray(moffset, moffset + bytes) // <- called temp in noise spec
        )

        moffset += symmetricState.decryptAndHash.bytes

        break
      case 'ee':
        dh[state.initiator ? 'initiator' : 'responder'](DhResult, state.epk, state.esk, state.re)
        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break
      case 'es':
        if (state.initiator) dh.initiator(DhResult, state.epk, state.esk, state.rs)
        else dh.responder(DhResult, state.spk, state.ssk, state.re)

        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break
      case 'se':
        if (state.initiator) dh.initiator(DhResult, state.spk, state.ssk, state.re)
        else dh.responder(DhResult, state.epk, state.esk, state.rs)

        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break
      case 'ss':
        dh[state.initiator ? 'initiator' : 'responder'](DhResult, state.spk, state.ssk, state.rs)

        symmetricState.mixKey(state.symmetricState, DhResult)
        sodium.sodium_memzero(DhResult)
        break

      default:
        throw new Error('Invalid message pattern')
    }
  }

  symmetricState.decryptAndHash(state.symmetricState, payloadBuffer, message.subarray(moffset))
  moffset += symmetricState.encryptAndHash.bytes

  readMessage.bytes = moffset

  if (state.messagePatterns.length === 0) {
    var tx = sodium.sodium_malloc(cipherState.STATELEN)
    var rx = sodium.sodium_malloc(cipherState.STATELEN)
    symmetricState.split(state.symmetricState, tx, rx)

    return {tx, rx}
  }
}
readMessage.bytes = 0

function clone (o) { // Good enough for now
  return JSON.parse(JSON.stringify(o))
}
