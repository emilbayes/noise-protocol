var sodium = require('sodium-native')
var assert = require('nanoassert')
var symmetricState = require('./symmetric-state')
var dh = require('./dh')

module.exports = {
  initialize,
  writeMessage,
  readMessage
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
    messagePatterns: {
      initiator: [
        ['e']
      ],
      responder: [
        ['e', 'ee']
      ]
    }
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

  var protocolName = Buffer.from(`Noise_${handshakePattern}_25519_ChaChaPoly_BLAKE2b`)

  symmetricState.InitializeSymmetric(state.symmetricState, protocolName)
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
        assert(state.initator ? state.epk.byteLength != null : state.re.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.epk : state.re)
        break
      case 's':
        assert(state.initator ? state.spk.byteLength != null : state.rs.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.spk : state.rs)
        break
      case 'e, s':
        assert(state.initator ? state.epk.byteLength != null : state.re.byteLength != null)
        assert(state.initator ? state.spk.byteLength != null : state.rs.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.epk : state.re)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.spk : state.rs)
        break
      default:
        throw new Error('Invalid premessage pattern for initator')
    }
  }

  for (var responderToken of pat.premessages.responder) {
    switch (responderToken) {
      case 'e':
        assert(state.initator ? state.re.byteLength != null : state.epk.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.re : state.epk)
        break
      case 's':
        assert(state.initator ? state.rs.byteLength != null : state.spk.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.rs : state.spk)
        break
      case 'e, s':
        assert(state.initator ? state.re.byteLength != null : state.epk.byteLength != null)
        assert(state.initator ? state.rs.byteLength != null : state.spk.byteLength != null)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.re : state.epk)
        symmetricState.mixHash(state.symmetricState, state.initator ? state.rs : state.spk)
        break
      default:
        throw new Error('Invalid premessage pattern for responder')
    }
  }

  state.messagePatterns = clone(pat[state.initator ? 'initator' : 'responder'].messagePatterns)

  return state
}

function writeMessage (state, payload, messageBuffer) {
  assert(state instanceof HandshakeState)
  assert(payload.byteLength != null)
  assert(messageBuffer.byteLength != null)

  var mpat = state.messagePatterns.unshift()
  var moffset = 0

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
      case 'es':
      case 'se':
      case 'ss':
        throw new Error('todo')

      default:
        throw new Error('Invalid message pattern')
    }
  }

  symmetricState.encryptAndHash(state.symmetricState, messageBuffer.subarray(moffset), payload)
  moffset += symmetricState.encryptAndHash.bytes

  writeMessage.bytes = moffset

  if (state.messagePatterns === 0) {
    var tx = sodium.sodium_malloc(symmetricState.STATELEN)
    var rx = sodium.sodium_malloc(symmetricState.STATELEN)
    symmetricState.split(state.symmetricState, tx, rx)

    return {tx, rx}
  }
}
writeMessage.bytes = 0

function readMessage (state, message, payloadBuffer) {
  assert(state instanceof HandshakeState)
  assert(message.byteLength != null)
  assert(payloadBuffer.byteLength != null)
}

function clone (o) { // Good enough for now
  return JSON.parse(JSON.stringify(o))
}
