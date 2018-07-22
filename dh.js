var sodium = require('sodium-native')
var assert = require('nanoassert')

var DHLEN = 2 * sodium.crypto_kx_SESSIONKEYBYTES
var PKLEN = sodium.crypto_kx_PUBLICKEYBYTES
var SKLEN = sodium.crypto_kx_SECRETKEYBYTES

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  keypair,
  initiator,
  responder
}

function keypair (pk, sk) {
  assert(pk.byteLength === PKLEN)
  assert(sk.byteLength === SKLEN)
  sodium.crypto_kx_keypair(pk, sk)
}

function initiator (output, keypair, pk) {
  assert(output.byteLength === DHLEN)
  assert(keypair.pk.byteLength === PKLEN)
  assert(keypair.sk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  sodium.crypto_kx_client_session_keys(
    output.subarray(DHLEN * 1 / 2, DHLEN * 2 / 2),
    output.subarray(DHLEN * 0 / 2, DHLEN * 1 / 2),
    keypair.pk,
    keypair.sk,
    pk
  )
}

function responder (output, keypair, pk) {
  assert(output.byteLength === DHLEN)
  assert(output.byteLength === DHLEN)
  assert(keypair.pk.byteLength === PKLEN)
  assert(keypair.sk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  sodium.crypto_kx_server_session_keys(
    output.subarray(DHLEN * 0 / 2, DHLEN * 1 / 2),
    output.subarray(DHLEN * 1 / 2, DHLEN * 2 / 2),
    keypair.pk,
    keypair.sk,
    pk
  )
}
