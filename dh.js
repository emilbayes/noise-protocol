var sodium = require('sodium-native')
var assert = require('nanoassert')

var DHLEN = 2 * sodium.crypto_kx_SESSIONKEYBYTES
var PKLEN = sodium.crypto_kx_PUBLICKEYBYTES
var SKLEN = sodium.crypto_kx_SECRETKEYBYTES
var SEEDLEN = sodium.crypto_kx_SEEDBYTES

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  SEEDLEN,
  generateKeypair,
  generateSeedKeypair,
  initiator,
  responder
}

function generateKeypair (pk, sk) {
  assert(pk.byteLength === PKLEN)
  assert(sk.byteLength === SKLEN)
  sodium.crypto_kx_keypair(pk, sk)
}

function generateSeedKeypair (pk, sk, seed) {
  assert(pk.byteLength === PKLEN)
  assert(sk.byteLength === SKLEN)
  assert(seed.byteLength === SKLEN)

  sodium.crypto_kx_seed_keypair(pk, sk, seed)
}

function initiator (output, lpk, lsk, pk) {
  assert(output.byteLength === DHLEN)
  assert(lpk.byteLength === PKLEN)
  assert(lsk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  sodium.crypto_kx_client_session_keys(
    output.subarray(DHLEN * 1 / 2, DHLEN * 2 / 2),
    output.subarray(DHLEN * 0 / 2, DHLEN * 1 / 2),
    lpk,
    lsk,
    pk
  )
}

function responder (output, lpk, lsk, pk) {
  assert(output.byteLength === DHLEN)
  assert(lpk.byteLength === PKLEN)
  assert(lsk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  sodium.crypto_kx_server_session_keys(
    output.subarray(DHLEN * 0 / 2, DHLEN * 1 / 2),
    output.subarray(DHLEN * 1 / 2, DHLEN * 2 / 2),
    lpk,
    lsk,
    pk
  )
}
