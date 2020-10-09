const crypto = require("crypto")
const sodium = require("sodium-universal")
const assert = require("nanoassert")

const ecdh = crypto.createECDH("prime256v1")
// prime used in 'prime256v1'
const prime = Buffer.from(
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
	"hex"
)
const DHLEN = 32
const PKLEN = 33 // first byte is parity byte
const SKLEN = 32

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  generateKeypair,
  generateSeedKeypair,
  dh
}

function generateKeypair(pk, sk) {
	assert(pk.byteLength === PKLEN)
	assert(sk.byteLength === SKLEN)

	while (true) {
		const pair = ecdh.generateKeys()
		let p = Buffer.from(prime)
		sodium.sodium_sub(p, pair.subarray(33))
		let res = sodium.sodium_compare(pair.subarray(33), p)
		if (res > 0) break
	}

	pk.fill(ecdh.getPublicKey(null, "compressed"))
	sk.fill(ecdh.getPrivateKey())
}

function generateSeedKeypair(pk, sk) {
  assert(false, "generateSeedKeypiar not supported for prime256v1")
}

function dh(output, lsk, pk) {
	ecdh.setPrivateKey(lsk)
	output.fill(ecdh.computeSecret(pk))
}


