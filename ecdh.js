const { assert } = require("console")
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
const PKLEN = 32 // typically 33, but we always remove parity byte
const SKLEN = 32

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

	// We're allowed to remove first parity-byte because the algorithm above
	// ensures that it's always the same.
	pk.fill(dh.getPublicKey(null, "compressed").subarray(1))
	sk.fill(dh.getPrivateKey())
}

function dh(output, lsk, pk) {
	ecdh.setPrivateKey(lsk)
	output.fill(ecdh.computeSecret(pk))
}

module.exports = {
	DHLEN,
	PKLEN,
	SKLEN,
	SEEDLEN,
	generateKeypair,
	dh,
}
