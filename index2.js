const ecdh = require('./ecdh')
const hash = require('./hash')(ecdh)
const symmetricState = require('./symmetric-state')(hash)
module.exports = require('./handshake-state')({
    dh: ecdh,
    symmetricState
})