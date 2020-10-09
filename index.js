const dh = require('./dh')
const hash = require('./hash')(dh)
const symmetricState = require('./symmetric-state')(hash)
module.exports = require('./handshake-state')({
  dh,
  symmetricState
})

module.exports.create = require('./handshake-state')
