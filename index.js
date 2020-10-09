const dh = require('./dh')()
const hash = require('./hash')({ dh })
const cipher = require('./cipher')()
const cipherState = require('./cipher-state')({ cipher })
const symmetricState = require('./symmetric-state')({ hash, cipherState })

module.exports = require('./handshake-state')({
  dh,
  hash,
  cipher,
  cipherState,
  symmetricState
})
