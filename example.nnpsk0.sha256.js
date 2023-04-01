const dh = require('./dh')()
const hash = require('./hash/sha256')({ dh })
const cipher = require('./cipher')()
const cipherState = require('./cipher-state')({ cipher })
const symmetricState = require('./symmetric-state')({ hash, cipherState })

const noise = require('./index').createHandshake({
  dh,
  hash,
  cipher,
  symmetricState,
  cipherState
})

const client = noise.initialize('NNpsk0', true, Buffer.from('NoiseAPIInit\x00\x00'))
const server = noise.initialize('NNpsk0', false, Buffer.from('NoiseAPIInit\x00\x00'))
const key = Buffer.from('JtfC7Vth4AwHFCy6RmyLn19zvta13SkMH7TIIJGbb6w=', 'base64');

noise.setPsks(client, key)
noise.setPsks(server, key)

const clientTx = Buffer.alloc(128)
const serverTx = Buffer.alloc(128)

const clientRx = Buffer.alloc(128)
const serverRx = Buffer.alloc(128)

// -> e, es, ss
noise.writeMessage(client, Buffer.alloc(0), clientTx)
noise.readMessage(
  server,
  clientTx.subarray(0, noise.writeMessage.bytes),
  serverRx
)

// <- e, ee, se
const serverSplit = noise.writeMessage(server, Buffer.alloc(0), serverTx)
const clientSplit = noise.readMessage(
  client,
  serverTx.subarray(0, noise.writeMessage.bytes),
  clientRx
)

noise.destroy(client)
noise.destroy(server)

// Can now do transport encryption with splits
console.log(serverSplit)
console.log(clientSplit)
