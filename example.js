const noise = require('./index2')

const sClient = noise.keygen()
const sServer = noise.keygen()

const client = noise.initialize('KK', true, Buffer.alloc(0), sClient, null, sServer.publicKey)
const server = noise.initialize('KK', false, Buffer.alloc(0), sServer, null, sClient.publicKey)

const clientTx = Buffer.alloc(128)
const serverTx = Buffer.alloc(128)

const clientRx = Buffer.alloc(128)
const serverRx = Buffer.alloc(128)

// -> e, es, ss
noise.writeMessage(client, Buffer.alloc(0), clientTx)
noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx)

// <- e, ee, se
const serverSplit = noise.writeMessage(server, Buffer.alloc(0), serverTx)
const clientSplit = noise.readMessage(client, serverTx.subarray(0, noise.writeMessage.bytes), clientRx)

noise.destroy(client)
noise.destroy(server)

// Can now do transport encryption with splits
console.log(serverSplit)
console.log(clientSplit)
