var noise = require('.')
var assert = require('nanoassert')

var client = noise.initialize('NN', true, Buffer.alloc(0))
var server = noise.initialize('NN', false, Buffer.alloc(0))

console.log(client, server)

var clientTx = Buffer.alloc(65535)
var serverTx = Buffer.alloc(65535)

var clientRx = Buffer.alloc(65535)
var serverRx = Buffer.alloc(65535)

noise.writeMessage(client, Buffer.alloc(0), clientTx)
console.log(client, clientTx.subarray(0, noise.writeMessage.bytes))

noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx)
console.log(server, serverRx.subarray(0, noise.readMessage.bytes))

noise.writeMessage(server, Buffer.alloc(0), serverTx)
console.log(server, serverTx.subarray(0, noise.writeMessage.bytes))

noise.readMessage(client, serverTx.subarray(0, noise.writeMessage.bytes), clientRx)
console.log(client, clientRx.subarray(0, noise.readMessage.bytes))
