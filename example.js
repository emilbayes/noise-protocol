var noise = require('.')
var sodium = require('sodium-native')
var dh = require('./dh')

var sClient = {publicKey: sodium.sodium_malloc(dh.PKLEN), secretKey: sodium.sodium_malloc(dh.SKLEN)}
var sServer = {publicKey: sodium.sodium_malloc(dh.PKLEN), secretKey: sodium.sodium_malloc(dh.SKLEN)}

dh.generateKeypair(sServer.publicKey, sServer.secretKey)
dh.generateKeypair(sClient.publicKey, sClient.secretKey)

var client = noise.initialize('XX', true, Buffer.alloc(0), sClient)
var server = noise.initialize('XX', false, Buffer.alloc(0), sServer)

console.log(client, server)

var clientTx = Buffer.alloc(128)
var serverTx = Buffer.alloc(128)

var clientRx = Buffer.alloc(128)
var serverRx = Buffer.alloc(128)

noise.writeMessage(client, Buffer.alloc(0), clientTx)
console.log(client, clientTx)

noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx)
console.log(server, serverRx)

noise.writeMessage(server, Buffer.alloc(0), serverTx)
console.log(server, serverTx)

noise.readMessage(client, serverTx.subarray(0, noise.writeMessage.bytes), clientRx)
console.log(client, clientRx)
noise.destroy(client)
noise.destroy(server)
