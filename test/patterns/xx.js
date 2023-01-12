const noise = require('../..')
const test = require('tape')

test('XX pattern', function (assert) {
  const client = noise.initialize('XX', true, Buffer.alloc(0), noise.keygen())
  const server = noise.initialize('XX', false, Buffer.alloc(0), noise.keygen())

  const clientTx = Buffer.alloc(512)
  const serverRx = Buffer.alloc(512)

  const serverTx = Buffer.alloc(512)
  const clientRx = Buffer.alloc(512)

  // ->
  assert.false(noise.writeMessage(client, Buffer.alloc(0), clientTx))
  assert.ok(noise.writeMessage.bytes > 0)
  assert.false(noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx))
  assert.equal(noise.readMessage.bytes, 0)

  // <-
  assert.false(noise.writeMessage(server, Buffer.alloc(0), serverTx))
  assert.ok(noise.writeMessage.bytes > 0)
  assert.false(noise.readMessage(client, serverTx.subarray(0, noise.writeMessage.bytes), clientRx))
  assert.equal(noise.readMessage.bytes, 0)

  // ->
  const splitClient = noise.writeMessage(client, Buffer.alloc(0), clientTx)
  assert.ok(noise.writeMessage.bytes > 0)
  const splitServer = noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx)
  assert.equal(noise.readMessage.bytes, 0)

  assert.same(splitClient.tx, splitServer.rx)
  assert.same(splitClient.rx, splitServer.tx)

  assert.end()
})
