const noise = require('../..')
const test = require('tape')

test('N pattern', function (assert) {
  const serverKeys = noise.keygen()

  const client = noise.initialize('N', true, Buffer.alloc(0), null, null, serverKeys.publicKey)
  const server = noise.initialize('N', false, Buffer.alloc(0), serverKeys)

  const clientTx = Buffer.alloc(512)
  const serverRx = Buffer.alloc(512)

  const splitClient = noise.writeMessage(client, Buffer.from('Hello world'), clientTx)
  assert.ok(noise.writeMessage.bytes > 11)
  assert.false(Buffer.from(clientTx).includes(Buffer.from('Hello world')))
  assert.false(Buffer.from(clientTx).includes(Buffer.from(client.rs)))
  assert.false(Buffer.from(clientTx).includes(Buffer.from(client.esk)))
  const splitServer = noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx)
  assert.equal(noise.readMessage.bytes, 11)

  assert.same(splitClient.tx, splitServer.rx)
  assert.same(splitClient.rx, splitServer.tx)
  assert.notSame(splitServer.rx, splitServer.tx)
  assert.notSame(splitClient.rx, splitClient.tx)

  assert.end()
})
