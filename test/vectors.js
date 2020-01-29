var noise = require('..')
var sodium = require('sodium-native')
var test = require('tape')

// This test resolves to fixed results due to supplying both fixed
// static keypairs and fixed epehemeral keypairs.
// Note though that all expected values in this test just come from
// running it and using the results – I couldn't find any verified test
// vectors for XChaChaPoly_Blake2b.
test('XX pattern with fixed ephemeral keys', function (assert) {
  var clientS = generateKeypair(getIncKey(0))
  var client = noise.initialize('XX', true, Buffer.alloc(0), clientS)
  client.fixedE = generateKeypair(getIncKey(32))
  var serverS = generateKeypair(getIncKey(64))
  var server = noise.initialize('XX', false, Buffer.alloc(0), serverS)
  server.fixedE = generateKeypair(getIncKey(96))

  var clientTx = Buffer.alloc(512)
  var serverRx = Buffer.alloc(512)

  var serverTx = Buffer.alloc(512)
  var clientRx = Buffer.alloc(512)

  // 1 -> e
  assert.false(noise.writeMessage(client, Buffer.alloc(0), clientTx))
  assert.ok(noise.writeMessage.bytes > 0)
  assert.false(noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx))
  assert.equal(noise.readMessage.bytes, 0)
  // console.log(1, clientTx.subarray(0, noise.writeMessage.bytes).toString('hex'))
  assert.equal(
    clientTx.subarray(0, noise.writeMessage.bytes).toString('hex'),
    '358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254'
  )

  // 2 <- e, ee s, es
  assert.false(noise.writeMessage(server, Buffer.alloc(0), serverTx))
  assert.ok(noise.writeMessage.bytes > 0)
  assert.false(noise.readMessage(client, serverTx.subarray(0, noise.writeMessage.bytes), clientRx))
  assert.equal(noise.readMessage.bytes, 0)
  // console.log(2, serverTx.subarray(0, noise.writeMessage.bytes).toString('hex'))
  assert.equal(
    serverTx.subarray(0, noise.writeMessage.bytes).toString('hex'),
    '675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f757bbaa0f101e72c6fb6bd56c69be777b58a6b2c254293fa2f8a1b31900f9932de6413d064c32573c16a50423246b7e919227f2f6ee37283e303a349ef31b1e8'
  )

  // 3 -> s, se
  var splitClient = noise.writeMessage(client, Buffer.alloc(0), clientTx)
  assert.ok(noise.writeMessage.bytes > 0)
  var splitServer = noise.readMessage(server, clientTx.subarray(0, noise.writeMessage.bytes), serverRx)
  assert.equal(noise.readMessage.bytes, 0)
  // console.log(3, clientTx.subarray(0, noise.writeMessage.bytes).toString('hex'))
  assert.equal(
    clientTx.subarray(0, noise.writeMessage.bytes).toString('hex'),
    'e7cf203f27d7a42b30f57ecc0923de9a5502517a6224351148f92b585a57ea8f77851e093bc266178e08dc39fe9820fbfbb22318f7fedf486f8dac5695c0e474'
  )

  assert.same(splitClient.tx, splitServer.rx)
  assert.same(splitClient.rx, splitServer.tx)
  // console.log('tx', splitClient.tx.toString('hex'))
  // console.log('rx', splitClient.rx.toString('hex'))
  assert.same(
    splitClient.tx.toString('hex'),
    '94d2a7ccce5abecf603150c05d325a53b5189e9e5533610fe4ab0a43bcb8fb7c0000000000000000'
  )
  assert.same(
    splitClient.rx.toString('hex'),
    'a8344558c4c7cb3403400b8d04355a331a7667ab1bedd267f2878b376121c7f20000000000000000'
  )

  assert.end()
})

function getIncKey (start) {
  var k = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) {
    k[i] = start + i
  }
  return k
}

function generateKeypair (secretKey) {
  var publicKey = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult_base(publicKey, secretKey)
  return { secretKey, publicKey }
}
