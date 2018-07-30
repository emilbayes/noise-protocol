var dh = require('../dh')
var test = require('tape')

test('constants', function (assert) {
  assert.ok(dh.DHLEN >= 32, 'DHLEN conforms to Noise Protocol')
  assert.end()
})

test('generateKeypair', function (assert) {
  var kp1 = {sk: Buffer.alloc(dh.SKLEN), pk: Buffer.alloc(dh.PKLEN)}
  var kp2 = {sk: Buffer.alloc(dh.SKLEN), pk: Buffer.alloc(dh.PKLEN)}
  var kp3 = {sk: Buffer.alloc(dh.SKLEN), pk: Buffer.alloc(dh.PKLEN)}

  dh.generateKeypair(kp2.pk, kp2.sk)
  dh.generateKeypair(kp3.pk, kp3.sk)

  assert.notOk(kp1.pk.equals(kp2.pk))
  assert.notOk(kp1.pk.equals(kp3.pk))
  assert.notOk(kp2.pk.equals(kp3.pk))

  assert.notOk(kp1.sk.equals(kp2.sk))
  assert.notOk(kp2.sk.equals(kp3.sk))
  assert.notOk(kp1.sk.equals(kp3.sk))

  assert.notOk(kp2.pk.equals(kp2.sk))
  assert.notOk(kp3.pk.equals(kp3.sk))

  assert.end()
})

test('initiator / responder', function (assert) {
  var server = {sk: Buffer.alloc(dh.SKLEN), pk: Buffer.alloc(dh.PKLEN)}
  var client = {sk: Buffer.alloc(dh.SKLEN), pk: Buffer.alloc(dh.PKLEN)}

  dh.generateKeypair(server.pk, server.sk)
  dh.generateKeypair(client.pk, client.sk)

  var dhc = Buffer.alloc(dh.DHLEN)
  var dhs = Buffer.alloc(dh.DHLEN)

  dh.initiator(dhc, client.pk, client.sk, server.pk)
  dh.responder(dhs, server.pk, server.sk, client.pk)

  assert.ok(dhc.equals(dhs))

  assert.end()
})
