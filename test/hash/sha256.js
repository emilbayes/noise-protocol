const dh = require('../../dh')()
const { hkdf, HASHLEN } = require('../../hash/sha256.js')({ dh })

const assert = require('nanoassert')

const chainingKey = Buffer.from(
  '4e6f6973655f58585f32353531395f58436861436861506f6c795f5348413235',
  'hex'
)

const inputKeyMaterial = Buffer.from(
  'a3eae50ea37a47e8a7aa0c7cd8e16528670536dcd538cebfd724fb68ce44f1910ad898860666227d4e8dd50d22a9a64d1c0a6f47ace092510161e9e442953da3',
  'hex'
)

const out1 = Buffer.alloc(HASHLEN)
const out2 = Buffer.alloc(HASHLEN)
const out3 = Buffer.alloc(HASHLEN)

hkdf(out1, out2, out3, chainingKey, inputKeyMaterial)

console.log(out1)

assert(
  'cc5659adff12714982f806e2477a8d5ddd071def4c29bb38777b7e37046f6914',
  out1
)
assert(
  'a16ada915e551ab623f38be674bb4ef15d428ae9d80688899c9ef9b62ef208fa',
  out2
)
assert(
  'ff67bf9727e31b06efc203907e6786667d2c7a74ac412b4d31a80ba3fd766f68',
  out3
)

console.log('all good')
