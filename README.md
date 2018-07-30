# `naive-noise`

> Naive implementation of the Noise Protocol Framework

:rotating_light: :warning: :rotating_light:

This implementation was made to get a feel for the different components in
Noise and test out some ideas

## Usage

```js
var noise = require('naive-noise')

```

## API

### `var handshakeState = noise.initialize(handshakePattern, initiator, [staticKeys], [ephemeralKeys], [remoteStaticKey], [remoteEphemeralKey])`

Create a new Noise handshake instance with:

* `handshakePattern` is one of `NN`, `KK`, `XX`
* `initiator` is Boolean
* `staticKeys` is local static keys as an object of `{publicKey, secretKey}`.
  This is only required if the handshake pattern mandates these as shared out of band (premessages)
* `ephemeralKeys` is local ephemeral keys as an object of `{publicKey, secretKey}`.
  This is only required if the handshake pattern mandates these as shared out of band (premessages)
* `remoteStaticKey` is a Buffer of `PKLEN` bytes. This is most likely not required
* `remoteEphemeralKey` is a Buffer of `PKLEN` bytes. This is most likely not required

### `noise.writeMessage(state, payload, messageBuffer)`

### `noise.writeMessage.bytes`

### `noise.readMessage(state, message, payloadBuffer)`

### `noise.readMessage.bytes`

### `noise.PKLEN`

### `noise.SKLEN`

## Install

```sh
npm install naive-noise
```

## Deviations from the Noise specification

* Uses `libsodium`s `crypto_kx_*` API which hashes the shared secret with the
  client and server public key; `BLAKE2b-512(shared || client_pk || server_pk)`
* Uses `crypto_aead_xchacha20poly1305_ietf_*` for symmetric cryptography with
  nonces `128-bit zero || 64-bit counter`, meaning the protocol name is `Noise_*_25519_XChaChaPoly_BLAKE2b`, with `*` being the handshake pattern

## License

[ISC](LICENSE)
