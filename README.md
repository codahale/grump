# grump

There is literally no reason why you should be looking at this.

(Which is to say, do not use this. For anything.)

## Keys

A Grump private key is the combination of a Curve25519 decryption key and a
Ed25519 signing key. Both are stored on disk encrypted with ChaCha20Poly1305,
using a key derived from your passphrase via scrypt.

A Grump public key is the combination of a Curve25519 encryption key and a
Ed25519 verifying key.

## Messages

Grump messages are a sequence of framed protobufs (little-endian, 32-bit frame
value, then that many bytes of protobuf).

A message starts with a header, which is contains the message key (a random
256-bit key) encrypted with the shared secret for each recipient (the Curve25519
ECDH shared secret, hashed with SHA-256) using ChaCha20Poly1305. There is no
meta-data, so random values can be added here to obscure the actual number of
recipients.

(To decrypt a message, one simply iterates through the recipients, trying each.)

After the header comes a series of chunks of arbitrary sizes, which are portions
of the plaintext encrypted with ChaCha20Poly1305. The last chunk in a message is
flagged as such.

The final element of a message is an Ed25519 signature of the SHA-256 hash of
every nonce and ciphertext (including those in the header) in the order they
appear in the message. Any attempt to add or remove chunks (or recipients) will
fail this verification.

## TODO

* Yes, I'm echoing your passphrase back to you. I said don't use this.
* Curve25519 provides ~128 bits of security, but ChaCha20 provides 256
  bits. It's a bit of a mismatch, but there isn't a Go impl of Curve41417 or
  whatever, so I'm inclined to press forward and forget about it.
* No, there isn't any way to keep track of whose keys are whose.
