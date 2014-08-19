# grump

There is literally no reason why you should be looking at this.

(Which is to say, do not use this. For anything.)

## Keys

Keys in Grump are very simple. A private key is a randomly generated 256-bit
value, used as a Curve25519 key. It's stored on disk encrypted with
ChaCha20Poly1305, using a key derived from your passphrase via scrypt, as a
protobuf.

## Messages

Grump messages are a sequence of framed protobufs (little-endian, 32-bit frame
value, then that many bytes of protobuf).

A message starts with a header, which is contains the message key (a random
256-bit key) encrypted with the shared secret for each recipient (the Curve25519
ECDH shared secret, hashed with SHA-256) using ChaCha20Poly1305. There is no
meta-data, so random values can be added here to obscure the actual number of
recipients.

(To decrypt a message, one simply iterates through the recipients, trying each.)

After the header comes a series of chunks of arbitrary sizes. Each chunk has a
32-bit ID, a nonce, and the ciphertext, which is the data encrypted with
ChaCha20Poly1305. To ensure that chunks are in the proper order, the sequence of
IDs of the chunks which precede any chunk are used as the authenticated data for
the chunk AEAD (e.g., chunk #4's authenticated data is `[1, 2, 3, 4]`, encoded
as a series of little-endian 32-bit values).

The last chunk in a message is flagged as such and includes an addition zero ID
appended to the end of its authenticated data.

## TODO

* Yes, I'm echoing your passphrase back to you. I said don't use this.
* Curve25519 provides ~128 bits of security, but ChaCha20 provides 256
  bits. It's a bit of a mismatch, but there isn't a Go impl of Curve41417 or
  whatever, so I'm inclined to press forward and forget about it.
* No, there isn't any way to keep track of whose keys are whose.
