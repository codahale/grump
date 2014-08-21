# Grump

[![Build Status](https://travis-ci.org/codahale/grump.png?branch=master)](https://travis-ci.org/codahale/grump)

Grump is an experiment in building a post-PGP, post-Snowden cryptosystem for
asynchronously sending confidential and authentic messages of arbitrary
size. **It is an experiment, and should literally never be used in a context
where the confidentiality or authenticity of a message has any value
whatsoever. It is intended to be a conversation piece, and has not been vetted,
analyzed, reviewed, or even heard of by a security professional. You are better
off CC'ing a copy of your communications to the FBI than using this. No
touchy.**

> It was on display in the bottom of a locked filing cabinet stuck in a disused
> lavatory with a sign on the door saying "Beware of the Leopard".

*I swear, I will slap you.*

## Threat Model

The threat model is defined in terms of what each possible attacker can
achieve. The list is intended to be exhaustive, i.e. if an entity can do
something that is not listed here then that should count as a break of Grump.

### Assumptions

#### The User

* The user acts reasonable and in their best interest. They do not reveal their
  passphrase or share unencrypted copies of messages.
* The user is running a copy of Grump which has not been suborned.

#### The User's Computer

* The computer is functioning correctly and is not compromised by malware.

#### The User's Friends

* The user's friends are also acting reasonably.
* The user's friends are also running copies of Grump which have not been
  suborned.

#### The World

* The security assumptions and proofs of [Curve25519][1], [Ed25519][2],
  [ChaCha20][3] and [Poly1305][4] (their [combination][5]), [SHA-512][6],
  [HKDF][7], and [scrypt][8] are valid.

[1]: http://cr.yp.to/ecdh.html
[2]: http://ed25519.cr.yp.to/
[3]: http://cr.yp.to/chacha.html
[4]: http://cr.yp.to/mac.html
[5]: http://eprint.iacr.org/2014/613.pdf
[6]: http://csrc.nist.gov/publications/nistpubs/800-107-rev1/sp800-107-rev1.pdf
[7]: https://tools.ietf.org/html/rfc5869
[8]: http://www.tarsnap.com/scrypt/scrypt.pdf

### Threats

#### Global, Passive Adversaries (GPAs)

A Global, Passive Adversary is an attacker who can eavesdrop on internet traffic
globally. A GPA can:

* Identify Grump messages as Grump messages.
* Observe when Grump messages are sent, and to whom they are sent.
* Learn the upper bound of the size of a Grump message.
* Learn the upper bound of the number of recipients of a Grump message.
* Identify Grump keys, both public and private, as such.
* Observe when Grump keys are sent or exchanged, and with whom.

#### Active Network Adversaries

An attacker with a privileged network position to the user can:

* Identify Grump messages as Grump messages.
* Observe when Grump messages are sent, and to whom they are sent if the
* message is sent directly (e.g., via email).
* Learn the upper bound of the size of a Grump message.
* Learn the upper bound of the number of recipients of a Grump message.
* Identify Grump keys, both public and private, as such.
* Observe when Grump keys are sent or exchanged, and with whom if the keys are
* sent directly.
* Modify messages such that they are no longer valid.
* Block messages from being sent.
* Replay previously recorded messages.

#### Seizure Of The User's Computer

An attacker who physically seizes the user's computer (or compromises the user's
backups) can:

* Attempt an offline dictionary/brute force attack on the user's passphrase. If
  successful, the attacker will be able to decrypt all messages encrypted with
  the user's public key as well as forge arbitrary messages from the user.
* Analyze the user's collection of other people's public keys, which may
  potentially aide traffic analysis and de-anonymization efforts.

#### Compromise Of The User's Computer

An attacker who physically compromises the user's computer can:

* Recover the user's passphrase, allowing them to decrypt all existing messages
  encrypted with the user's public key as well as forge arbitrary messages from
  the user.
* Analyze the user's public keys of other people's public keys, which may
  potentially aide traffic analysis and de-anonymization efforts.

#### Recipients Of A Message

A valid recipient of a message can:

* Prove, to some degree, that a particular message came from a particular user.

#### Thirsty Randos

A thirsty rando can:

* Stop playing in my mentions.

### Scenarios

#### A Non-Recipient Attempts To Read A Message

Without their public key being used to encrypt a copy of the message key, a
non-recipient would have to brute force the 256-bit ChaCha20Poly1305 key used to
encrypt a message key copy.

#### A Non-Recipient Attempts To Modify A Message

A more crafty attacker may attempt to modify a message.

If they modify either the nonce or the ciphertext of a packet in the message,
ChaCha20Poly1305 will fail to authenticate and decryption will halt.

If they duplicate a packet or modify the order of the packets, the Ed25519
signature will fail to verify and decryption will halt.

#### A Recipient Attempts To Modify A Message

A recipient has the message key, which allows them to forge packets for a
message. While this would allow them to copy the header from a message and
replace all the contents with valid ChaCha20Poly1305 ciphertexts, the Ed25519
signature will fail to verify and decryption will halt.

#### A Rando Plays With Protobufs

The sole aspect of a message which is unauthenticated is the Protocol Buffer and
framing metadata. An attacker can craft a message which has protobuf frames
which are up to 4GiB. Grump implementations should perform hygiene checks on
these values, and Protocol Buffer implementations should be checked for
robustness to these types of attacks.

## Design

### Curve25519 & Ed25519

* It's fast.
* It's constant-time.
* It only requires entropy to generate keys.
* It produces small keys.
* It uses a safe EC curve.

### ChaCha20Poly1305

* It's fast.
* It's constant-time.
* It's a strong AEAD.

### scrypt

* It's resistant to CPU-, GPU-, FPGA-, and ASIC-optimized dictionary attacks.
* Its parameters are adjustable, despite being a bit opaque.

### SHA-512 and HKDF

* Ed25519 already uses SHA-512.

### Keys

A Grump private key is the combination of a Curve25519 decryption key and a
Ed25519 signing key. Both are stored on disk encrypted with ChaCha20Poly1305,
using a key derived from your passphrase via scrypt.

A Grump public key is the combination of a Curve25519 encryption key and a
Ed25519 verifying key.

### Messages

Grump messages are a sequence of framed protobufs (little-endian, 32-bit frame
value, then that many bytes of protobuf).

A message starts with a header, which is contains the message key (a random
256-bit key) encrypted with the shared secret for each recipient (the Curve25519
ECDH shared secret, run through HKDF-SHA-512) using ChaCha20Poly1305. There is
no meta-data, so random values can be added here to obscure the actual number of
recipients.

(To decrypt a message, one simply iterates through the recipients, trying each.)

After the header comes a series of packets of arbitrary sizes, which are
portions of the plaintext encrypted with ChaCha20Poly1305. The last packet in a
message is flagged as such.

The final element of a message is an Ed25519 signature of the SHA-512 hash of
every nonce and ciphertext (including those in the header) in the order they
appear in the message. Any attempt to add or remove packets (or recipients) will
fail this verification.

## TODO

* Yes, I'm echoing your passphrase back to you. I said don't use this.
* Curve25519 provides ~128 bits of security, but ChaCha20 provides 256
  bits. It's a bit of a mismatch, but there isn't a Go impl of Curve41417 or
  whatever, so I'm inclined to press forward and forget about it.
* No, there isn't any way to keep track of whose keys are whose.
