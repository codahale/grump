// Package grump implements a grumpy cryptosystem for asynchronous messages.
//
// Grump is an experiment in building a post-PGP, post-Snowden cryptosystem for
// asynchronously sending confidential and authentic messages of arbitrary
// size. It is an experiment, and should literally never be used in a context
// where the confidentiality or authenticity of a message has any value
// whatsoever. It is intended to be a conversation piece, and has not been
// vetted, analyzed, reviewed, or even heard of by a security professional. You
// are better off CC'ing a copy of your communications to the FBI than using
// this. No touchy.
//
//     It was on display in the bottom of a locked filing cabinet stuck in a
//     disused lavatory with a sign on the door saying "Beware of the Leopard".
//
// I swear, I will slap you.
//
// Threat Model
//
// The threat model is defined in terms of what each possible attacker can
// achieve. The list is intended to be exhaustive, i.e. if an entity can do
// something that is not listed here then that should count as a break of Grump.
//
//
// Assumptions About The User
//
// The user must act reasonably and in their best interest. They must not reveal
// their passphrase or share unencrypted copies of messages.
//
// The user must run a copy of Grump which has not been suborned.
//
//
// Assumptions About The User's Computer
//
// The user's computer computer must function correctly and not be compromised
// by malware.
//
//
// Assumptions About The User's Friends
//
// The user's friends must also act reasonably.
//
// The user's friends must also run copies of Grump which have not been
// suborned.
//
//
// Assumptions About The World
//
// The security assumptions and proofs of Curve25519
// (http://cr.yp.to/ecdh.html), Ed25519 (http://ed25519.cr.yp.to/), ChaCha20
// (http://cr.yp.to/chacha.html), Poly1305 (http://cr.yp.to/mac.html), their
// combination (http://eprint.iacr.org/2014/613.pdf), SHA-512
// (http://csrc.nist.gov/publications/nistpubs/800-107-rev1/sp800-107-rev1.pdf),
// HKDF (https://tools.ietf.org/html/rfc5869), and scrypt
// (http://www.tarsnap.com/scrypt/scrypt.pdf) must be valid.
//
//
// Threats From Global Passive Adversaries
//
// A Global Passive Adversary is an attacker who can eavesdrop on internet
// traffic globally. A GPA can:
//
//     * Identify Grump messages as Grump messages.
//     * Observe when Grump messages are sent, and to whom they are sent.
//     * Learn the upper bound of the size of a Grump message.
//     * Learn the upper bound of the number of recipients of a Grump message.
//     * Identify Grump keys, both public and private, as such.
//     * Observe when Grump keys are sent or exchanged, and with whom.
//
//
// Threats From Active Network Adversaries
//
// An attacker with a privileged network position to the user can:
//
//     * Identify Grump messages as Grump messages.
//     * Observe when Grump messages are sent, and to whom they are sent if the
//       message is sent directly (e.g., via email).
//     * Learn the upper bound of the size of a Grump message.
//     * Learn the upper bound of the number of recipients of a Grump message.
//     * Identify Grump keys, both public and private, as such.
//     * Observe when Grump keys are sent or exchanged, and with whom if the
//       keys are sent directly.
//     * Modify messages such that they are no longer valid.
//     * Block messages from being sent.
//     * Replay previously recorded messages.
//
//
// Seizure Of The User's Computer
//
// An attacker who physically seizes the user's computer (or compromises the
// user's backups) can:
//
//     * Attempt an offline dictionary/brute force attack on the user's
//       passphrase. If successful, the attacker will be able to decrypt all
//       messages encrypted with the user's public key as well as forge
//       arbitrary messages from the user.
//     * Analyze the user's collection of other people's public keys, which may
//       potentially aide traffic analysis and de-anonymization efforts.
//
//
// Compromise Of The User's Computer
//
// An attacker who physically compromises the user's computer can:
//
//     * Recover the user's passphrase, allowing them to decrypt all existing
//       messages encrypted with the user's public key as well as forge
//       arbitrary messages from the user.
//     * Analyze the user's public keys of other people's public keys, which may
//       potentially aide traffic analysis and de-anonymization efforts.
//
//
// Recipients Of A Message
//
// A valid recipient of a message can:
//
//     * Prove, to some degree, that a particular message came from a particular
//       user.
//
//
// Thirsty Randos
//
// A thirsty rando can:
//
//     * Stop playing in my mentions.
//
//
// If A Non-Recipient Attempts To Read A Message
//
// Without their public key being used to encrypt a copy of the message key, a
// non-recipient would have to brute force the 256-bit ChaCha20Poly1305 key used
// to encrypt a message key copy.
//
//
// If A Non-Recipient Attempts To Modify A Message
//
// A more crafty attacker may attempt to modify an existing message.
//
// If they modify the header, either by adding junk recipients or by removing
// valid recipients, the resulting message will be considered invalid when the
// first packet fails to decrypt due to the SHA-512 hash of the header being
// different.
//
// If they modify either the nonce or the ciphertext of a packet in the message,
// ChaCha20Poly1305 will fail to authenticate and decryption will halt.
//
// If they duplicate a packet or modify the order of the packets, the SHA-512
// hash will change and that packet and all following packets will fail to
// decrypt.
//
// Finally, the Ed25519 signature will fail to verify if any non-signature bytes
// in the message change.
//
//
// If A Recipient Attempts To Modify A Message
//
// A recipient has the message key, which allows them to forge packets for a
// message. While this would allow them to copy the header from a message and
// replace all the contents with valid ChaCha20Poly1305 ciphertexts, the Ed25519
// signature will fail to verify and decryption will halt.
//
//
// If A Rando Plays With Protobufs
//
// The sole aspect of a message which is unauthenticated is the Protocol Buffer
// and framing metadata. An attacker can craft a message which has protobuf
// frames which are up to 4GiB. Grump implementations should perform hygiene
// checks on these values, and Protocol Buffer implementations should be checked
// for robustness to these types of attacks.
//
// If a packet's frame is changed to, for example, elide data, the SHA-512 hash
// will change and the packet will become invalid.
//
//
// Design
//
// The general design is largely informed by ECIES
// (http://en.wikipedia.org/wiki/Integrated_Encryption_Scheme), in that it
// combines a key exchange algorithm, a key derivation algorithm, and an
// IND-CCA2 AEAD scheme.
//
//
// Protocol Buffers
//
// X.509 is better than nothing, but it's horrible. Grump uses Protocol Buffers,
// which has extremely broad language support
// (https://code.google.com/p/protobuf/wiki/ThirdPartyAddOns).
//
//
// Curve25519 And Ed25519
//
// These algorithms were selected because they're both fast, constant-time,
// require entropy for key generation only, use small keys, and use safe
// elliptic curves (http://safecurves.cr.yp.to).
//
//
// ChaCha20Poly1305
//
// The ChaChaPoly1305 AEAD construction was chosen because it's fast and
// constant-time.
//
//
// Scrypt
//
// scrypt was chosen as a PBKDF algorithm because it's resistant to CPU-, GPU-,
// FPGA-, and ASIC-optimized dictionary attacks.
//
//
// SHA-512 and HKDF
//
// These were selected as a KDF because Ed25519 already uses SHA-512.
//
//
// Keys
//
// A Grump private key is the combination of a Curve25519 decryption key and a
// Ed25519 signing key. Both are stored on disk encrypted with ChaCha20Poly1305,
// using a key derived from your passphrase via scrypt.
//
// A Grump public key is the combination of a Curve25519 encryption key and a
// Ed25519 verifying key.
//
// No, there isn't any way to keep track of whose keys are whose.
//
//
// Messages
//
// Grump messages are a sequence of framed protobufs (little-endian, 32-bit
// frame value, then that many bytes of protobuf).
//
// A message starts with a header, which is contains the message key (a random
// 256-bit key) encrypted with the shared secret for each recipient (the
// Curve25519 ECDH shared secret, run through HKDF-SHA-512) using
// ChaCha20Poly1305. There is no meta-data, so random values can be added here
// to obscure the actual number of recipients.
//
// (To decrypt a message, one simply iterates through the recipients, trying
// each.)
//
// After the header comes a series of packets of arbitrary sizes, which are
// portions of the plaintext encrypted with ChaCha20Poly1305, using the SHA-512
// hash of all previously written bytes as the authenticated data. The last
// packet in a message is flagged as such.
//
// The final element of a message is an Ed25519 signature of the SHA-512 hash of
// every byte in the message which precedes the signature's frame.  Any attempt
// to modify the message will fail this verification.
//
// Synchronous Communications
//
// Grump also provides a system for secure, synchronous communication. It uses a
// simple, two-round handshake.
//
// First, Alice and Bob send each other random 256-bit nonces.
//
// Second, Alice generates a random Curve25519 point, and multiplies it by the
// curve's base to produce her ECDH presecret. She also creates an Ed25519
// signature of Bob's nonce and her ECDH presecret. She sends both the ECDH
// presecret and the signature. Bob does the same.
//
// They both verify each other's signatures, and if the signature is valid,
// calculate the final ECDH shared secret. They each derive two keys using
// HKDF-SHA512: one for sending data (using a null salt and the peer's public
// key as the info), and one for receiving data (using a null salt and their own
// public key as the info).
//
// Data is then transmitted back and forth using standard Grump encrypted data
// packets, each encrypted with ChaCha20Poly1305 and a random nonce. If any of
// the packets fail to decrypt, the connection is closed.
package grump
