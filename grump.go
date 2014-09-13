package grump

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/hkdf"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"github.com/andrew-d/go-termutil"
	"github.com/codahale/chacha20poly1305"
	"github.com/codahale/grump/pb"
)

var (
	// ErrBadPassphrase is returned when the passphrase provided cannot decrypt
	// the given private key.
	ErrBadPassphrase = errors.New("bad passphrase")

	// ErrBadSignature is returned when the message has been tampered with.
	ErrBadSignature = errors.New("bad signature")

	// ErrNotDecryptable is returned when the given private key cannot be used
	// to decrypt the message key.
	ErrNotDecryptable = errors.New("not decryptable with the given key")

	// ErrFrameTooLarge is returned when a protobuf's frame is too large.
	ErrFrameTooLarge = errors.New("frame too large")
)

const (
	// MaxFrameSize is the maximum allowable size for a protobuf frame.
	MaxFrameSize = 1024 * 1024 * 10
)

// GenerateKeyPair creates a new Curve25519 key pair and encrypts the private
// key with the given passphrase and scrypt parameters.
func GenerateKeyPair(passphrase []byte, n, r, p uint) ([]byte, []byte, error) {
	// generate Curve25519 keys
	encryptingKey, decryptingKey, err := genCurve25519Keys()
	if err != nil {
		return nil, nil, err
	}

	// generate Ed25519 keys
	verifyingKey, signingKey, err := genEd25519Keys()
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := encryptPrivateKey(passphrase, decryptingKey, signingKey, n, r, p)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := proto.Marshal(&pb.PublicKey{
		VerifyingKey:  verifyingKey,
		EncryptingKey: encryptingKey,
	})
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// ChangePassphrase decrypts the given private key with the old passphrase and
// re-encrypts it with the new passphrase.
func ChangePassphrase(privateKey, oldPassphrase, newPassphrase []byte, n, r, p uint) ([]byte, error) {
	decryptingKey, signingKey, err := decryptPrivateKey(oldPassphrase, privateKey)
	if err != nil {
		return nil, err
	}

	return encryptPrivateKey(newPassphrase, decryptingKey, signingKey, n, r, p)
}

// Encrypt first decrypts the given private key with the given passphrase, then
// uses it to encrypt all of the data in the given reader so that only the given
// recipients can decrypt it.
func Encrypt(privateKey, passphrase []byte, recipients [][]byte, r io.Reader, w io.Writer, packetSize int) error {
	fw := framedWriter{
		w:       w,
		sizeBuf: make([]byte, 4),
		h:       sha512.New(),
	}

	// decrypt the private key
	decryptingKey, signingKey, err := decryptPrivateKey(passphrase, privateKey)
	if err != nil {
		return err
	}

	// generate a random message key
	messageKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(messageKey); err != nil {
		return err
	}
	aead, _ := chacha20poly1305.NewChaCha20Poly1305(messageKey)

	// encrypt the message key for all recipients
	header, err := encryptMessageKey(decryptingKey, messageKey, recipients)
	if err != nil {
		return err
	}
	if err := fw.writeMessage(header); err != nil {
		return err
	}

	plaintext := make([]byte, packetSize)
	nonce := make([]byte, aead.NonceSize())

	// iterate through the plaintext, encrypting packets
	var done bool
	for !done {
		// read N bytes of plaintext
		n, err := io.ReadFull(r, plaintext)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			done = true
		} else if err != nil {
			return err
		}

		// generate a nonce
		if _, err := rand.Read(nonce); err != nil {
			return err
		}

		// write the encrypted packet
		if err := fw.writeMessage(&pb.Packet{
			Data: &pb.EncryptedData{
				Nonce:      nonce,
				Ciphertext: aead.Seal(nil, nonce, plaintext[:n], fw.digest()),
			},
			Last: proto.Bool(done),
		}); err != nil {
			return err
		}
	}

	// write the signature
	sig := ed25519Sign(signingKey, fw.digest())
	return fw.writeMessage(&pb.Signature{
		Signature: sig,
	})
}

// Decrypt first decrypts the given private key with the given passphrase and
// then decrypts the data, verifying that it came from the given sender.
func Decrypt(privateKey, passphrase, sender []byte, r io.Reader, w io.Writer) error {
	fr := framedReader{
		r:       r,
		sizeBuf: make([]byte, 4),
		h:       sha512.New(),
	}

	// decode the public key
	var pubKey pb.PublicKey
	if err := proto.Unmarshal(sender, &pubKey); err != nil {
		return err
	}

	// decrypt the private key
	decryptingKey, _, err := decryptPrivateKey(passphrase, privateKey)
	if err != nil {
		return err
	}

	// read the header and recover the message key
	var header pb.Header
	if err := fr.readMessage(&header); err != nil {
		return err
	}
	messageKey, err := decryptMessageKey(
		decryptingKey, pubKey.EncryptingKey, &header,
	)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewChaCha20Poly1305(messageKey)
	if err != nil {
		return err
	}

	var packet pb.Packet

	// iterate through the packets, decrypting them
	for {
		// calculate the hash so far
		digest := fr.digest()

		// decode a packet
		if err := fr.readMessage(&packet); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		// decrypt the data
		ed := packet.Data
		plaintext, err := aead.Open(nil, ed.Nonce, ed.Ciphertext, digest)
		if err != nil {
			return ErrBadSignature
		}

		// write the plaintext
		if _, err := w.Write(plaintext); err != nil {
			return err
		}

		// and break if it's the last packet
		if packet.GetLast() {
			break
		}
	}

	// calculate the digest so far
	digest := fr.digest()

	// read the signature
	var sig pb.Signature
	if err := fr.readMessage(&sig); err != nil {
		return err
	}

	// verify the signature
	if !ed25519Verify(pubKey.VerifyingKey, digest, sig.Signature) {
		return ErrBadSignature
	}

	return nil
}

// Sign first decrypts the private key with the given passphrase, then uses it
// to create a Ed25519 signature of the given data.
func Sign(privKey, passphrase []byte, r io.Reader, w io.Writer) error {
	// decrypt the private key
	_, signingKey, err := decryptPrivateKey(passphrase, privKey)
	if err != nil {
		return err
	}

	// hash the data
	h := sha512.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}

	// sign the data and encode the signature
	buf, err := proto.Marshal(&pb.Signature{
		Signature: ed25519Sign(signingKey, h.Sum(nil)),
	})
	if err != nil {
		return err
	}

	// write the signature
	_, err = w.Write(buf)
	return err
}

// Verify returns an error if the given signature for the given data was not
// created by the owner of the given public key.
func Verify(publicKey, signature []byte, r io.Reader) error {
	// decode the public key
	var pubKey pb.PublicKey
	if err := proto.Unmarshal(publicKey, &pubKey); err != nil {
		return err
	}

	// decode the signature
	var sig pb.Signature
	if err := proto.Unmarshal(signature, &sig); err != nil {
		return err
	}

	// hash the data
	h := sha512.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}

	// verify the signature
	if !ed25519Verify(pubKey.VerifyingKey, h.Sum(nil), sig.Signature) {
		return ErrBadSignature
	}
	return nil
}

// ReadPassphrase either prompts interactively for the passphrase or reads it
// from stdin.
func ReadPassphrase(interactive bool, prompt string) ([]byte, error) {
	if interactive {
		return termutil.GetPass(prompt, os.Stderr.Fd(), os.Stdin.Fd())
	}
	return ioutil.ReadAll(os.Stdin)
}

// decryptPrivateKey decodes and decrypts the given private key, returning the
// decrypting key and the signing key.
func decryptPrivateKey(passphrase, pubKey []byte) ([]byte, []byte, error) {
	// decode the protobuf
	var pk pb.PrivateKey
	if err := proto.Unmarshal(pubKey, &pk); err != nil {
		return nil, nil, err
	}

	// generate the key
	key, err := scrypt.Key(
		passphrase,
		pk.Salt,
		int(pk.GetN()),
		int(pk.GetR()),
		int(pk.GetP()),
		chacha20poly1305.KeySize,
	)
	if err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.NewChaCha20Poly1305(key)
	if err != nil {
		return nil, nil, err
	}

	// decrypt the decrypting key
	k := pk.DecryptingKey
	decryptingKey, err := aead.Open(nil, k.Nonce, k.Ciphertext, nil)
	if err != nil {
		return nil, nil, ErrBadPassphrase
	}

	// decrypt the signing key
	k = pk.SigningKey
	signingKey, err := aead.Open(nil, k.Nonce, k.Ciphertext, nil)
	if err != nil {
		return nil, nil, ErrBadPassphrase
	}

	return decryptingKey, signingKey, nil
}

// encryptMessageKey returns a header with encrypted copies of the message key
// for each recipient. Any recipient slices which are nil will be replaced with
// fake recipients.
func encryptMessageKey(decryptingKey, messageKey []byte, recipients [][]byte) (*pb.Header, error) {
	recipients, err := secureShuffle(recipients)
	if err != nil {
		return nil, err
	}

	keys := make([]*pb.EncryptedData, len(recipients))
	var pubKey pb.PublicKey
	for i, buf := range recipients {
		var key []byte
		if buf == nil {
			// Create a fake recipient by using a random value as a shared
			// secret.
			key = make([]byte, chacha20poly1305.KeySize)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
		} else {
			if err := proto.Unmarshal(buf, &pubKey); err != nil {
				return nil, err
			}
			key = sharedSecret(decryptingKey, pubKey.EncryptingKey)

		}
		aead, _ := chacha20poly1305.NewChaCha20Poly1305(key)

		// generate a random nonce
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		// and encrypt the message key
		keys[i] = &pb.EncryptedData{
			Nonce:      nonce,
			Ciphertext: aead.Seal(nil, nonce, messageKey, nil),
		}
	}

	return &pb.Header{Keys: keys}, nil
}

// decryptMessageKey decrypts the message key by trying all the encrypted keys
// in a header.
func decryptMessageKey(decryptingKey []byte, encryptingKey []byte, header *pb.Header) ([]byte, error) {
	key := sharedSecret(decryptingKey, encryptingKey)
	aead, _ := chacha20poly1305.NewChaCha20Poly1305(key)
	for _, k := range header.Keys {
		key, err := aead.Open(nil, k.Nonce, k.Ciphertext, nil)
		if err == nil {
			return key, nil
		}
	}
	return nil, ErrNotDecryptable
}

// sharedSecret returns a 256-bit key from the HKDF-SHA-512 output of the
// Curve25519 ECDH shared secret for the two keys.
func sharedSecret(decryptingKey []byte, encryptingKey []byte) []byte {
	// perform Curve25519 ECDH
	var privKey, pubKey, sharedKey [32]byte
	copy(privKey[:], decryptingKey)
	copy(pubKey[:], encryptingKey)
	curve25519.ScalarMult(&sharedKey, &privKey, &pubKey)

	key := make([]byte, chacha20poly1305.KeySize)
	kdf := hkdf.New(sha512.New, sharedKey[:], nil, nil)
	_, _ = kdf.Read(key)
	return key
}

// encryptPrivateKey creates an encrypted version of the given private key.
func encryptPrivateKey(passphrase, decryptingKey, signingKey []byte, n, r, p uint) ([]byte, error) {
	// derive the symmetric key from the passphrase
	salt := make([]byte, 32) // 256-bit salt
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, _ := scrypt.Key(passphrase, salt, 1<<n, int(r), int(p), chacha20poly1305.KeySize)
	aead, _ := chacha20poly1305.NewChaCha20Poly1305(key)

	// encrypt the decrypting key
	decNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(decNonce); err != nil {
		return nil, err
	}
	encDecryptingKey := aead.Seal(nil, decNonce, decryptingKey, nil)

	// encrypt the signing key
	sigNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(sigNonce); err != nil {
		return nil, err
	}
	encSigningKey := aead.Seal(nil, sigNonce, signingKey, nil)

	// serialize the private key
	return proto.Marshal(&pb.PrivateKey{
		N:    proto.Uint64(uint64(1 << n)),
		R:    proto.Uint64(uint64(r)),
		P:    proto.Uint64(uint64(p)),
		Salt: salt,
		DecryptingKey: &pb.EncryptedData{
			Nonce:      decNonce,
			Ciphertext: encDecryptingKey,
		},
		SigningKey: &pb.EncryptedData{
			Nonce:      sigNonce,
			Ciphertext: encSigningKey,
		},
	})
}

// genCurve25519Keys generates a Curve25519 key pair.
func genCurve25519Keys() ([]byte, []byte, error) {
	var pubKey, privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return nil, nil, err
	}
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return pubKey[:], privKey[:], nil
}

// genEd25519Keys generates an Ed25519 key pair.
func genEd25519Keys() ([]byte, []byte, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	return pubKey[:], privKey[:], err
}

// ed25519Sign creates an Ed25519 signature of a given hash.
func ed25519Sign(signingKey, hash []byte) []byte {
	var privKey [ed25519.PrivateKeySize]byte
	copy(privKey[:], signingKey)
	return ed25519.Sign(&privKey, hash)[:]
}

// ed25519Verify verifies an Ed25519 signature of a given hash.
func ed25519Verify(verifyingKey, hash, sig []byte) bool {
	var pubKey [ed25519.PublicKeySize]byte
	copy(pubKey[:], verifyingKey)

	var s [ed25519.SignatureSize]byte
	copy(s[:], sig)

	return ed25519.Verify(&pubKey, hash, &s)
}

// secureShuffle returns the given keys in random order.
func secureShuffle(keys [][]byte) ([][]byte, error) {
	k := make([][]byte, len(keys))
	copy(k, keys)

	for i := len(k) - 1; i > 1; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
		if err != nil {
			return nil, err
		}
		j := int(n.Int64())
		k[i], k[j] = k[j], k[i]
	}

	return k, nil
}

// framedReader reads protobuf messages, framed with a 32-bit little-endian
// length prefix.
type framedReader struct {
	r            io.Reader
	sizeBuf, buf []byte
	h            hash.Hash
}

// digest returns the SHA-512 digest of all the data written.
func (fr framedReader) digest() []byte {
	return fr.h.Sum(nil)
}

// readMessage reads the next message in the reader into the given protobuf.
func (fr framedReader) readMessage(msg proto.Message) error {
	if _, err := io.ReadFull(fr.r, fr.sizeBuf); err != nil {
		return err
	}

	size := int(binary.LittleEndian.Uint32(fr.sizeBuf))
	if size > MaxFrameSize {
		return ErrFrameTooLarge
	}

	if len(fr.buf) < size {
		fr.buf = make([]byte, size)
	}

	n, err := io.ReadFull(fr.r, fr.buf)
	if err != nil {
		return err
	}

	_, _ = fr.h.Write(fr.sizeBuf)
	_, _ = fr.h.Write(fr.buf[:n])

	return proto.Unmarshal(fr.buf[:n], msg)
}

// framedWriter writes protobuf messages, framed with a 32-bit little-endian
// length prefix.
type framedWriter struct {
	w       io.Writer
	sizeBuf []byte
	h       hash.Hash
}

// digest returns the SHA-512 digest of all the data written.
func (fw framedWriter) digest() []byte {
	return fw.h.Sum(nil)
}

// writeMessage writes the given protobuf message into the writer.
func (fw framedWriter) writeMessage(msg proto.Message) error {
	buf, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(fw.sizeBuf, uint32(len(buf)))

	if _, err := fw.w.Write(fw.sizeBuf); err != nil {
		return err
	}

	_, _ = fw.h.Write(fw.sizeBuf)
	_, _ = fw.h.Write(buf)

	_, err = fw.w.Write(buf)
	return err
}
