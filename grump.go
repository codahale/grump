package grump

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/big"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"github.com/codahale/chacha20poly1305"
	"github.com/codahale/grump/pb"
)

// PublicKey is a Grump public key, which consists of a Curve25519 public key
// for encryption and a Ed25519 public key for verification.
type PublicKey []byte

// PrivateKey is a Grump private key, which consists of a Curve25519 private key
// for decryption and a Ed25519 private key for signing. Both are encrypted with
// ChaCha20Poly1305 using a key derived from a passphrase using scrypt.
type PrivateKey []byte

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

	saltSize = 32 // 256-bit salts
)

// GenerateKeyPair creates a new Curve25519 key pair and encrypts the private
// key with the given passphrase and scrypt parameters.
func GenerateKeyPair(
	passphrase string,
	n, r, p int,
) (PublicKey, PrivateKey, error) {
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

	// derive the symmetric key from the passphrase
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, n, r, p, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}
	aead, _ := chacha20poly1305.NewChaCha20Poly1305(key)

	// encrypt the decrypting key
	decNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(decNonce); err != nil {
		return nil, nil, err
	}
	encDecryptingKey := aead.Seal(nil, decNonce, decryptingKey, nil)

	// encrypt the signing key
	sigNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(sigNonce); err != nil {
		return nil, nil, err
	}
	encSigningKey := aead.Seal(nil, sigNonce, signingKey, nil)

	// serialize the private key
	privateKey, err := proto.Marshal(&pb.PrivateKey{
		N:    proto.Uint64(uint64(n)),
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

// Encrypt first unlocks the given private key with the given passphrase, then
// uses it to encrypt all of the data in the given reader so that only the given
// recipients can decrypt it.
func Encrypt(
	privateKey PrivateKey,
	passphrase string,
	recipients []PublicKey,
	r io.Reader,
	w io.Writer,
	packetSize int,
) error {
	sigHash := sha256.New()

	fw := framedWriter{
		w:       w,
		sizeBuf: make([]byte, 4),
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
	header, err := encryptMessageKey(decryptingKey, messageKey, recipients, sigHash)
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

		// encrypt the plaintext
		ciphertext := aead.Seal(nil, nonce, plaintext[:n], nil)

		// hash both
		_, _ = sigHash.Write(nonce)
		_, _ = sigHash.Write(ciphertext)

		// write the packet
		if err := fw.writeMessage(&pb.Packet{
			Data: &pb.EncryptedData{
				Nonce:      nonce,
				Ciphertext: ciphertext,
			},
			Last: proto.Bool(done),
		}); err != nil {
			return err
		}
	}

	// write the signature
	sig := ed25519Sign(signingKey, sigHash.Sum(nil))
	return fw.writeMessage(&pb.Signature{
		Signature: sig,
	})
}

// Decrypt first unlocks the given private key with the given passphrase and
// then decrypts the data, verifying that it came from the given sender.
func Decrypt(
	privateKey PrivateKey,
	passphrase string,
	sender PublicKey,
	r io.Reader,
	w io.Writer,
) error {
	sigHash := sha256.New()

	fr := framedReader{
		r:       r,
		sizeBuf: make([]byte, 4),
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

	// hash all the nonces and keys in the header
	for _, ed := range header.Keys {
		_, _ = sigHash.Write(ed.Nonce)
		_, _ = sigHash.Write(ed.Ciphertext)
	}

	var packet pb.Packet

	// iterate through the packets, decrypting them
	for {
		// decode a packet
		if err := fr.readMessage(&packet); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		// hash the nonce and ciphertext
		ed := packet.Data
		_, _ = sigHash.Write(ed.Nonce)
		_, _ = sigHash.Write(ed.Ciphertext)

		// decrypt the data
		plaintext, err := aead.Open(nil, ed.Nonce, ed.Ciphertext, nil)
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

	// read the signature
	var sig pb.Signature
	if err := fr.readMessage(&sig); err != nil {
		return err
	}

	// verify the signature
	if !ed25519Verify(pubKey.VerifyingKey, sigHash.Sum(nil), sig.Signature) {
		return ErrBadSignature
	}

	return nil
}

// decryptPrivateKey decodes and decrypts the given private key, returning the
// decrypting key and the signing key.
func decryptPrivateKey(passphrase string, pubKey []byte) ([]byte, []byte, error) {
	// decode the protobuf
	var pk pb.PrivateKey
	if err := proto.Unmarshal(pubKey, &pk); err != nil {
		return nil, nil, err
	}

	// generate the key
	key, err := scrypt.Key(
		[]byte(passphrase),
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

// encryptMessageKey returns a header with encrypted copies of the message key for
// each recipient.
func encryptMessageKey(
	decryptingKey,
	messageKey []byte,
	recipients []PublicKey,
	sigHash hash.Hash,
) (*pb.Header, error) {
	recipients, err := secureShuffle(recipients, messageKey)
	if err != nil {
		return nil, err
	}

	keys := make([]*pb.EncryptedData, len(recipients))
	var pubKey pb.PublicKey
	for i, buf := range recipients {
		if err := proto.Unmarshal(buf, &pubKey); err != nil {
			return nil, err
		}
		key := sharedSecret(decryptingKey, pubKey.EncryptingKey)
		aead, _ := chacha20poly1305.NewChaCha20Poly1305(key)

		// generate a random nonce
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		// and encrypt the message key
		ciphertext := aead.Seal(nil, nonce, messageKey, nil)
		_, _ = sigHash.Write(nonce)
		_, _ = sigHash.Write(ciphertext)

		keys[i] = &pb.EncryptedData{
			Nonce:      nonce,
			Ciphertext: ciphertext,
		}
	}

	return &pb.Header{Keys: keys}, nil
}

// decryptMessageKey decrypts the message key by trying all the encrypted keys
// in a header.
func decryptMessageKey(
	decryptingKey []byte,
	encryptingKey []byte,
	header *pb.Header,
) ([]byte, error) {
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

// sharedSecret returns the SHA-256 hash of the Curve25519 ECDH shared secret
// for the two keys.
func sharedSecret(decryptingKey []byte, encryptingKey []byte) []byte {
	// perform Curve25519 ECDH
	var privKey, pubKey, sharedKey [32]byte
	copy(privKey[:], decryptingKey)
	copy(pubKey[:], encryptingKey)
	curve25519.ScalarMult(&sharedKey, &privKey, &pubKey)

	// run that through SHA-256
	h := sha256.New()
	_, _ = h.Write(sharedKey[:])
	return h.Sum(nil)
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

func secureShuffle(keys []PublicKey, messageKey []byte) ([]PublicKey, error) {
	k := make([]PublicKey, len(keys))
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

	if _, err := io.ReadFull(fr.r, fr.buf); err != nil {
		return err
	}

	return proto.Unmarshal(fr.buf, msg)
}

// framedWriter writes protobuf messages, framed with a 32-bit little-endian
// length prefix.
type framedWriter struct {
	w       io.Writer
	sizeBuf []byte
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

	_, err = fw.w.Write(buf)
	return err
}
