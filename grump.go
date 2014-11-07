package grump

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/andrew-d/go-termutil"
	"github.com/codahale/chacha20poly1305"
	"github.com/codahale/grump/pb"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
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
	// generate Ed25519 keys
	pubKey, privKey, err := genEd25519Keys()
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := encryptPrivateKey(passphrase, privKey, n, r, p)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := proto.Marshal(&pb.PublicKey{
		Key: pubKey,
	})
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// ChangePassphrase decrypts the given private key with the old passphrase and
// re-encrypts it with the new passphrase.
func ChangePassphrase(privateKey, oldPassphrase, newPassphrase []byte, n, r, p uint) ([]byte, error) {
	privKey, err := decryptPrivateKey(oldPassphrase, privateKey)
	if err != nil {
		return nil, err
	}

	return encryptPrivateKey(newPassphrase, privKey, n, r, p)
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
	privKey, err := decryptPrivateKey(passphrase, privateKey)
	if err != nil {
		return err
	}

	// generate a random message key
	messageKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(messageKey); err != nil {
		return err
	}
	aead, _ := chacha20poly1305.New(messageKey)

	// encrypt the message key for all recipients
	header, err := encryptMessageKey(privKey, messageKey, recipients)
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
	sig := ed25519Sign(privKey, fw.digest())
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
	privKey, err := decryptPrivateKey(passphrase, privateKey)
	if err != nil {
		return err
	}

	// read the header and recover the message key
	var header pb.Header
	if err := fr.readMessage(&header); err != nil {
		return err
	}
	messageKey, err := decryptMessageKey(privKey, pubKey.Key, &header)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(messageKey)
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
	if !ed25519Verify(pubKey.Key, digest, sig.Signature) {
		return ErrBadSignature
	}

	return nil
}

// Sign first decrypts the private key with the given passphrase, then uses it
// to create a Ed25519 signature of the given data.
func Sign(privateKey, passphrase []byte, r io.Reader, w io.Writer) error {
	// decrypt the private key
	privKey, err := decryptPrivateKey(passphrase, privateKey)
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
		Signature: ed25519Sign(privKey, h.Sum(nil)),
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
	if !ed25519Verify(pubKey.Key, h.Sum(nil), sig.Signature) {
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

// decryptPrivateKey decodes and decrypts the given private key.
func decryptPrivateKey(passphrase, privKey []byte) ([]byte, error) {
	// decode the protobuf
	var pk pb.PrivateKey
	if err := proto.Unmarshal(privKey, &pk); err != nil {
		return nil, err
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
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// decrypt the private key
	privateKey, err := aead.Open(nil, pk.Key.Nonce, pk.Key.Ciphertext, nil)
	if err != nil {
		return nil, ErrBadPassphrase
	}

	return privateKey, nil
}

// encryptMessageKey returns a header with encrypted copies of the message key
// for each recipient. Any recipient slices which are nil will be replaced with
// fake recipients.
func encryptMessageKey(privKey, messageKey []byte, recipients [][]byte) (*pb.Header, error) {
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
			key = sharedSecret(privKey, pubKey.Key)

		}
		aead, _ := chacha20poly1305.New(key)

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
func decryptMessageKey(privKey, pubKey []byte, header *pb.Header) ([]byte, error) {
	key := sharedSecret(privKey, pubKey)
	aead, _ := chacha20poly1305.New(key)
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
func sharedSecret(privKey, pubKey []byte) []byte {
	var edPrivKey [64]byte
	var edPubKey [32]byte
	copy(edPrivKey[:], privKey)
	copy(edPubKey[:], pubKey)

	// convert to Curve25519 keys
	var cpPrivKey, cpPubKey, sharedKey [32]byte
	extra25519.PrivateKeyToCurve25519(&cpPrivKey, &edPrivKey)
	extra25519.PublicKeyToCurve25519(&cpPubKey, &edPubKey)

	// perform Curve25519 ECDH
	curve25519.ScalarMult(&sharedKey, &cpPrivKey, &cpPubKey)

	key := make([]byte, chacha20poly1305.KeySize)
	kdf := hkdf.New(sha512.New, sharedKey[:], nil, nil)
	_, _ = kdf.Read(key)
	return key
}

// encryptPrivateKey creates an encrypted version of the given private key.
func encryptPrivateKey(passphrase, privKey []byte, n, r, p uint) ([]byte, error) {
	// derive the symmetric key from the passphrase
	salt := make([]byte, 32) // 256-bit salt
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, _ := scrypt.Key(passphrase, salt, 1<<n, int(r), int(p), 32)
	aead, _ := chacha20poly1305.New(key)

	// encrypt the private key
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	encryptedKey := aead.Seal(nil, nonce, privKey, nil)

	// serialize the private key
	return proto.Marshal(&pb.PrivateKey{
		N:    proto.Uint64(uint64(1 << n)),
		R:    proto.Uint64(uint64(r)),
		P:    proto.Uint64(uint64(p)),
		Salt: salt,
		Key: &pb.EncryptedData{
			Nonce:      nonce,
			Ciphertext: encryptedKey,
		},
	})
}

// genEd25519Keys generates an Ed25519 key pair.
func genEd25519Keys() ([]byte, []byte, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	return pubKey[:], privKey[:], err
}

// ed25519Sign creates an Ed25519 signature of a given hash.
func ed25519Sign(privKey, hash []byte) []byte {
	var k [ed25519.PrivateKeySize]byte
	copy(k[:], privKey)
	return ed25519.Sign(&k, hash)[:]
}

// ed25519Verify verifies an Ed25519 signature of a given hash.
func ed25519Verify(pubKey, hash, sig []byte) bool {
	var k [ed25519.PublicKeySize]byte
	copy(k[:], pubKey)

	var s [ed25519.SignatureSize]byte
	copy(s[:], sig)

	return ed25519.Verify(&k, hash, &s)
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
