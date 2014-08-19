package grump

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/goprotobuf/proto"
	"github.com/codahale/chacha20poly1305"
	"github.com/codahale/grump/pb"
)

// PublicKey is a Grump public key. This is a 32-byte Curve25519 point.
type PublicKey []byte

// PrivateKey is a Grump private key. This is a 32-byte Curve25519 point,
// encrypted with ChaCha20Poly1305 using a key derived from a passphrase using
// scrypt.
type PrivateKey []byte

// GenerateKeyPair creates a new Curve25519 key pair and encrypts the private
// key with the given passphrase and scrypt parameters.
func GenerateKeyPair(passphrase string, n, r, p int) (PublicKey, PrivateKey, error) {
	var publicKey, privateKey [32]byte

	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, nil, err
	}

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, n, r, p, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}

	aead, _ := chacha20poly1305.NewChaCha20Poly1305(key)

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := aead.Seal(nil, nonce, privateKey[:], nil)

	pk := &pb.PrivateKey{
		N:          proto.Uint64(uint64(n)),
		R:          proto.Uint64(uint64(r)),
		P:          proto.Uint64(uint64(p)),
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	pkb, err := proto.Marshal(pk)
	if err != nil {
		return nil, nil, err
	}

	return publicKey[:], pkb, nil
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
	chunkSize int,
) error {
	_, privKey, err := loadKeyPair(passphrase, privateKey)
	if err != nil {
		return err
	}

	mw := messageWriter{
		w:       w,
		sizeBuf: make([]byte, 4),
	}

	messageKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(messageKey); err != nil {
		return err
	}

	header, err := generateHeader(privKey, messageKey, recipients)
	if err != nil {
		return err
	}

	aead, _ := chacha20poly1305.NewChaCha20Poly1305(messageKey)

	if err := mw.writeMessage(header); err != nil {
		return err
	}

	id := uint32(1)
	idList := idList{buf: make([]byte, 4)}
	plaintext := make([]byte, chunkSize)
	nonce := make([]byte, aead.NonceSize())

	done := false
	for !done {
		n, err := io.ReadFull(r, plaintext)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			done = true
		} else if err != nil {
			return err
		}

		if _, err := rand.Read(nonce); err != nil {
			return err
		}

		ciphertext := aead.Seal(nil, nonce, plaintext[:n], idList.add(id))

		if err := mw.writeMessage(&pb.Chunk{
			Id:         &id,
			Nonce:      nonce,
			Ciphertext: ciphertext,
		}); err != nil {
			return err
		}

		id++
	}

	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := aead.Seal(nil, nonce, nil, idList.add(id))

	err = mw.writeMessage(&pb.Chunk{
		Id:         &id,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Last:       proto.Bool(true),
	})

	return err
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
	_, privKey, err := loadKeyPair(passphrase, privateKey)
	if err != nil {
		return err
	}

	mr := messageReader{
		r:       r,
		sizeBuf: make([]byte, 4),
		maxSize: 1024 * 1024 * 10,
	}

	var header pb.Header

	if err := mr.readMessage(&header); err != nil {
		return err
	}

	messageKey, err := recoverKey(privKey, sender, &header)
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.NewChaCha20Poly1305(messageKey)
	if err != nil {
		return err
	}

	idList := idList{buf: make([]byte, 4)}
	var chunk pb.Chunk

	for {
		if err := mr.readMessage(&chunk); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		ad := idList.add(chunk.GetId())
		plaintext, err := aead.Open(nil, chunk.Nonce, chunk.Ciphertext, ad)
		if err != nil {
			return err
		}

		if _, err := w.Write(plaintext); err != nil {
			return err
		}

		if chunk.Last != nil && *chunk.Last {
			break
		}
	}

	return nil
}

func loadKeyPair(passphrase string, buf []byte) ([]byte, []byte, error) {
	var pk pb.PrivateKey
	if err := proto.Unmarshal(buf, &pk); err != nil {
		return nil, nil, err
	}

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

	privateKey, err := aead.Open(nil, pk.Nonce, pk.Ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}

	var pubKey, privKey [32]byte
	copy(privKey[:], privateKey)

	curve25519.ScalarBaseMult(&pubKey, &privKey)

	return pubKey[:], privateKey, nil
}

func generateHeader(privateKey PrivateKey, messageKey []byte, recipients []PublicKey) (*pb.Header, error) {
	keys := make([]*pb.Header_Key, len(recipients))

	for i, recipientKey := range recipients {
		aead := sharedSecretAEAD(privateKey, recipientKey)

		// generate a random nonce
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		// and encrypt the message key
		keys[i] = &pb.Header_Key{
			Nonce:      nonce,
			Ciphertext: aead.Seal(nil, nonce, messageKey, nil),
		}
	}

	return &pb.Header{Keys: keys}, nil
}

func recoverKey(privateKey PrivateKey, senderKey PublicKey, header *pb.Header) ([]byte, error) {
	aead := sharedSecretAEAD(privateKey, senderKey)

	for _, k := range header.Keys {
		key, err := aead.Open(nil, k.Nonce, k.Ciphertext, nil)
		if err == nil {
			return key, nil
		}
	}

	return nil, errors.New("no suitable key was found")
}

// sharedSecret returns a ChaCha20Poly1305 AEAD keyed with the SHA-256 hash of
// the Curve25519 ECDH shared secret for the two keys.
func sharedSecretAEAD(privateKey PrivateKey, publicKey PublicKey) cipher.AEAD {
	// perform Curve25519 ECDH
	var privKey, pubKey, sharedKey [32]byte
	copy(privKey[:], privateKey)
	copy(pubKey[:], publicKey)
	curve25519.ScalarMult(&sharedKey, &privKey, &pubKey)

	// run that through SHA-256
	h := sha256.New()
	_, _ = h.Write(sharedKey[:])

	// use as key for ChaCha20Poly1305
	aead, _ := chacha20poly1305.NewChaCha20Poly1305(h.Sum(nil))
	return aead
}

type messageReader struct {
	r            io.Reader
	sizeBuf, buf []byte
	maxSize      int
}

func (mr messageReader) readMessage(msg proto.Message) error {
	if _, err := io.ReadFull(mr.r, mr.sizeBuf); err != nil {
		return err
	}

	size := int(binary.LittleEndian.Uint32(mr.sizeBuf))
	if size > mr.maxSize {
		return errors.New("frame too large")
	}

	if len(mr.buf) < size {
		mr.buf = make([]byte, size)
	}

	if _, err := io.ReadFull(mr.r, mr.buf); err != nil {
		return err
	}

	return proto.Unmarshal(mr.buf, msg)
}

type messageWriter struct {
	w       io.Writer
	sizeBuf []byte
}

func (mw messageWriter) writeMessage(msg proto.Message) error {
	buf, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(mw.sizeBuf, uint32(len(buf)))

	if _, err := mw.w.Write(mw.sizeBuf); err != nil {
		return err
	}

	_, err = mw.w.Write(buf)
	return err
}

type idList struct {
	data, buf []byte
}

func (l *idList) add(id uint32) []byte {
	binary.LittleEndian.PutUint32(l.buf, id)
	l.data = append(l.data, l.buf...)
	return l.data
}
