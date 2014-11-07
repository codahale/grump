package grump

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	alicePub, alicePriv, err := GenerateKeyPair([]byte("alice"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := GenerateKeyPair([]byte("bob"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	carolPub, carolPriv, err := GenerateKeyPair([]byte("carol"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	_, evePriv, err := GenerateKeyPair([]byte("eve"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("this is a lovely way to handle stuff")

	// a message encrypted for Bob and Carol
	encryptedMessage := bytes.NewBuffer(nil)
	if err := Encrypt(
		alicePriv,
		[]byte("alice"),
		[][]byte{bobPub, carolPub, nil, nil},
		bytes.NewReader(message),
		encryptedMessage,
		16,
	); err != nil {
		t.Fatal(err)
	}

	// Bob can decrypt the message
	bobMessage := bytes.NewBuffer(nil)
	if err := Decrypt(
		bobPriv,
		[]byte("bob"),
		alicePub,
		bytes.NewReader(encryptedMessage.Bytes()),
		bobMessage,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, bobMessage.Bytes()) {
		t.Fatalf("Bob expected %v, but decrypted %v", message, bobMessage.Bytes())
	}

	// Carol can decrypt the message
	carolMessage := bytes.NewBuffer(nil)
	if err := Decrypt(
		carolPriv,
		[]byte("carol"),
		alicePub,
		bytes.NewReader(encryptedMessage.Bytes()),
		carolMessage,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, carolMessage.Bytes()) {
		t.Fatalf("Carol expected %v, but decrypted %v", message, carolMessage.Bytes())
	}

	// Eve cannot decrypt the message
	eveMessage := bytes.NewBuffer(nil)
	if err := Decrypt(
		evePriv,
		[]byte("eve"),
		alicePub,
		bytes.NewReader(encryptedMessage.Bytes()),
		eveMessage,
	); err != ErrNotDecryptable {
		t.Fatalf(
			"Eve shouldn't have been able to decrypt the message, but got %v (%v)",
			eveMessage.Bytes(), err,
		)
	}

	// Mallory cannot modify the message
	modifiedMessage := encryptedMessage.Bytes()
	modifiedMessage[300] ^= 32 // boop
	malloryMessage := bytes.NewBuffer(nil)
	if err := Decrypt(
		carolPriv,
		[]byte("carol"),
		alicePub,
		bytes.NewReader(encryptedMessage.Bytes()),
		malloryMessage,
	); err != ErrBadSignature {
		t.Fatalf(
			"Mallory shouldn't have been able to modify the message, but Carol got %v (%v)",
			malloryMessage.Bytes(), err,
		)
	}
}

func TestChangePassphrase(t *testing.T) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	newPriv, err := ChangePassphrase(priv, []byte("woo"), []byte("yay"), 10, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("this is a lovely way to handle stuff")
	encryptedMessage := bytes.NewBuffer(nil)
	if err := Encrypt(
		priv,
		[]byte("woo"),
		[][]byte{pub},
		bytes.NewReader(message),
		encryptedMessage,
		16,
	); err != nil {
		t.Fatal(err)
	}

	newMessage := bytes.NewBuffer(nil)
	if err := Decrypt(
		newPriv,
		[]byte("yay"),
		pub,
		bytes.NewReader(encryptedMessage.Bytes()),
		newMessage,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, newMessage.Bytes()) {
		t.Fatalf("Expected %v, but decrypted %v", message, newMessage.Bytes())
	}
}

func TestEncryptBadPassphrase(t *testing.T) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := Encrypt(
		priv,
		[]byte("yay"),
		[][]byte{pub},
		bytes.NewReader(nil),
		bytes.NewBuffer(nil),
		16,
	); err != ErrBadPassphrase {
		t.Fatalf("Expected 'bad passphrase', but got %v", err)
	}
}

func TestDecryptBadPassphrase(t *testing.T) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := Decrypt(
		priv,
		[]byte("yay"),
		pub,
		bytes.NewReader(nil),
		bytes.NewBuffer(nil),
	); err != ErrBadPassphrase {
		t.Fatalf("Expected 'bad passphrase', but got %v", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	message := make([]byte, 1024*1024)
	signature := bytes.NewBuffer(nil)
	if err := Sign(
		priv,
		[]byte("woo"),
		bytes.NewReader(message),
		signature,
	); err != nil {
		t.Fatal(err)
	}

	if err := Verify(
		pub,
		signature.Bytes(),
		bytes.NewReader(message),
	); err != nil {
		t.Fatal(err)
	}

	// shouldn't verify a bad message
	badMessage := make([]byte, len(message))
	badMessage[100] ^= 90
	if err := Verify(
		pub,
		signature.Bytes(),
		bytes.NewReader(badMessage),
	); err == nil {
		t.Fatalf("Expected ErrBadSignature, but no error was returned")
	}

	// shouldn't verify a bad signature
	badSignature := signature.Bytes()
	badSignature[1] ^= 90
	if err := Verify(
		pub,
		badSignature,
		bytes.NewReader(message),
	); err == nil {
		t.Fatalf("Expected ErrBadSignature, but no error was returned")
	}
}

func TestSignAndVerifyBadMessage(t *testing.T) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 8, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	message := make([]byte, 1024*1024)
	signature := bytes.NewBuffer(nil)
	if err := Sign(
		priv,
		[]byte("woo"),
		bytes.NewReader(message),
		signature,
	); err != nil {
		t.Fatal(err)
	}
	message[100] ^= 90

	if err := Verify(
		pub,
		signature.Bytes(),
		bytes.NewReader(message),
	); err == nil {
		t.Fatalf("Expected ErrBadSignature, but no error was returned")
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		GenerateKeyPair([]byte("woo"), 20, 8, 1)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 2, 8, 1)
	if err != nil {
		b.Fatal(err)
	}
	recipients := [][]byte{pub}
	message := make([]byte, 1024*1024)

	b.SetBytes(1024 * 1024)
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		Encrypt(
			priv,
			[]byte("woo"),
			recipients,
			bytes.NewReader(message),
			ioutil.Discard,
			1024*64,
		)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 2, 8, 1)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024*1024)
	encryptedMessage := bytes.NewBuffer(nil)
	if err := Encrypt(
		priv,
		[]byte("woo"),
		[][]byte{pub},
		bytes.NewReader(message),
		encryptedMessage,
		1024*64,
	); err != nil {
		b.Fatal(err)
	}
	message = encryptedMessage.Bytes()

	b.SetBytes(1024 * 1024)
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		Decrypt(
			priv,
			[]byte("woo"),
			pub,
			bytes.NewReader(message),
			ioutil.Discard,
		)
	}
}

func BenchmarkSign(b *testing.B) {
	_, priv, err := GenerateKeyPair([]byte("woo"), 2, 8, 1)
	if err != nil {
		b.Fatal(err)
	}
	message := make([]byte, 1024*1024)

	b.SetBytes(1024 * 1024)
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		Sign(
			priv,
			[]byte("woo"),
			bytes.NewReader(message),
			ioutil.Discard,
		)
	}
}

func BenchmarkVerify(b *testing.B) {
	pub, priv, err := GenerateKeyPair([]byte("woo"), 2, 8, 1)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024*1024)
	signature := bytes.NewBuffer(nil)
	if err := Sign(
		priv,
		[]byte("woo"),
		bytes.NewReader(message),
		signature,
	); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(1024 * 1024)
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		Verify(
			pub,
			signature.Bytes(),
			bytes.NewReader(message),
		)
	}
}
