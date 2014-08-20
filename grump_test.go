package grump

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestEndToEnd(t *testing.T) {
	alicePub, alicePriv, err := GenerateKeyPair("alice", 256, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := GenerateKeyPair("bob", 256, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	carolPub, carolPriv, err := GenerateKeyPair("carol", 256, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	_, evePriv, err := GenerateKeyPair("eve", 256, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("this is a lovely way to handle stuff")

	// a message encrypted for Bob and Carol
	encryptedMessage := bytes.NewBuffer(nil)
	if err := Encrypt(
		alicePriv,
		"alice",
		[]PublicKey{bobPub, carolPub},
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
		"bob",
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
		"carol",
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
		"eve",
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
		"carol",
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

func TestGenerateKeyPairBadParams(t *testing.T) {
	pub, priv, err := GenerateKeyPair("woo", -100, 1, 1)

	if pub != nil {
		t.Errorf("Expected no public key, but got %v", pub)
	}

	if priv != nil {
		t.Errorf("Expected no private key, but got %v", priv)
	}

	if err == nil {
		t.Error("Expected an error, but got none")
	}
}

func TestEncryptBadPassphrase(t *testing.T) {
	pub, priv, err := GenerateKeyPair("woo", 256, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := Encrypt(
		priv,
		"yay",
		[]PublicKey{pub},
		bytes.NewReader(nil),
		bytes.NewBuffer(nil),
		16,
	); err != ErrBadPassphrase {
		t.Fatalf("Expected 'bad passphrase', but got %v", err)
	}

}

func TestDecryptBadPassphrase(t *testing.T) {
	pub, priv, err := GenerateKeyPair("woo", 256, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := Decrypt(
		priv,
		"yay",
		pub,
		bytes.NewReader(nil),
		bytes.NewBuffer(nil),
	); err != ErrBadPassphrase {
		t.Fatalf("Expected 'bad passphrase', but got %v", err)
	}

}

func BenchmarkGenerateKeyPair(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		GenerateKeyPair("woo", 1<<20, 8, 1)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	pub, priv, err := GenerateKeyPair("woo", 2, 8, 1)
	if err != nil {
		b.Fatal(err)
	}
	recipients := []PublicKey{pub}
	message := make([]byte, 1024*1024)

	b.SetBytes(1024 * 1024)
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		Encrypt(
			priv,
			"woo",
			recipients,
			bytes.NewReader(message),
			ioutil.Discard,
			1024*64,
		)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pub, priv, err := GenerateKeyPair("woo", 2, 8, 1)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024*1024)
	encryptedMessage := bytes.NewBuffer(nil)
	if err := Encrypt(
		priv, "woo",
		[]PublicKey{pub},
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
			priv, "woo",
			pub,
			bytes.NewReader(message),
			ioutil.Discard,
		)
	}
}
