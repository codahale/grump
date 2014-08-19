package grump

import (
	"bytes"
	"crypto/rand"
	"testing"

	"code.google.com/p/go.crypto/curve25519"
)

func BenchmarkGenerateHeader(b *testing.B) {
	sender := genKeyPair()
	messageKey := make([]byte, 32)
	recipients := [][]byte{
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		generateHeader(sender.privateKey, messageKey, recipients)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	sender := genKeyPair()
	data := make([]byte, 1024*1024*10)
	buf := bytes.NewBuffer(make([]byte, 1024*1024*15))
	recipients := [][]byte{
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Encrypt(sender.privateKey, recipients, bytes.NewReader(data), buf, 1024*10)
	}
}

func TestEncryptThenDecrypt(t *testing.T) {
	sender := genKeyPair()
	recipient := genKeyPair()
	recipients := [][]byte{
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		recipient.publicKey,
	}

	data := make([]byte, 1024)
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	if err := Encrypt(sender.privateKey, recipients, bytes.NewReader(data), buf, 256); err != nil {
		t.Fatal(err)
	}

	data = buf.Bytes()
	buf = bytes.NewBuffer(nil)
	if err := Decrypt(recipient.privateKey, sender.publicKey, bytes.NewReader(data), buf); err != nil {
		t.Fatal(err)
	}

	t.Logf("%v", buf.Bytes())
}

func BenchmarkRecoverKey(b *testing.B) {
	sender := genKeyPair()
	messageKey := make([]byte, 32)
	recipient := genKeyPair()
	recipients := [][]byte{
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		genKeyPair().publicKey,
		recipient.publicKey,
	}

	h, err := generateHeader(sender.privateKey, messageKey, recipients)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		recoverKey(recipient.privateKey, sender.publicKey, h)
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	sender := genKeyPair()
	rando := genKeyPair()
	recipients := []keyPair{
		genKeyPair(),
		genKeyPair(),
		genKeyPair(),
		genKeyPair(),
	}
	messageKey := "yay for me"
	recipientPKs := make([][]byte, len(recipients))
	for i, kp := range recipients {
		recipientPKs[i] = kp.publicKey
	}

	h, err := generateHeader(sender.privateKey, []byte(messageKey), recipientPKs)
	if err != nil {
		t.Error(err)
	}

	for _, kp := range recipients {
		mk, err := recoverKey(kp.privateKey, sender.publicKey, h)
		if err != nil {
			t.Error(err)
		}

		if string(mk) != messageKey {
			t.Fatalf("Bad recovery: %#v, %#v, %#v for %#v", sender, recipients, h, kp)
		}
	}

	randoKey, err := recoverKey(rando.privateKey, sender.publicKey, h)
	if err == nil {
		t.Errorf("Rando was able to recover key: %v", randoKey)
	}

	mistakenKey, err := recoverKey(recipients[0].privateKey, rando.publicKey, h)
	if err == nil {
		t.Errorf("Recipient was able to recover key from rando: %v", mistakenKey)
	}
}

type keyPair struct {
	privateKey, publicKey []byte
}

func genKeyPair() keyPair {
	var publicKey, privateKey [32]byte

	if _, err := rand.Read(privateKey[:]); err != nil {
		panic(err)
	}

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return keyPair{publicKey: publicKey[:], privateKey: privateKey[:]}
}
