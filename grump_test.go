package grump

import (
	"bytes"
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

	// Alice can decrypt the message
	aliceMessage := bytes.NewBuffer(nil)
	if err := Decrypt(
		alicePriv,
		"alice",
		bobPub, // she needs to pretend the message was from Bob
		bytes.NewReader(encryptedMessage.Bytes()),
		aliceMessage,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, aliceMessage.Bytes()) {
		t.Fatalf("Alice expected %v, but decrypted %v", message, aliceMessage.Bytes())
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
	); err == nil {
		t.Fatalf(
			"Eve shouldn't have been able to decrypt the message, but got %v",
			eveMessage.Bytes(),
		)
	}

	// Mallory cannot modify the message
	modifiedMessage := encryptedMessage.Bytes()
	modifiedMessage[90] ^= 32 // boop
	malloryMessage := bytes.NewBuffer(nil)
	if err := Decrypt(
		carolPriv,
		"carol",
		alicePub,
		bytes.NewReader(encryptedMessage.Bytes()),
		malloryMessage,
	); err == nil {
		t.Fatalf(
			"Mallory shouldn't have been able to modify the message, but Carol got %v",
			malloryMessage.Bytes(),
		)
	}
}
