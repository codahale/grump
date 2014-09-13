package main

import (
	"io/ioutil"

	"github.com/codahale/grump"
)

func generate(n, r, p uint, pubKeyFilename, privKeyFilename string, batch bool) {
	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase: ")
	if err != nil {
		die(err)
	}

	pubKey, privKey, err := grump.GenerateKeyPair(passphrase, n, r, p)
	if err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(pubKeyFilename, pubKey, 0644); err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(privKeyFilename, privKey, 0600); err != nil {
		die(err)
	}
}
