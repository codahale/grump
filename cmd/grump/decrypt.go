package main

import (
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func decrypt(pubKeyFilename, privKeyFilename, inFilename, outFilename string, batch bool) {

	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase: ")
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(privKeyFilename)
	if err != nil {
		die(err)
	}

	pubKey, err := ioutil.ReadFile(pubKeyFilename)
	if err != nil {
		die(err)
	}

	in, err := os.Open(inFilename)
	if err != nil {
		die(err)
	}
	defer in.Close()

	out, err := os.Create(outFilename)
	if err != nil {
		die(err)
	}
	defer out.Close()

	if err := grump.Decrypt(privKey, passphrase, pubKey, in, out); err != nil {
		die(err)
	}
}
