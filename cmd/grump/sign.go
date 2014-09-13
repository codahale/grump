package main

import (
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func sign(privKeyFilename, inFilename, sigFilename string, batch bool) {
	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase: ")
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(privKeyFilename)
	if err != nil {
		die(err)
	}

	in, err := os.Open(inFilename)
	if err != nil {
		die(err)
	}
	defer in.Close()

	sig, err := os.Create(sigFilename)
	if err != nil {
		die(err)
	}
	defer sig.Close()

	if err := grump.Sign(privKey, passphrase, in, sig); err != nil {
		die(err)
	}
}
