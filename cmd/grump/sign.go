package main

import (
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func sign(args map[string]interface{}) {
	privKeyName := args["--priv"].(string)
	inputName := args["<input>"].(string)
	sigName := args["<signature>"].(string)
	batch := args["--batch"] == true

	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase: ")
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(privKeyName)
	if err != nil {
		die(err)
	}

	in, err := os.Open(inputName)
	if err != nil {
		die(err)
	}
	defer in.Close()

	sig, err := os.Create(sigName)
	if err != nil {
		die(err)
	}
	defer sig.Close()

	if err := grump.Sign(privKey, passphrase, in, sig); err != nil {
		die(err)
	}
}
