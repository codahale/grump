package main

import (
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func decrypt(args map[string]interface{}) {
	pubKeyName := args["--pub"].([]string)[0]
	privKeyName := args["--priv"].(string)
	inputName := args["<input>"].(string)
	outputName := args["<output>"].(string)
	batch := args["--batch"] == true

	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase: ")
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(privKeyName)
	if err != nil {
		die(err)
	}

	pubKey, err := ioutil.ReadFile(pubKeyName)
	if err != nil {
		die(err)
	}

	in, err := os.Open(inputName)
	if err != nil {
		die(err)
	}
	defer in.Close()

	out, err := os.Create(outputName)
	if err != nil {
		die(err)
	}
	defer out.Close()

	if err := grump.Decrypt(privKey, passphrase, pubKey, in, out); err != nil {
		die(err)
	}
}
