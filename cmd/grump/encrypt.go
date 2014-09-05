package main

import (
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func encrypt(args map[string]interface{}) {
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

	var recipients [][]byte
	for _, filename := range args["--pub"].([]string) {
		if filename == "-" {
			// generate a fake recipient
			recipients = append(recipients, nil)
		} else {
			recipient, err := ioutil.ReadFile(filename)
			if err != nil {
				die(err)
			}
			recipients = append(recipients, recipient)
		}
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

	if err := grump.Encrypt(
		privKey,
		passphrase,
		recipients,
		in,
		out,
		1024*1024,
	); err != nil {
		die(err)
	}
}
