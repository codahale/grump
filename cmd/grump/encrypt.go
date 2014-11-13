package main

import (
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func encrypt(pubKeyFilenames []string, privKeyFilename, inFilename, outFilename string, batch bool) {
	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase")
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(privKeyFilename)
	if err != nil {
		die(err)
	}

	var recipients [][]byte
	for _, filename := range pubKeyFilenames {
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
