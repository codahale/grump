package main

import (
	"flag"
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func decrypt() {
	var (
		pubKeyFile  = flag.String("pub", "", "public key file")
		privKeyFile = flag.String("priv", "", "private key file")
		inFile      = flag.String("in", "", "input file")
		outFile     = flag.String("out", "", "output file")
		passPrompt  = flag.Bool("prompt", true, "prompt for passphrase")
	)
	flag.Parse()

	passphrase, err := grump.ReadPassphrase(*passPrompt, "Passphrase: ")
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(*privKeyFile)
	if err != nil {
		die(err)
	}

	sender, err := ioutil.ReadFile(*pubKeyFile)
	if err != nil {
		die(err)
	}

	in, err := os.Open(*inFile)
	if err != nil {
		die(err)
	}
	defer in.Close()

	out, err := os.Create(*outFile)
	if err != nil {
		die(err)
	}
	defer out.Close()

	if err := grump.Decrypt(privKey, passphrase, sender, in, out); err != nil {
		die(err)
	}
}
