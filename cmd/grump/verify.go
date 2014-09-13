package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func verify(pubKeyFilename, inFilename, sigFilename string, quiet bool) {
	pubKey, err := ioutil.ReadFile(pubKeyFilename)
	if err != nil {
		die(err)
	}

	sig, err := ioutil.ReadFile(sigFilename)
	if err != nil {
		die(err)
	}

	in, err := os.Open(inFilename)
	if err != nil {
		die(err)
	}
	defer in.Close()

	err = grump.Verify(pubKey, sig, in)
	if err != nil {
		if quiet {
			os.Exit(-1)
		}
		die(err)
	} else {
		if !quiet {
			fmt.Fprintln(os.Stderr, "good signature")
		}
	}
}
