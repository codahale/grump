package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func verify(args map[string]interface{}) {
	pubKeyName := args["--pub"].([]string)[0]
	inputName := args["<input>"].(string)
	sigName := args["<signature>"].(string)
	quiet := args["--quiet"] == true

	pubKey, err := ioutil.ReadFile(pubKeyName)
	if err != nil {
		die(err)
	}

	signature, err := ioutil.ReadFile(sigName)
	if err != nil {
		die(err)
	}

	in, err := os.Open(inputName)
	if err != nil {
		die(err)
	}
	defer in.Close()

	err = grump.Verify(pubKey, signature, in)
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
