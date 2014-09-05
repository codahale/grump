package main

import (
	"io/ioutil"
	"strconv"

	"github.com/codahale/grump"
)

func generate(args map[string]interface{}) {
	n, err := strconv.ParseUint(args["-N"].(string), 10, 64)
	if err != nil {
		die(err)
	}

	r, err := strconv.Atoi(args["-r"].(string))
	if err != nil {
		die(err)
	}

	p, err := strconv.Atoi(args["-p"].(string))
	if err != nil {
		die(err)
	}

	batch := args["--batch"] == true
	pubKeyName := args["--pub"].([]string)[0]
	privKeyName := args["--priv"].(string)

	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase: ")
	if err != nil {
		die(err)
	}

	pubKey, privKey, err := grump.GenerateKeyPair(passphrase, 1<<uint(n), r, p)
	if err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(pubKeyName, pubKey, 0644); err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(privKeyName, privKey, 0600); err != nil {
		die(err)
	}
}
