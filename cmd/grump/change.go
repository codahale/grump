package main

import (
	"io/ioutil"
	"strconv"

	"github.com/codahale/grump"
)

func change(args map[string]interface{}) {
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

	privKeyName := args["--priv"].(string)

	privKey, err := ioutil.ReadFile(privKeyName)
	if err != nil {
		die(err)
	}

	oldPassphrase, err := grump.ReadPassphrase(true, "Old passphrase: ")
	if err != nil {
		die(err)
	}

	newPassphrase, err := grump.ReadPassphrase(true, "New passphrase: ")
	if err != nil {
		die(err)
	}

	privKey, err = grump.ChangePassphrase(privKey, oldPassphrase, newPassphrase, 1<<uint(n), r, p)
	if err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(privKeyName, privKey, 0600); err != nil {
		die(err)
	}
}
