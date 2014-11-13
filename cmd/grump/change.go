package main

import (
	"io/ioutil"

	"github.com/codahale/grump"
)

func change(n, r, p uint, privKeyFilename string) {
	privKey, err := ioutil.ReadFile(privKeyFilename)
	if err != nil {
		die(err)
	}

	oldPass, err := grump.ReadPassphrase(true, "Old passphrase")
	if err != nil {
		die(err)
	}

	newPass, err := grump.ReadPassphrase(true, "New passphrase")
	if err != nil {
		die(err)
	}

	privKey, err = grump.ChangePassphrase(privKey, oldPass, newPass, n, r, p)
	if err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(privKeyFilename, privKey, 0600); err != nil {
		die(err)
	}
}
