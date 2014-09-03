package main

import (
	"flag"
	"io/ioutil"

	"github.com/codahale/grump"
)

func change() {
	var (
		n = flag.Int("N", 1<<20, "scrypt iterations")
		r = flag.Int("r", 8, "scrypt block size")
		p = flag.Int("p", 1, "scrypt parallelization factor")

		privKeyName = flag.String("priv", "", "private key name")
	)
	flag.Parse()

	privKey, err := ioutil.ReadFile(*privKeyName)
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

	privKey, err = grump.ChangePassphrase(privKey, oldPassphrase, newPassphrase, *n, *r, *p)
	if err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(*privKeyName, privKey, 0600); err != nil {
		die(err)
	}
}
