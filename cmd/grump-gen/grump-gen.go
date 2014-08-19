package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func main() {
	var (
		n = flag.Int("N", 1<<20, "scrypt iterations")
		r = flag.Int("r", 8, "scrypt block size")
		p = flag.Int("p", 1, "scrypt parallelization factor")

		pubKeyName  = flag.String("pub", "out.pub", "public key name")
		privKeyName = flag.String("priv", "out.priv", "private key name")
	)
	flag.Parse()

	var passphrase string
	fmt.Printf("Passphrase: ")
	fmt.Scanln(&passphrase)

	pubKey, privKey, err := grump.GenerateKeyPair(passphrase, *n, *r, *p)
	if err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(*pubKeyName, pubKey, 0644); err != nil {
		die(err)
	}

	if err := ioutil.WriteFile(*privKeyName, privKey, 0600); err != nil {
		die(err)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
