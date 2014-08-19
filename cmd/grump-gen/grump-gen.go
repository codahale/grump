package main

import (
	"encoding/base64"
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

		pubKeyName  = flag.String("pub-key", "out.pub", "public key name")
		privKeyName = flag.String("priv-key", "out.priv", "private key name")
	)
	flag.Parse()

	var passphrase []byte
	fmt.Printf("Passphrase: ")
	fmt.Scanln(&passphrase)

	pubKey, privKey, err := grump.GenerateKeyPair(passphrase, *n, *r, *p)
	if err != nil {
		die(err)
	}

	b64 := base64.URLEncoding.EncodeToString(pubKey)
	if err := ioutil.WriteFile(*pubKeyName, []byte(b64), 0600); err != nil {
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
