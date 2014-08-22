// grump-sign creates signatures for files.
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
		privKeyFile = flag.String("priv", "", "private key name")
		inFile      = flag.String("in", "", "input file name")
		sigFile     = flag.String("sig", "", "signature file name")
		passPrompt  = flag.Bool("prompt", true, "prompt for passphrase")
	)
	flag.Parse()

	passphrase, err := grump.ReadPassphrase(*passPrompt)
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(*privKeyFile)
	if err != nil {
		die(err)
	}

	in, err := os.Open(*inFile)
	if err != nil {
		die(err)
	}
	defer in.Close()

	sig, err := os.Create(*sigFile)
	if err != nil {
		die(err)
	}
	defer sig.Close()

	if err := grump.Sign(privKey, passphrase, in, sig); err != nil {
		die(err)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
