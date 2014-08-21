// grump-verify verifies signatures of files.
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
		pubKeyFile = flag.String("pub", "", "public key file")
		inFile     = flag.String("in", "", "input file")
		sigFile    = flag.String("sig", "", "signature file")
	)
	flag.Parse()

	pubKey, err := ioutil.ReadFile(*pubKeyFile)
	if err != nil {
		die(err)
	}

	signature, err := ioutil.ReadFile(*sigFile)
	if err != nil {
		die(err)
	}

	in, err := os.Open(*inFile)
	if err != nil {
		die(err)
	}
	defer in.Close()

	if err := grump.Verify(pubKey, in, signature); err != nil {
		die(err)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
