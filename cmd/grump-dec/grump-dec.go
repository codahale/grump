// grump-dec decrypts Grump files.
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
		pubKeyFile  = flag.String("pub", "", "public key file")
		privKeyFile = flag.String("priv", "", "private key file")
		inFile      = flag.String("in", "", "input file")
		outFile     = flag.String("out", "", "output file")
	)
	flag.Parse()

	var passphrase string
	fmt.Printf("Passphrase: ")
	fmt.Scanln(&passphrase)

	privKey, err := ioutil.ReadFile(*privKeyFile)
	if err != nil {
		die(err)
	}

	sender, err := ioutil.ReadFile(*pubKeyFile)
	if err != nil {
		die(err)
	}

	in, err := os.Open(*inFile)
	if err != nil {
		die(err)
	}
	defer in.Close()

	out, err := os.Create(*outFile)
	if err != nil {
		die(err)
	}
	defer out.Close()

	if err := grump.Decrypt(privKey, passphrase, sender, in, out); err != nil {
		die(err)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
