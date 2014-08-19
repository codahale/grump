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
		pubKeyName  = flag.String("pub", "", "public key name")
		privKeyName = flag.String("priv", "", "private key name")
		inFile      = flag.String("in", "", "input file name")
		outFile     = flag.String("out", "", "output file name")
	)
	flag.Parse()

	var passphrase string
	fmt.Printf("Passphrase: ")
	fmt.Scanln(&passphrase)

	privKey, err := ioutil.ReadFile(*privKeyName)
	if err != nil {
		die(err)
	}

	sender, err := ioutil.ReadFile(*pubKeyName)
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
