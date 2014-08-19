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
		pubKeyName  = flag.String("recipient", "out.pub", "public key name")
		privKeyName = flag.String("key", "out.priv", "private key name")
		inFile      = flag.String("in", "", "input file name")
		outFile     = flag.String("out", "", "output file name")
	)
	flag.Parse()

	var passphrase []byte
	fmt.Printf("Passphrase: ")
	fmt.Scanln(&passphrase)

	f, err := os.Open(*privKeyName)
	if err != nil {
		die(err)
	}
	defer f.Close()

	_, privKey, err := grump.LoadKeyPair(f, passphrase)
	if err != nil {
		die(err)
	}

	recipStr, err := ioutil.ReadFile(*pubKeyName)
	if err != nil {
		die(err)
	}

	recipient, err := base64.URLEncoding.DecodeString(string(recipStr))
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

	if err := grump.Encrypt(privKey, [][]byte{recipient}, in, out, 1024*1024); err != nil {
		die(err)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
