// grump-enc encrypts files using Grump keys.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/codahale/grump"
)

func main() {
	var (
		privKeyName = flag.String("priv", "", "private key name")
		inFile      = flag.String("in", "", "input file name")
		outFile     = flag.String("out", "", "output file name")

		pubKeys fileList
	)
	flag.Var(&pubKeys, "pub", "public key (use '-' for a fake recipient)")
	flag.Parse()

	var passphrase string
	fmt.Printf("Passphrase: ")
	fmt.Scanln(&passphrase)

	privKey, err := ioutil.ReadFile(*privKeyName)
	if err != nil {
		die(err)
	}

	var recipients []grump.PublicKey
	for _, filename := range pubKeys {
		if filename == "-" { // generate a fake recipient
			recipient := make([]byte, 32)
			if _, err := rand.Read(recipient); err != nil {
				die(err)
			}
			recipients = append(recipients, recipient)
		} else {
			recipient, err := ioutil.ReadFile(filename)
			if err != nil {
				die(err)
			}
			recipients = append(recipients, recipient)
		}
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

	if err := grump.Encrypt(
		privKey,
		passphrase,
		recipients,
		in,
		out,
		1024*1024,
	); err != nil {
		die(err)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}

type fileList []string

func (fl *fileList) Set(s string) error {
	*fl = append(*fl, s)
	return nil
}

func (fl *fileList) String() string {
	return fmt.Sprint([]string(*fl))
}
