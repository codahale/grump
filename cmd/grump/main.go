package main

import (
	"fmt"
	"os"

	"github.com/docopt/docopt-go"
)

func main() {
	usage := `Grump is a grumpy cryptosystem for asynchronous messages.

Usage:
  grump generate [--batch] [-N=<int>] [-r=<int>] [-p=<int>] --pub=<file> --priv=<file>
  grump change [-N=<int>] [-r=<int>] [-p=<int>] --priv=<file>
  grump encrypt [--batch] --priv=<file> --pub=<file>... <input> <output>
  grump decrypt [--batch] --priv=<file> --pub=<file> <input> <output>
  grump sign [--batch] --priv=<file> <input> <output>
  grump verify [--quiet] --pub=<file> <input> <signature>

Options:
  -h --help     Show this screen.
  -B --batch    Read the passphrase from stdin rather than prompting.
  -N=<int>      The scrypt iteration factor. [default: 20]
  -r=<int>      The scrypt block size. [default: 8]
  -p=<int>      The scrypt paralleization factor. [default: 1]
  --pub=<file>  A public key.
  --priv=<file> A private key.
  -q --quiet    Don't print anything to stdout.
`
	args, err := docopt.Parse(usage, nil, true, "", false)
	if err != nil {
		panic(err)
	}

	if args["generate"] == true {
		generate(args)
	} else if args["change"] == true {
		change(args)
	} else if args["encrypt"] == true {
		encrypt(args)
	} else if args["decrypt"] == true {
		decrypt(args)
	} else if args["sign"] == true {
		sign(args)
	} else if args["verify"] == true {
		verify(args)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
