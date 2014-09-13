package main

import (
	"fmt"
	"os"
	"strconv"

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
		n, err := strconv.ParseUint(args["-N"].(string), 10, 64)
		if err != nil {
			die(err)
		}

		r, err := strconv.ParseUint(args["-r"].(string), 10, 64)
		if err != nil {
			die(err)
		}

		p, err := strconv.ParseUint(args["-p"].(string), 10, 64)
		if err != nil {
			die(err)
		}

		generate(
			uint(n), uint(r), uint(p),
			args["--pub"].([]string)[0],
			args["--priv"].(string),
			args["--batch"] == true,
		)
	} else if args["change"] == true {
		n, err := strconv.ParseUint(args["-N"].(string), 10, 64)
		if err != nil {
			die(err)
		}

		r, err := strconv.ParseUint(args["-r"].(string), 10, 64)
		if err != nil {
			die(err)
		}

		p, err := strconv.ParseUint(args["-p"].(string), 10, 64)
		if err != nil {
			die(err)
		}

		change(uint(n), uint(r), uint(p), args["--priv"].(string))
	} else if args["encrypt"] == true {
		encrypt(
			args["--pub"].([]string),
			args["--priv"].(string),
			args["<input>"].(string),
			args["<output>"].(string),
			args["--batch"] == true,
		)
	} else if args["decrypt"] == true {
		decrypt(
			args["--pub"].([]string)[0],
			args["--priv"].(string),
			args["<input>"].(string),
			args["<output>"].(string),
			args["--batch"] == true,
		)
	} else if args["sign"] == true {
		sign(
			args["--priv"].(string),
			args["<input>"].(string),
			args["<output>"].(string),
			args["--batch"] == true,
		)
	} else if args["verify"] == true {
		verify(
			args["--pub"].([]string)[0],
			args["<input>"].(string),
			args["<signature>"].(string),
			args["--quiet"] == true,
		)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
