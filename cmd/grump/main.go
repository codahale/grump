package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func init() {
	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		os.Exit(64)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
	}

	mode := os.Args[1]
	os.Args = os.Args[1:]

	switch mode {
	case "generate":
		generate()
	case "change":
		change()
	case "encrypt":
		encrypt()
	case "decrypt":
		decrypt()
	case "sign":
		sign()
	case "verify":
		verify()
	default:
		printUsage()
	}
}

type fileList []string

func (fl *fileList) Set(s string) error {
	*fl = append(*fl, s)
	return nil
}

func (fl *fileList) String() string {
	return fmt.Sprint([]string(*fl))
}

func printUsage() {
	fmt.Fprintln(
		os.Stderr,
		strings.TrimSpace(`
Available commands:

    generate  generate a new key pair
    change    change the passphrase for a key
    encrypt   encrypt a file
    decrypt   decrypt a file
    sign      sign a file
    verify    verify a file
`),
	)
	os.Exit(64)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}
