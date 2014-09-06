package main

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir, err := ioutil.TempDir(os.TempDir(), "woo")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	f, err := os.Open("main.go")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// generate a key pair
	os.Stdin = f
	os.Args = []string{
		"grump",
		"generate",
		"--batch",
		"-N", "4",
		"-r", "16",
		"-p", "2",
		"--pub", path.Join(dir, "tmp.pub"),
		"--priv", path.Join(dir, "tmp.priv"),
	}
	main()

	// encrypt a file
	f, err = os.Open("main.go")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	os.Stdin = f
	os.Args = []string{
		"grump",
		"encrypt",
		"--batch",
		"--pub", path.Join(dir, "tmp.pub"),
		"--pub", "-",
		"--pub", "-",
		"--pub", "-",
		"--priv", path.Join(dir, "tmp.priv"),
		"main.go",
		path.Join(dir, "main.grump"),
	}
	main()

	// decrypt a file
	f, err = os.Open("main.go")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	os.Stdin = f
	os.Args = []string{
		"grump",
		"decrypt",
		"--batch",
		"--pub", path.Join(dir, "tmp.pub"),
		"--priv", path.Join(dir, "tmp.priv"),
		path.Join(dir, "main.grump"),
		path.Join(dir, "main.happy"),
	}
	main()

	// sign a file
	f, err = os.Open("main.go")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	os.Stdin = f
	os.Args = []string{
		"grump",
		"sign",
		"--batch",
		"--priv", path.Join(dir, "tmp.priv"),
		"main.go",
		path.Join(dir, "main.go.sig"),
	}
	main()

	// verify a file
	os.Args = []string{
		"grump",
		"verify",
		"-q",
		"--pub", path.Join(dir, "tmp.pub"),
		"main.go",
		path.Join(dir, "main.go.sig"),
	}
	main()
}
