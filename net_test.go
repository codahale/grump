package grump_test

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/codahale/grump"
)

func TestSockets(t *testing.T) {
	pubA, privA, err := grump.GenerateKeyPair([]byte("one"), 2, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	pubB, privB, err := grump.GenerateKeyPair([]byte("two"), 2, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	l, err := grump.Listen("tcp", ":0", privA, []byte("one"), pubA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		data := expected
		for len(data) > 0 {
			if _, err := conn.Write(data[:256]); err != nil {
				t.Fatal(err)
			}
			data = data[256:]
		}
	}()

	conn, err := grump.Dial("tcp", l.Addr().String(), privB, []byte("two"), pubB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	actual, err := ioutil.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(actual, expected) {
		t.Fatal("Didn't receive exactly what was sent")
	}
}

var (
	expected = make([]byte, 1024*256)
)

func init() {
	for i := range expected {
		expected[i] = byte(i)
	}
}
