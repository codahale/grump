package grump_test

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
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

	data := make(chan string, 100)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		if _, err := fmt.Fprintln(conn, "this is the server."); err != nil {
			t.Fatal(err)
		}

		b := make([]byte, len("this is the client!\n"))

		if _, err := conn.Read(b); err != nil {
			t.Fatal(err)
		}

		wg.Done()

		data <- string(b)
	}()

	conn, err := grump.Dial("tcp", l.Addr().String(), privB, []byte("two"), pubB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, "this is the client!"); err != nil {
		t.Fatal(err)
	}

	b := make([]byte, len("this is the server.\n"))

	if _, err := conn.Read(b); err != nil {
		t.Fatal(err)
	}

	data <- string(b)

	wg.Wait()
	close(data)

	var v []string
	for s := range data {
		v = append(v, s)
	}
	sort.Strings(v)

	expected := []string{
		"this is the client!\n",
		"this is the server.\n",
	}

	if !reflect.DeepEqual(v, expected) {
		t.Errorf("Was %#v, but expected %#v", v, expected)
	}
}
