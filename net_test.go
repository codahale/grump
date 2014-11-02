package grump_test

import (
	"bufio"
	"fmt"
	"reflect"
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

		if _, err := fmt.Fprintln(conn, "this is the server."); err != nil {
			t.Fatal(err)
		}
	}()

	conn, err := grump.Dial("tcp", l.Addr().String(), privB, []byte("two"), pubB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var data []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		data = append(data, scanner.Text())
	}

	expected := []string{"this is the server."}
	if !reflect.DeepEqual(expected, data) {
		t.Errorf("Was %v but expected %v", data, expected)
	}
}
