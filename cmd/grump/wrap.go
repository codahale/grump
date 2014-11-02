package main

import (
	"io"
	"io/ioutil"
	"log"
	"net"

	"github.com/codahale/grump"
)

func wrap(pubKeyFilename, privKeyFilename, peerKeyFilename, listenAddr, connectAddr string, batch bool) {

	passphrase, err := grump.ReadPassphrase(!batch, "Passphrase: ")
	if err != nil {
		die(err)
	}

	privKey, err := ioutil.ReadFile(privKeyFilename)
	if err != nil {
		die(err)
	}

	pubKey, err := ioutil.ReadFile(pubKeyFilename)
	if err != nil {
		die(err)
	}

	peerKey, err := ioutil.ReadFile(peerKeyFilename)
	if err != nil {
		die(err)
	}

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		die(err)
	}

	for {
		incoming, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		outgoing, err := grump.Dial("tcp", connectAddr, privKey, passphrase, pubKey, peerKey)
		if err != nil {
			log.Println(err)
			continue
		}

		go func() {
			if _, err := io.Copy(outgoing, incoming); err != nil {
				log.Println(err)
			}
		}()

		go func() {
			if _, err := io.Copy(incoming, outgoing); err != nil {
				log.Println(err)
			}
		}()
	}
}
