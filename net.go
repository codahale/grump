package grump

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"time"

	"github.com/codahale/chacha20"
	"github.com/codahale/chacha20poly1305"
	"github.com/codahale/grump/pb"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Listen announces on the local network address laddr, using the given key pair
// and expecting connections from the owner of the given peer key.
//
// The network net must be a stream-oriented network: "tcp", "tcp4", "tcp6",
// "unix" or "unixpacket".
//
// See net.Dial for the syntax of laddr.
func Listen(network, address string, privateKey, passphrase, publicKey, peerKey []byte) (net.Listener, error) {
	var pubKey, prKey pb.PublicKey

	if err := proto.Unmarshal(publicKey, &pubKey); err != nil {
		return nil, err
	}

	if err := proto.Unmarshal(peerKey, &prKey); err != nil {
		return nil, err
	}

	privKey, err := decryptPrivateKey(passphrase, privateKey)
	if err != nil {
		return nil, err
	}

	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &listener{
		listener:   l,
		pubKey:     pubKey.Key,
		privKey:    privKey,
		peerPubKey: prKey.Key,
	}, nil
}

type listener struct {
	listener                    net.Listener
	peerPubKey, pubKey, privKey []byte
}

func (l listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l listener) Close() error {
	return l.listener.Close()
}

func (l listener) Accept() (net.Conn, error) {
	c, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	conn := conn{
		buf:      bytes.NewBuffer(nil),
		conn:     c,
		sent:     sha512.New(),
		received: sha512.New(),
	}
	if err := conn.handshake(
		l.peerPubKey,
		l.privKey,
		l.pubKey,
	); err != nil {
		return nil, err
	}
	return &conn, nil
}

// Dial connects to the address on the named network, using the given key pair
// and expecting to connect to the owner of the given peer key.
func Dial(network, address string, privateKey, passphrase, publicKey, peerKey []byte) (net.Conn, error) {
	var pubKey, prKey pb.PublicKey

	if err := proto.Unmarshal(publicKey, &pubKey); err != nil {
		return nil, err
	}

	if err := proto.Unmarshal(peerKey, &prKey); err != nil {
		return nil, err
	}

	privKey, err := decryptPrivateKey(passphrase, privateKey)
	if err != nil {
		return nil, err
	}

	// connect to server
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	conn := conn{
		buf:      bytes.NewBuffer(nil),
		conn:     c,
		sent:     sha512.New(),
		received: sha512.New(),
	}

	if err := conn.handshake(
		prKey.Key,
		privKey,
		pubKey.Key,
	); err != nil {
		return nil, err
	}
	return &conn, nil
}

type conn struct {
	conn               net.Conn
	buf                *bytes.Buffer
	sending, receiving cipher.AEAD
	sent, received     hash.Hash
}

func (c *conn) handshake(peerPubKey, privKey, pubKey []byte) error {
	// generate a random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	// send it as first part of handshake
	if err := c.writeHandshakeA(nonce); err != nil {
		return err
	}

	// read the nonce from the peer
	peerNonce, err := c.readHandshakeA()
	if err != nil {
		return err
	}

	// generate random EC point
	var x [32]byte
	if _, err := rand.Read(x[:]); err != nil {
		return err
	}

	// multiply by curve base
	var y [32]byte
	curve25519.ScalarBaseMult(&y, &x)

	// create signature of both ECDH presecret and peer nonce
	sig := ed25519Sign(privKey, append(peerNonce, y[:]...))

	// send it as second part of handshake
	if err := c.writeHandshakeB(y[:], sig); err != nil {
		return err
	}

	// read the peer's EC point and signature
	peerY, peerSig, err := c.readHandshakeB()
	if err != nil {
		return err
	}

	// verify the signature of the peer's point and our nonce
	if !ed25519Verify(peerPubKey, append(nonce, peerY[:]...), peerSig) {
		return errors.New("bad handshake")
	}

	// calculate the ECDH shared secret
	var secret [32]byte
	curve25519.ScalarMult(&secret, &x, peerY)

	// derive two keys, one for sending data, one for receiving data
	sendingKey := make([]byte, chacha20.KeySize)
	receivingKey := make([]byte, chacha20.KeySize)

	// sending key is derived from the shared secret w/ HKDF-SHA512 using the
	// peer's public key as the label
	sR := hkdf.New(sha512.New, secret[:], nil, peerPubKey)
	if _, err := io.ReadFull(sR, sendingKey); err != nil {
		return err
	}
	c.sending, _ = chacha20poly1305.New(sendingKey)

	// receiving key is derived from the shared secret w/ HKDF-SHA512 using the
	// agents's public key as the label
	rR := hkdf.New(sha512.New, secret[:], nil, pubKey)
	if _, err := io.ReadFull(rR, receivingKey); err != nil {
		return err
	}
	c.receiving, _ = chacha20poly1305.New(receivingKey)

	return nil
}

func (c *conn) Read(p []byte) (int, error) {
	// handle the read from the buffer if there is any
	if c.buf.Len() > 0 {
		return c.buf.Read(p)
	}

	ad := c.received.Sum(nil)

	// if we don't have enough buffered, read a message
	var msg pb.EncryptedData
	if err := c.readMsg(&msg); err != nil {
		return 0, err
	}

	// decrypt it
	d, err := c.receiving.Open(nil, msg.Nonce, msg.Ciphertext, ad)
	if err != nil {
		// close the connection on tampering
		_ = c.Close()
		return 0, err
	}

	// append the new message to the buffer
	_, _ = c.buf.Write(d)

	// try again!
	return c.Read(p)
}

func (c *conn) Write(p []byte) (int, error) {
	nonce := make([]byte, c.sending.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}

	ctxt := c.sending.Seal(nil, nonce, p, c.sent.Sum(nil))

	return len(p), c.writeMsg(&pb.EncryptedData{
		Nonce:      nonce,
		Ciphertext: ctxt,
	})
}

func (c *conn) writeHandshakeB(y, sig []byte) error {
	msg := &pb.HandshakeB{
		Presecret: y,
		Signature: sig,
	}
	return c.writeMsg(msg)
}

func (c *conn) readHandshakeB() (*[32]byte, []byte, error) {
	var msg pb.HandshakeB
	if err := c.readMsg(&msg); err != nil {
		return nil, nil, err
	}

	var y [32]byte
	copy(y[:], msg.Presecret)
	return &y, msg.Signature, nil
}

func (c *conn) writeHandshakeA(nonce []byte) error {
	return c.writeMsg(&pb.HandshakeA{
		Nonce: nonce,
	})
}

func (c *conn) readHandshakeA() ([]byte, error) {
	var msg pb.HandshakeA
	if err := c.readMsg(&msg); err != nil {
		return nil, err
	}
	return msg.Nonce, nil
}

func (c *conn) writeMsg(msg proto.Message) error {
	buf, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	buf = append(make([]byte, 4), buf...)
	binary.LittleEndian.PutUint32(buf, uint32(len(buf)-4))

	_, err = c.conn.Write(buf)
	_, _ = c.sent.Write(buf)

	return err
}

func (c *conn) readMsg(msg proto.Message) error {
	// read len
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return err
	}
	_, _ = c.received.Write(buf)

	// check frame size
	n := int(binary.LittleEndian.Uint32(buf))
	if n > MaxFrameSize {
		return ErrFrameTooLarge
	}

	// read buf
	buf = make([]byte, n)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return err
	}
	_, _ = c.received.Write(buf)

	return proto.Unmarshal(buf, msg)
}

func (c *conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *conn) Close() error {
	return c.conn.Close()
}
