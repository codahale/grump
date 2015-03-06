// Code generated by protoc-gen-go.
// source: grump.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	grump.proto

It has these top-level messages:
	Header
	Packet
	Signature
	PublicKey
	PrivateKey
	EncryptedData
	HandshakeA
	HandshakeB
*/
package pb

import proto "github.com/golang/protobuf/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal

// The header is the first structure in a Grump message, and contains a set of
// encrypted copies of the message key.
type Header struct {
	// For each intended recipient of the message, a copy of the message key is
	// added here, encrypted with the HKDF-SHA-512 output of the X25519 shared
	// secret produced with the author's private key and the recipient's public
	// key.
	//
	// The recipients of a message are not identified via metadata. To decrypt a
	// session key, the recipients must iterate through the keys and try
	// decrypting each of them. Unused, random keys may be added to this set to
	// confound additional metadata analysis.
	Keys []*EncryptedData `protobuf:"bytes,1,rep,name=keys" json:"keys,omitempty"`
}

func (m *Header) Reset()         { *m = Header{} }
func (m *Header) String() string { return proto.CompactTextString(m) }
func (*Header) ProtoMessage()    {}

func (m *Header) GetKeys() []*EncryptedData {
	if m != nil {
		return m.Keys
	}
	return nil
}

// The body of the message consists of data packets, which are portions of the
// original message, encrypted with the message key, and using the SHA-512 hash
// of all the bytes in the message which precede it as the authenticated data.
type Packet struct {
	Data *EncryptedData `protobuf:"bytes,1,opt,name=data" json:"data,omitempty"`
	Last bool           `protobuf:"varint,2,opt,name=last" json:"last,omitempty"`
}

func (m *Packet) Reset()         { *m = Packet{} }
func (m *Packet) String() string { return proto.CompactTextString(m) }
func (*Packet) ProtoMessage()    {}

func (m *Packet) GetData() *EncryptedData {
	if m != nil {
		return m.Data
	}
	return nil
}

// The final part of a message is the Ed25519 signature of the SHA-512 hash of
// all bytes in the message which precede the signature's frame.
type Signature struct {
	Signature []byte `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *Signature) Reset()         { *m = Signature{} }
func (m *Signature) String() string { return proto.CompactTextString(m) }
func (*Signature) ProtoMessage()    {}

// Public keys are stored in the clear.
type PublicKey struct {
	Key []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
}

func (m *PublicKey) Reset()         { *m = PublicKey{} }
func (m *PublicKey) String() string { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()    {}

// Private keys are stored encrypted with a key derived via scrypt from a
// passphrase.
type PrivateKey struct {
	N    uint64         `protobuf:"varint,1,opt" json:"N,omitempty"`
	R    uint64         `protobuf:"varint,2,opt,name=r" json:"r,omitempty"`
	P    uint64         `protobuf:"varint,3,opt,name=p" json:"p,omitempty"`
	Salt []byte         `protobuf:"bytes,4,opt,name=salt,proto3" json:"salt,omitempty"`
	Key  *EncryptedData `protobuf:"bytes,5,opt,name=key" json:"key,omitempty"`
}

func (m *PrivateKey) Reset()         { *m = PrivateKey{} }
func (m *PrivateKey) String() string { return proto.CompactTextString(m) }
func (*PrivateKey) ProtoMessage()    {}

func (m *PrivateKey) GetKey() *EncryptedData {
	if m != nil {
		return m.Key
	}
	return nil
}

// Data encrypted with ChaCha290Poly1305.
type EncryptedData struct {
	Nonce      []byte `protobuf:"bytes,1,opt,name=nonce,proto3" json:"nonce,omitempty"`
	Ciphertext []byte `protobuf:"bytes,2,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
}

func (m *EncryptedData) Reset()         { *m = EncryptedData{} }
func (m *EncryptedData) String() string { return proto.CompactTextString(m) }
func (*EncryptedData) ProtoMessage()    {}

// The first half of a handshake.
type HandshakeA struct {
	Nonce []byte `protobuf:"bytes,1,opt,name=nonce,proto3" json:"nonce,omitempty"`
}

func (m *HandshakeA) Reset()         { *m = HandshakeA{} }
func (m *HandshakeA) String() string { return proto.CompactTextString(m) }
func (*HandshakeA) ProtoMessage()    {}

// The second half of a handshake.
type HandshakeB struct {
	Presecret []byte `protobuf:"bytes,1,opt,name=presecret,proto3" json:"presecret,omitempty"`
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *HandshakeB) Reset()         { *m = HandshakeB{} }
func (m *HandshakeB) String() string { return proto.CompactTextString(m) }
func (*HandshakeB) ProtoMessage()    {}

func init() {
}
