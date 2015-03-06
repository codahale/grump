package grump

import (
	"encoding/binary"
	"hash"
	"io"

	"github.com/golang/protobuf/proto"
)

// framedReader reads protobuf messages, framed with a 32-bit little-endian
// length prefix.
type framedReader struct {
	r            io.Reader
	sizeBuf, buf []byte
	h            hash.Hash
}

// digest returns the SHA-512 digest of all the data written.
func (fr framedReader) digest() []byte {
	return fr.h.Sum(nil)
}

// readMessage reads the next message in the reader into the given protobuf.
func (fr framedReader) readMessage(msg proto.Message) error {
	if _, err := io.ReadFull(fr.r, fr.sizeBuf); err != nil {
		return err
	}

	size := int(binary.LittleEndian.Uint32(fr.sizeBuf))
	if size > MaxFrameSize {
		return ErrFrameTooLarge
	}

	if len(fr.buf) < size {
		fr.buf = make([]byte, size)
	}

	n, err := io.ReadFull(fr.r, fr.buf)
	if err != nil {
		return err
	}

	_, _ = fr.h.Write(fr.sizeBuf)
	_, _ = fr.h.Write(fr.buf[:n])

	return proto.Unmarshal(fr.buf[:n], msg)
}

// framedWriter writes protobuf messages, framed with a 32-bit little-endian
// length prefix.
type framedWriter struct {
	w       io.Writer
	sizeBuf []byte
	h       hash.Hash
}

// digest returns the SHA-512 digest of all the data written.
func (fw framedWriter) digest() []byte {
	return fw.h.Sum(nil)
}

// writeMessage writes the given protobuf message into the writer.
func (fw framedWriter) writeMessage(msg proto.Message) error {
	buf, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(fw.sizeBuf, uint32(len(buf)))

	if _, err := fw.w.Write(fw.sizeBuf); err != nil {
		return err
	}

	_, _ = fw.h.Write(fw.sizeBuf)
	_, _ = fw.h.Write(buf)

	_, err = fw.w.Write(buf)
	return err
}
