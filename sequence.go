package snmp

import (
	"bytes"
	"io"
)

// Sequence represents an SNMP SEQUENCE.
type Sequence []DataType

// Encode encodes a Sequence with the proper header.
func (s Sequence) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	for _, entry := range s {
		encodedEntry, err := entry.Encode()
		if err != nil {
			return nil, err
		}

		_, err = buf.Write(encodedEntry)
		if err != nil {
			return nil, err
		}
	}

	seqLength := buf.Len()

	return append(encodeHeaderSequence(0x30, seqLength), buf.Bytes()...), nil
}

// decodeSequence decodes a sequence up to length bytes from r.
// It returns the SNMP data type, the number of bytes read, and an error.
func decodeSequence(length int, r io.Reader) (Sequence, int, error) {
	seq := Sequence{}
	seqBytes := 0
	bytesRead := 0

	for seqBytes < length {
		item, read, err := decode(r)
		if read > 0 && item != nil {
			seq = append(seq, item)
			bytesRead += read
			seqBytes += read
		}

		if err != nil {
			return nil, bytesRead, err
		}
	}

	return seq, bytesRead, nil
}
