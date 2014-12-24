package snmp

import (
	"bytes"
	"io"
)

// TODO: add comment
type Sequence []DataType

// TODO: add comment
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
