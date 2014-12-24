package snmp

import (
	"bytes"
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
