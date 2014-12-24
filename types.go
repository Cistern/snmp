package snmp

import (
	"bytes"
)

const (
	TypeInteger  = 0x02
	TypeString   = 0x04
	TypeOID      = 0x06
	TypeSequence = 0x30
	TypeCounter  = 0x41
	TypeGauge    = 0x42

	TypeGetResponse = 0xa2
	TypeReport      = 0xa8
)

// TODO: add comment
type DataType interface {
	Encode() ([]byte, error)
}

// TODO: add comment
type String string

// TODO: add comment
func (s String) Encode() ([]byte, error) {
	return append(encodeHeaderSequence(0x4, len(s)), []byte(s)...), nil
}

// TODO: add comment
type GetRequest []DataType

// TODO: add comment
func (s GetRequest) Encode() ([]byte, error) {
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

	return append(encodeHeaderSequence(0xa0, seqLength), buf.Bytes()...), nil
}

// TODO: add comment
type GetNextRequest []DataType

// TODO: add comment
func (s GetNextRequest) Encode() ([]byte, error) {
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

	return append(encodeHeaderSequence(0xa1, seqLength), buf.Bytes()...), nil
}

// TODO: add comment
type Report []DataType

// TODO: add comment
func (s Report) Encode() ([]byte, error) {
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

	return append(encodeHeaderSequence(0xa8, seqLength), buf.Bytes()...), nil
}

// TODO: add comment
type null byte

// TODO: add comment
func (n null) Encode() ([]byte, error) {
	return []byte{0x05, 0}, nil
}

// TODO: add comment
const Null null = 0

// TODO: add comment
type Gauge int

// TODO: add comment
func (g Gauge) Encode() ([]byte, error) {
	result := []byte{}

	if g == 0 {
		result = append(result, 0)
	}

	if g < 0 {
		minusOne := (-g) - 1

		for minusOne > 0 {
			result = append(result, byte((minusOne%256)^0xff))
			minusOne >>= 8
		}

		if result[len(result)-1]&0x80 == 0 {
			result = append(result, 0xff)
		}
	}

	if g > 0 {
		for g > 0 {
			result = append(result, byte(g%256))
			g >>= 8
		}

		if result[len(result)-1]&0x80 != 0 {
			result = append(result, 0x0)
		}
	}

	return append(encodeHeaderSequence(0x42, len(result)), reverseSlice(result)...), nil
}
