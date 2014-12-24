package snmp

import (
	"bytes"
	"errors"
	"fmt"
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
type ObjectIdentifier []uint16

// TODO: add comment
func (oid ObjectIdentifier) Encode() ([]byte, error) {
	if len(oid) < 2 {
		return nil, errors.New("snmp: invalid ObjectIdentifier length")
	}

	if oid[0] != 1 && oid[1] != 3 {
		return nil, errors.New("ObjectIdentifier does not start with .1.3")
	}

	b := make([]byte, 0, len(oid)+1)

	b = append(b, 0x2b)

	for i := 2; i < len(oid); i++ {
		b = append(b, encodeOIDUint(oid[i])...)
	}

	return append(encodeHeaderSequence(0x6, len(b)), b...), nil
}

// TODO: add comment
func (oid ObjectIdentifier) String() string {
	str := ""

	for _, part := range oid {
		str += fmt.Sprintf(".%d", part)
	}

	return str
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
