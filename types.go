package snmp

import (
	"bytes"
	"errors"
	"fmt"
)

type DataType interface {
	Encode() ([]byte, error)
}

type Sequence []DataType

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

type Int int

func (i Int) Encode() ([]byte, error) {
	result := []byte{}

	if i == 0 {
		result = append(result, 0)
	}

	if i < 0 {
		minusOne := (-i) - 1

		for minusOne > 0 {
			result = append(result, byte((minusOne%256)^0xff))
			minusOne >>= 8
		}

		if result[len(result)-1]&0x80 == 0 {
			result = append(result, 0xff)
		}
	}

	if i > 0 {
		for i > 0 {
			result = append(result, byte(i%256))
			i >>= 8
		}

		if result[len(result)-1]&0x80 != 0 {
			result = append(result, 0x0)
		}
	}

	return append(encodeHeaderSequence(0x02, len(result)), reverseSlice(result)...), nil
}

type String string

func (s String) Encode() ([]byte, error) {
	return append(encodeHeaderSequence(0x4, len(s)), []byte(s)...), nil
}

type GetRequest []DataType

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

type GetNextRequest []DataType

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

type GetResponse []DataType

func (s GetResponse) Encode() ([]byte, error) {
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

	return append(encodeHeaderSequence(0xa2, seqLength), buf.Bytes()...), nil
}

type Report []DataType

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

type ObjectIdentifier []uint16

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

func (oid ObjectIdentifier) String() string {
	str := ""

	for _, part := range oid {
		str += fmt.Sprintf(".%d", part)
	}

	return str
}

type null byte

func (n null) Encode() ([]byte, error) {
	return []byte{0x05, 0}, nil
}

const Null null = 0

type Gauge int

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
