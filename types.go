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

	TypeGetRequest     = 0xa0
	TypeGetNextRequest = 0xa1
	TypeGetResponse    = 0xa2
	TypeReport         = 0xa8
)

// DataType represents an SNMP data type.
type DataType interface {
	Encode() ([]byte, error)
}

// String represents an SNMP OCTET STRING.
type String string

// Encode encodes a String with the proper header.
func (s String) Encode() ([]byte, error) {
	return append(encodeHeaderSequence(0x4, len(s)), []byte(s)...), nil
}

// Report represents an SNMP Report-PDU.
type Report []DataType

// Encode encodes a Report with the proper header.
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

// null represents an SNMP NULL data type.
type null byte

// Encode encodes a null with the proper header.
func (n null) Encode() ([]byte, error) {
	return []byte{0x05, 0}, nil
}

// Null represents an SNMP NULL.
const Null null = 0

// Gauge represents an SNMP GAUGE data type.
type Gauge int

// Encode encodes a Gauge with the proper header.
func (g Gauge) Encode() ([]byte, error) {
	result := encodeInteger(int(g))
	return append(encodeHeaderSequence(0x42, len(result)), result...), nil
}
