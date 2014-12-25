package snmp

import (
	"bytes"
)

const (
	TypeInteger   = 0x02
	TypeString    = 0x04
	TypeNull      = 0x05
	TypeOID       = 0x06
	TypeSequence  = 0x30
	TypeIpAddress = 0x40
	TypeCounter   = 0x41
	TypeGauge     = 0x42
	TypeTimeTicks = 0x43
	TypeCounter64 = 0x46

	TypeNoSuchObject   = 0x80
	TypeNoSuchInstance = 0x81
	TypeEndOfMIBView   = 0x82

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

// String represents an SNMP IpAddress.
type IpAddress []byte

// Encode encodes a String with the proper header.
func (ip IpAddress) Encode() ([]byte, error) {
	return append(encodeHeaderSequence(TypeIpAddress, len(ip)), []byte(ip)...), nil
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

type tag byte

func (t tag) Encode() ([]byte, error) {
	return []byte{byte(t), 0}, nil
}

// Null represents an SNMP NULL.
const Null tag = 0x05

const NoSuchObject tag = TypeNoSuchObject
const NoSuchInstance tag = TypeNoSuchInstance
const EndOfMIBView tag = TypeEndOfMIBView

// Gauge represents an SNMP Gauge data type.
type Gauge int

// Encode encodes a Gauge with the proper header.
func (g Gauge) Encode() ([]byte, error) {
	result := encodeInteger(int(g))
	return append(encodeHeaderSequence(TypeGauge, len(result)), result...), nil
}

// Counter represents an SNMP Counter data type.
type Counter int

// Encode encodes a Counter with the proper header.
func (c Counter) Encode() ([]byte, error) {
	result := encodeInteger(int(c))
	return append(encodeHeaderSequence(TypeCounter, len(result)), result...), nil
}

// Counter64 represents an SNMP Counter64 data type.
type Counter64 int

// Encode encodes a Counter with the proper header.
func (c Counter64) Encode() ([]byte, error) {
	result := encodeInteger(int(c))
	return append(encodeHeaderSequence(TypeCounter64, len(result)), result...), nil
}

// TimeTicks represents an SNMP TimeTicks data type.
type TimeTicks int

// Encode encodes a Gauge with the proper header.
func (t TimeTicks) Encode() ([]byte, error) {
	result := encodeInteger(int(t))
	return append(encodeHeaderSequence(TypeTimeTicks, len(result)), result...), nil
}
