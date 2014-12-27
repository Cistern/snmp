package snmp

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ObjectIdentifier represents an SNMP OID.
type ObjectIdentifier []uint

// ParseOID parses and returns an ObjectIdentifier and an error.
func ParseOID(str string) (ObjectIdentifier, error) {
	parts := strings.Split(strings.Trim(str, "."), ".")

	oid := ObjectIdentifier{}

	for _, part := range parts {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, err
		}

		oid = append(oid, uint(n))
	}

	return oid, nil
}

// MustParseOID parses a string and returns an ObjectIdentifier.
// It panics if an error is encountered.
func MustParseOID(str string) ObjectIdentifier {
	oid, err := ParseOID(str)
	if err != nil {
		panic(err)
	}

	return oid
}

// encodeOIDUint encodes a uint using base 128.
func encodeOIDUint(i uint) []byte {
	var b []byte

	if i < 128 {
		return []byte{byte(i)}
	}

	b = append(b, byte(i)%128)
	i /= 128

	for i > 0 {
		b = append(b, 128+byte(i)%128)
		i /= 128
	}

	return reverseSlice(b)
}

// Encode encodes an ObjectIdentifier with the proper header.
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

// decodeOID decodes an OID up to length bytes from r.
// It returns the SNMP data type, the number of bytes read, and an error.
func decodeOID(length int, r io.Reader) (ObjectIdentifier, int, error) {
	bytesRead := 0

	// Read into a buffer
	b := make([]byte, length)
	n, err := r.Read(b)
	bytesRead += n

	if err != nil {
		return nil, bytesRead, err
	}

	oid := ObjectIdentifier{uint(b[0]) / 40, uint(b[0]) % 40}

	for i := 1; i < length; i++ {
		val := uint(0)

		for b[i] >= 128 {
			val += uint(b[i]) - 128
			val *= 128
			i++
		}

		val += uint(b[i])

		oid = append(oid, val)
	}

	return oid, bytesRead, nil
}

// String returns the string representation of an ObjectIdentifer.
// This value can be parsed into the original OID as well.
func (oid ObjectIdentifier) String() string {
	str := ""

	for _, part := range oid {
		str += fmt.Sprintf(".%d", part)
	}

	return str
}
