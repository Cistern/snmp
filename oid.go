package snmp

import (
	"strconv"
	"strings"
)

// TODO: add comment
func ParseOID(str string) (ObjectIdentifier, error) {
	parts := strings.Split(strings.Trim(str, "."), ".")

	oid := ObjectIdentifier{}

	for _, part := range parts {
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil, err
		}

		oid = append(oid, uint16(n))
	}

	return oid, nil
}

// TODO: add comment
func MustParseOID(str string) ObjectIdentifier {
	oid, err := ParseOID(str)
	if err != nil {
		panic(err)
	}

	return oid
}

// TODO: add comment
func encodeOIDUint(i uint16) []byte {
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
