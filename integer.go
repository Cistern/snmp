package snmp

import (
	"io"
)

// Int represents an SNMP INTEGER.
type Int int

// encodeInteger encodes a length-encoded integer.
func encodeInteger(i int) []byte {
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

		if len(result) == 0 {
			result = append(result, 0xff)
		} else {
			if result[len(result)-1]&0x80 == 0 {
				result = append(result, 0xff)
			}
		}
	} else {
		for i > 0 {
			result = append(result, byte(i%256))
			i >>= 8
		}

		if result[len(result)-1]&0x80 != 0 {
			result = append(result, 0x0)
		}
	}

	return reverseSlice(result)
}

// Encode encodes an Int with the proper header.
func (i Int) Encode() ([]byte, error) {
	result := encodeInteger(int(i))
	return append(encodeHeaderSequence(0x02, len(result)), result...), nil
}

// decodeInteger decodes an integer up to length bytes from r.
// It returns the SNMP data type, the number of bytes read, and an error.
func decodeInteger(length int, r io.Reader) (Int, int, error) {
	intBytes := make([]byte, int(length))
	bytesRead := 0

	n, err := r.Read(intBytes)
	bytesRead += n

	if err != nil {
		return 0, bytesRead, err
	}

	i := 0
	negative := false
	if intBytes[0]&0x80 != 0 {
		negative = true
	}

	for j, b := range intBytes {
		if j > 0 {
			i <<= 8
		}

		if negative {
			b ^= 0xff
		}

		i |= int(b)
	}

	if negative {
		i = -1 * (i + 1)
	}

	return Int(i), bytesRead, nil
}
