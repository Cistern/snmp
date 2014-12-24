package snmp

import (
	"encoding/asn1"
	"errors"
	"io"
	"log"
)

var (
	ErrDecodingType = errors.New("snmp: error decoding type")
)

func decode(r io.Reader) (DataType, int, error) {
	bytesRead := 0

	typeLength := []byte{0, 0}
	n, err := r.Read(typeLength)

	bytesRead += n

	if err != nil {
		return nil, bytesRead, err
	}

	t := typeLength[0]
	length := int(typeLength[1])

	// TODO: add comment - this is decoding the length?
	if length > 0x7F {
		lengthNumBytes := 0x80 ^ byte(length)
		length = 0
		for lengthNumBytes > 0 {
			length = length << 8
			var b [1]byte
			n, err := r.Read(b[:])

			bytesRead += n

			if err != nil {
				return nil, bytesRead, err
			}

			length |= int(b[0])

			lengthNumBytes--
		}

	}

	// TODO: add comment - sequence
	if t == 0x30 {
		seq := Sequence{}
		seqBytes := 0

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

	// TODO: add comment - integer types
	if t == 0x02 || t == 0x41 || t == 0x42 {
		intBytes := make([]byte, int(length))
		n, err := r.Read(intBytes)
		bytesRead += n

		if err != nil {
			return nil, bytesRead, err
		}

		// Decode integer
		i := 0
		negative := false
		if intBytes[0]&0x80 != 0 {
			negative = true
		}

		log.Println(intBytes)

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

		log.Println(i)

		intBytes = append([]byte{0x02, byte(length)}, intBytes...)
		asn1.Unmarshal(intBytes, &i)
		log.Println(i)
		return Int(i), bytesRead, nil
	}

	// TODO: add comment - strings
	if t == 0x04 {

		str := make([]byte, length)
		n, _ := r.Read(str)
		bytesRead += n

		if err != nil {
			return nil, bytesRead, err
		}

		return String(str), bytesRead, nil
	}

	// TODO: add comment - get response
	if t == 0xa2 {
		getResponse, n, err := decodeGetResponse(length, r)
		return getResponse, n + bytesRead, err
	}

	// TODO: add comment - report
	if t == 0xa8 {

		res := Report{}
		seqBytes := 0

		for seqBytes < length {
			item, read, err := decode(r)
			if read > 0 && item != nil {
				res = append(res, item)
				bytesRead += read
				seqBytes += read
			}

			if err != nil {
				return nil, bytesRead, err
			}
		}

		return res, bytesRead, nil
	}

	// TODO: add comment - OID
	if t == 0x06 {

		// Read into a buffer
		b := make([]byte, length)
		n, err := r.Read(b)
		bytesRead += n

		if err != nil {
			return nil, bytesRead, err
		}

		// Decode OID
		oid := ObjectIdentifier{uint16(b[0]) / 40, uint16(b[0]) % 40}

		for i := 1; i < length; i++ {
			val := uint16(0)

			for b[i] >= 128 {
				val += uint16(b[i]) - 128
				val *= 128
				i++
			}

			val += uint16(b[i])

			oid = append(oid, val)
		}

		return oid, bytesRead, nil
	}

	// TODO: use a switch for ^?

	return nil, bytesRead, errors.New("unknown type")
}
