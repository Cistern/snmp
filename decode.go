package snmp

import (
	"errors"
	"io"
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

	// Decode the length
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

	// Decode Sequence
	if t == TypeSequence {
		seq, n, err := decodeSequence(length, r)
		return seq, bytesRead + n, err
	}

	// Decode Integer, Counter, Gauge
	if t == TypeInteger || t == TypeCounter || t == TypeGauge {
		i, n, err := decodeInteger(length, r)
		return i, bytesRead + n, err
	}

	// Decode String
	if t == TypeString {

		str := make([]byte, length)
		n, _ := r.Read(str)
		bytesRead += n

		if err != nil {
			return nil, bytesRead, err
		}

		return String(str), bytesRead, nil
	}

	// Decode GetResponse
	if t == TypeGetResponse {
		getResponse, n, err := decodeGetResponse(length, r)
		return getResponse, n + bytesRead, err
	}

	// Decode Report
	if t == TypeReport {

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

	// Decode OID
	if t == TypeOID {

		// Read into a buffer
		b := make([]byte, length)
		n, err := r.Read(b)
		bytesRead += n

		if err != nil {
			return nil, bytesRead, err
		}

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

	return nil, bytesRead, errors.New("unknown type")
}
