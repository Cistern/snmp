package snmp

import (
	"errors"
	"io"
	"log"
)

var (
	ErrDecodingType = errors.New("snmp: error decoding type")
	ErrUnknownType  = errors.New("snmp: unknown type")
)

// decode decodes an SNMP DataType from r.
// It returns the SNMP data type, the number of bytes read, and an error.
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

	// Decode types
	switch t {
	case TypeSequence:
		seq, n, err := decodeSequence(length, r)
		return seq, bytesRead + n, err

	case TypeInteger, TypeCounter, TypeCounter64, TypeGauge, TypeTimeTicks:
		i, n, err := decodeInteger(length, r)
		return i, bytesRead + n, err

	case TypeString:
		str := make([]byte, length)
		n, _ := r.Read(str)
		bytesRead += n

		if err != nil {
			return nil, bytesRead, err
		}

		return String(str), bytesRead, nil

	case TypeIpAddress:
		ip := make(IpAddress, length)
		n, _ := r.Read(ip)
		bytesRead += n

		if err != nil {
			return nil, bytesRead, err
		}

		return ip, bytesRead, nil

	case TypeOID:
		oid, n, err := decodeOID(length, r)
		return oid, bytesRead + n, err

	case TypeGetResponse:
		getResponse, n, err := decodeGetResponse(length, r)
		return getResponse, n + bytesRead, err

	case TypeReport:
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

	case TypeNull, TypeNoSuchObject, TypeNoSuchInstance, TypeEndOfMIBView:
		return tag(t), bytesRead, nil

	default:
		log.Printf("0x%X", t)
		return nil, bytesRead, ErrUnknownType
	}
}
