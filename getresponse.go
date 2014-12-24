package snmp

import (
	"bytes"
	"io"
)

// GetResponse represents an SNMP GetResponse-PDU.
type GetResponse struct {
	PDU
}

// Encode encodes a GetResponse with the proper header.
func (s GetResponse) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	for _, entry := range s.PDU.rawSequence {
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

// decodeGetResponse decodes a GetResponse up to length bytes from r.
// It returns the SNMP data type, the number of bytes read, and an error.
func decodeGetResponse(length int, r io.Reader) (GetResponse, int, error) {
	res := GetResponse{}

	pdu, bytesRead, err := decodePDU(length, r)
	res.PDU = pdu

	return res, bytesRead, err
}
