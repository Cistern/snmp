package snmp

import (
	"bytes"
)

// GetRequest represents an SNMP GetRequest-PDU.
type GetRequest struct {
	PDU
}

func newGetRequest(requestID int, varbinds []Varbind) GetRequest {
	pdu := newPDU(requestID, 0, 0, varbinds)

	return GetRequest{
		PDU: pdu,
	}
}

// Encode encodes a GetRequest with the proper header.
func (s GetRequest) Encode() ([]byte, error) {
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

	return append(encodeHeaderSequence(TypeGetRequest, seqLength), buf.Bytes()...), nil
}
