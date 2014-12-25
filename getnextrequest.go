package snmp

import (
	"bytes"
)

// GetNextRequest represents an SNMP GetNextRequest-PDU.
type GetNextRequest struct {
	PDU
}

func newGetNextRequest(requestID int, varbinds []Varbind) GetNextRequest {
	pdu := newPDU(requestID, 0, 0, varbinds)

	return GetNextRequest{
		PDU: pdu,
	}
}

// Encode encodes a GetNextRequest with the proper header.
func (s GetNextRequest) Encode() ([]byte, error) {
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

	return append(encodeHeaderSequence(TypeGetNextRequest, seqLength), buf.Bytes()...), nil
}
