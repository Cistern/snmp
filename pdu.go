package snmp

import (
	"io"
)

// PDU represents an SNMP PDU.
type PDU struct {
	rawSequence []DataType
	requestID   int
	err         int
	errIndex    int
	varbinds    []Varbind
}

func (p PDU) Varbinds() []Varbind {
	return p.varbinds
}

func decodePDU(length int, r io.Reader) (PDU, int, error) {
	pdu := PDU{}

	seqBytes := 0
	bytesRead := 0

	for seqBytes < length {
		item, read, err := decode(r)
		if read > 0 && item != nil {
			pdu.rawSequence = append(pdu.rawSequence, item)
			bytesRead += read
			seqBytes += read
		}

		if err != nil {
			return pdu, bytesRead, err
		}
	}

	reqID, ok := pdu.rawSequence[0].(Int)
	if !ok {
		return pdu, bytesRead, ErrDecodingType
	}
	pdu.requestID = int(reqID)

	errorCode, ok := pdu.rawSequence[1].(Int)
	if !ok {
		return pdu, bytesRead, ErrDecodingType
	}
	pdu.err = int(errorCode)

	errIndex, ok := pdu.rawSequence[2].(Int)
	if !ok {
		return pdu, bytesRead, ErrDecodingType
	}
	pdu.errIndex = int(errIndex)

	varbindSeq, ok := pdu.rawSequence[3].(Sequence)
	if !ok {
		return pdu, bytesRead, ErrDecodingType
	}
	for _, varbindElem := range varbindSeq {
		varbindPair, ok := varbindElem.(Sequence)
		if !ok {
			return pdu, bytesRead, ErrDecodingType
		}

		oid, ok := varbindPair[0].(ObjectIdentifier)
		if ok {
			val := varbindPair[1]
			pdu.varbinds = append(pdu.varbinds, NewVarbind(oid, val))
		}
	}

	return pdu, bytesRead, nil
}
