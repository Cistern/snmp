package snmp

import (
	"bytes"
	"io"
)

// TODO: add comment
type GetResponse struct {
	rawSequence []DataType
	requestID   int
	err         int
	errIndex    int
	Varbinds    []Varbind
}

// TODO: add comment
func (s GetResponse) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	for _, entry := range s.rawSequence {
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

func decodeGetResponse(length int, r io.Reader) (DataType, int, error) {
	res := GetResponse{}
	seqBytes := 0
	bytesRead := 0

	for seqBytes < length {
		item, read, err := decode(r)
		if read > 0 && item != nil {
			res.rawSequence = append(res.rawSequence, item)
			bytesRead += read
			seqBytes += read
		}

		if err != nil {
			return nil, bytesRead, err
		}
	}

	reqID, ok := res.rawSequence[0].(Int)
	if !ok {
		return nil, bytesRead, ErrDecodingType
	}
	res.requestID = int(reqID)

	errorCode, ok := res.rawSequence[1].(Int)
	if !ok {
		return nil, bytesRead, ErrDecodingType
	}
	res.err = int(errorCode)

	errIndex, ok := res.rawSequence[2].(Int)
	if !ok {
		return nil, bytesRead, ErrDecodingType
	}
	res.errIndex = int(errIndex)

	varbindSeq, ok := res.rawSequence[3].(Sequence)
	if !ok {
		return nil, bytesRead, ErrDecodingType
	}
	for _, varbindElem := range varbindSeq {
		varbindPair, ok := varbindElem.(Sequence)
		if !ok {
			return nil, bytesRead, ErrDecodingType
		}

		oid, ok := varbindPair[0].(ObjectIdentifier)
		if ok {
			val := varbindPair[1]
			res.Varbinds = append(res.Varbinds, NewVarbind(oid, val))
		}
	}

	return res, bytesRead, nil
}
