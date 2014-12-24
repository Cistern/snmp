package snmp

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func compEncoding(i int) bool {
	b1, _ := asn1.Marshal(i)
	b2, _ := Int(i).Encode()

	return bytes.Equal(b1, b2)
}

func compDecoding(b []byte) bool {
	i := 0
	asn1.Unmarshal(b, &i)
	dataType, _, _ := decode(bytes.NewReader(b))

	return i == int(dataType.(Int))
}

func TestIntegerEncoding(t *testing.T) {
	cases := [...]int{
		0,
		-127,
		127,
		128,
		-128,
		12345,
		-12345,
		1,
		-1,
	}

	for _, testCase := range cases {
		if !compEncoding(testCase) {
			t.Errorf("encoding failed for %d", testCase)
		}
	}
}

func TestIntegerDecoding(t *testing.T) {
	cases := [...][]byte{
		{2, 1, 0},
		{2, 1, 129},
		{2, 1, 127},
		{2, 2, 0, 128},
		{2, 1, 128},
		{2, 2, 48, 57},
		{2, 2, 207, 199},
		{2, 1, 1},
		{2, 1, 255},
	}

	for _, testCase := range cases {
		if !compDecoding(testCase) {
			t.Errorf("encoding failed for %d", testCase)
		}
	}
}
