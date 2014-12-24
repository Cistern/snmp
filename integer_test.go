package snmp

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestInteger(t *testing.T) {
	i := 123274972974

	b1, err := asn1.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(b1)

	b2, err := Int(i).Encode()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(b2)

	t.Log(decode(bytes.NewReader(b2)))
}
