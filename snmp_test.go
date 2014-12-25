package snmp

import (
	"fmt"
	"testing"
)

func TestSNMP(t *testing.T) {
	sess, err := NewSession("localhost:161", "adminusr", "snmpPASSWORD", "snmpPASSWORD")
	if err != nil {
		t.Fatal(err)
	}

	err = sess.Discover()
	if err != nil {
		t.Fatal(err)
	}

	res, err := sess.Get(MustParseOID(".1.3.6.1.2.1.1.1.0"))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(res.requestID)
	t.Log(res.err)
	t.Log(res.errIndex)
	t.Log(res.varbinds[0].OID)
	t.Log(res.varbinds[0].GetStringValue())

	res, err = sess.GetNext(res.varbinds[0].OID)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(res.varbinds[0].OID)

	oid := MustParseOID(".1.0")
	for {
		res, err := sess.Get(oid)
		if err != nil {
			break
		}
		if len(res.varbinds) == 0 {
			break
		}

		fmt.Printf("%v = %T %v\n", res.varbinds[0].OID, res.varbinds[0].value, res.varbinds[0].value)
		res, err = sess.GetNext(oid)
		if err != nil {
			break
		}

		if len(res.varbinds) == 0 {
			break
		}

		oid = res.varbinds[0].OID
	}
}
