package snmp

import (
	"testing"
)

func TestSNMP(t *testing.T) {
	sess, err := NewSession("demo.snmplabs.com:161", "usr-sha-aes", "authkey1", "privkey1")
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

	if vbinds := res.Varbinds(); len(vbinds) > 0 {
		desc, err := vbinds[0].GetStringValue()
		if err != nil {
			t.Fatalf("expected string value for %v, got %v of type %T", vbinds[0].OID,
				vbinds[0].value, vbinds[0].value)
		}
		if desc != "SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m" {
			t.Error("Expected desc %v, got %v", "SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m", desc)
		}

	} else {
		t.Fatalf("expected non-empty Varbinds, got %v", vbinds)
	}
}
