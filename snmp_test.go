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

	t.Log(sess.Get(MustParseOID(".1.3.6.1.2.1.1.1.0")))
}
