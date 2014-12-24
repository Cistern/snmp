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

	//desc := string(res.(Sequence)[2].(GetResponse)[3].(Sequence)[0].(Sequence)[1].(String))
	//if desc != "SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m" {
	//	t.Error("Expected desc %v, got %v", "SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m", desc)
	//}

	t.Log(res.requestID)
	t.Log(res.err)
	t.Log(res.errIndex)
	t.Log(res.varbinds[0].OID)
	t.Log(res.varbinds[0].GetStringValue())
}
