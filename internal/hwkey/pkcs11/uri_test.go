package pkcs11

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	u, err := ParseURI("pkcs11:token=YubiKey%20PIV;id=%01;type=private?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so&pin-source=file:///etc/port49/pin")
	if err != nil {
		t.Fatal(err)
	}
	if u.Token != "YubiKey PIV" || !bytes.Equal(u.ID, []byte{1}) || u.Type != "private" ||
		u.ModulePath != "/usr/lib/x86_64-linux-gnu/libykcs11.so" || u.PINSource != "file:///etc/port49/pin" {
		t.Fatalf("parsed %+v", u)
	}
	for _, bad := range []struct{ uri, says string }{
		{"pkcs11:id=%01?pin-value=123456", "pin-value"},
		{"pkcs11:id=%01", "module-path"},
		{"pkcs11:id=%01?module-path=libykcs11.so", "absolute"},
		{"pkcs11:id=%zz?module-path=/x.so", "percent"},
		{"pkcs11:colour=red;id=%01?module-path=/x.so", "colour"},
		{"pkcs11:id=%01;id=%02?module-path=/x.so", "twice"},
		{"pkcs11:?module-path=/x.so", "id or object"},
		{"file:/x", "pkcs11:"},
	} {
		if _, err := ParseURI(bad.uri); err == nil || !strings.Contains(err.Error(), bad.says) {
			t.Errorf("ParseURI(%q) = %v, want an error naming %q", bad.uri, err, bad.says)
		}
	}
	// A malformed escape in a pin-value is refused as pin-value, and no
	// byte of the PIN is in the error (final review client M11).
	_, err = ParseURI("pkcs11:id=%01?module-path=/x.so&pin-value=98%Z7")
	if err == nil || !strings.Contains(err.Error(), "pin-value is refused") || strings.Contains(err.Error(), "Z7") ||
		strings.Contains(err.Error(), "98") {
		t.Errorf("a pin-value with a bad escape: %v", err)
	}
}

// String is canonical and carries no PIN source's contents; parsing it again
// gives the same URI.
func TestURIStringRoundTrips(t *testing.T) {
	u, err := ParseURI("pkcs11:token=A%20B;id=%01%ff;slot-id=3?module-path=/x/m.so")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseURI(u.String())
	if err != nil {
		t.Fatalf("%q: %v", u.String(), err)
	}
	if again.Token != "A B" || !bytes.Equal(again.ID, []byte{1, 0xff}) || again.SlotID == nil || *again.SlotID != 3 ||
		again.ModulePath != "/x/m.so" {
		t.Fatalf("round trip: %+v", again)
	}
}
