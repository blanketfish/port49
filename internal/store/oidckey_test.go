package store

import "testing"

func TestParseOIDCKeyInvertsOIDCKey(t *testing.T) {
	for _, c := range [][3]string{{OIDCSid, "https://idp.example.com/realms/corp", "a b:c"}, {OIDCSub, "i", "u-1"}} {
		kind, iss, v, ok := ParseOIDCKey(OIDCKey(c[0], c[1], c[2]))
		if !ok || kind != c[0] || iss != c[1] || v != c[2] {
			t.Fatalf("%v: %q %q %q %v", c, kind, iss, v, ok)
		}
	}
	for _, bad := range []string{"", "sid", "sid 9:short 1:x", "sid 1:i 5:x", "jti 1:i 1:x",
		"sid +1:i 1:x", "sid 01:i 1:x", "sid 1:i 1:x ", "sid 1:i 1:xy"} {
		if _, _, _, ok := ParseOIDCKey(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
	// An issuer holding separators is not mis-split.
	k := OIDCKey(OIDCSid, "a 1:b", "c")
	if _, iss, v, ok := ParseOIDCKey(k); !ok || iss != "a 1:b" || v != "c" {
		t.Fatalf("%q: %q %q %v", k, iss, v, ok)
	}
}
