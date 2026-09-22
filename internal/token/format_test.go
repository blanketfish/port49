package token

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func isBase62(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			return false
		}
	}
	return true
}

func TestTagIsDeterministicPerDeviceAndKey(t *testing.T) {
	k := TagKey([]byte("enc-key"))
	a, b := Tag(k, "leaf-01"), Tag(k, "leaf-01")
	if a != b || len(a) != TagLen || !isBase62(a) {
		t.Fatalf("%q %q", a, b)
	}
	if Tag(k, "leaf-02") == a {
		t.Fatal("two devices must not share a tag")
	}
	if Tag(TagKey([]byte("other")), "leaf-01") == a {
		t.Fatal("tag must depend on the key")
	}
}

func TestNewAndParse(t *testing.T) {
	k := TagKey([]byte("enc-key"))
	tok, err := New(rand.Reader, k, "leaf-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != Len || !isBase62(tok) || !strings.HasPrefix(tok, Tag(k, "leaf-01")) {
		t.Fatalf("%q", tok)
	}
	tag, ok := Parse([]byte(tok))
	if !ok || tag != Tag(k, "leaf-01") {
		t.Fatalf("parse %q %v", tag, ok)
	}
	if _, ok := Parse([]byte("too-short")); ok {
		t.Fatal("short input must not parse")
	}
	if _, ok := Parse([]byte(strings.Repeat("!", Len))); ok {
		t.Fatal("non-base62 must not parse")
	}
	tok2, _ := New(rand.Reader, k, "leaf-01")
	if tok2 == tok {
		t.Fatal("two mints must differ")
	}
}

// A 30-character token clears the 255-byte PAP ceiling by an order of
// magnitude (design §8), and the interactive prompt limits measured so far
// (tests/lab/results/L8-arista_eos.md, L8-juniper_vsrx.md,
// L8-juniper_vjunos-router.md, L8-cisco_nxos.md, L8-cisco_iosxe.md) are all
// far above it. PAP input limits are unmeasured on every platform (L8 is open).
func TestTokenFitsEveryMeasuredPromptLimit(t *testing.T) {
	if Len != 30 {
		t.Fatalf("token length changed to %d; re-read L8 before accepting it", Len)
	}
}

func TestBase62(t *testing.T) {
	if got := Base62([]byte{0}); got != "0" {
		t.Fatalf("%q", got)
	}
	if got := Base62([]byte{61}); got != "z" {
		t.Fatalf("%q", got)
	}
	if !isBase62(Base62(bytes.Repeat([]byte{0xff}, 32))) {
		t.Fatal("not base62")
	}
}
