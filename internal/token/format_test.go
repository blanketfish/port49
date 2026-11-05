package token

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/username"
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

// The window is what a daemon ACCEPTS: one tag key per encryption key in the
// store's read window. A token tagged under either is this device's; one tagged
// under a key that has left the window, or under any key for another device, is
// not.
func TestTagWindowAcceptsEveryKeyInIt(t *testing.T) {
	cur, prev, gone := TagKey([]byte("v2")), TagKey([]byte("v1")), TagKey([]byte("v0"))
	w := NewTagWindow(cur, prev)
	for _, k := range [][]byte{cur, prev} {
		if !w.Matches(Tag(k, "leaf-01"), "leaf-01") {
			t.Fatal("a tag under a key in the window must be accepted")
		}
	}
	if w.Matches(Tag(gone, "leaf-01"), "leaf-01") {
		t.Fatal("a tag under a key that has left the window must be refused")
	}
	// Device binding still holds under every key in the window; a window is
	// not a way for one device's token to work at another.
	for _, k := range [][]byte{cur, prev} {
		if w.Matches(Tag(k, "leaf-99"), "leaf-01") {
			t.Fatal("another device's tag must be refused under every key in the window")
		}
	}
	// A window with no keys accepts nothing: it fails closed, never open.
	if (TagWindow{}).Matches(Tag(cur, "leaf-01"), "leaf-01") {
		t.Fatal("an empty window must accept no tag at all")
	}
	if NewTagWindow(nil, []byte{}).Matches(Tag(cur, "leaf-01"), "leaf-01") {
		t.Fatal("an empty key is not a key")
	}
}

// synthTokenShaped is token-shaped (Len base62 characters) and obviously not a
// credential.
const synthTokenShaped = "SyntheticTokenShapedNameXY1234"

func TestLoggedUsernameRedactsOnlyTokenShapedNames(t *testing.T) {
	if len(synthTokenShaped) != Len {
		t.Fatalf("fixture is %d bytes, want %d", len(synthTokenShaped), Len)
	}
	cases := []struct {
		name, in, want string
		redacted       bool
	}{
		{"plain_name", "alice", "alice", false},
		{"token_shaped", synthTokenShaped, "", true},
		{"token_shaped_with_trailing_space_and_cr", synthTokenShaped + " \r", "", true},
		{"thirty_chars_with_dot", "synthetic.name.of.thirty.chars", "synthetic.name.of.thirty.chars", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, red := LoggedUsername(c.in)
			if got != c.want || red != c.redacted {
				t.Fatalf("LoggedUsername(%q) = %q, %v; want %q, %v", c.in, got, red, c.want, c.redacted)
			}
		})
	}
}

func TestLoggedUsernameRedactsWrappedAndNearTokenShapes(t *testing.T) {
	tok := synthTokenShaped
	lower := strings.ToLower(tok)
	redacted := map[string]string{
		"domain_prefix":        `corp\` + tok,
		"domain_prefix_lower":  `CORP\` + lower,
		"at_suffix":            tok + "@",
		"at_host":              tok + "@example",
		"at_host_lower":        lower + "@Example.com",
		"truncated_paste":      tok[:len(tok)-1],
		"truncated_paste_more": tok[:27],
		"one_char_too_long":    tok + "x",
		"trailing_nul":         tok + "\x00",
		"leading_nul":          "\x00" + tok,
		"interior_control":     tok[:10] + "\x01" + tok[10:],
		// No digit in the first 24 characters: only the digitless run rule
		// sees these.
		"digitless_truncated_paste":        tok[:24],
		"digitless_truncated_paste_domain": `corp\` + tok[:24],
		// A 30-character lower-case token with no digit and no upper case:
		// only the canonical form's exact check sees it behind a prefix.
		"digitless_lower_token_domain": `corp\abcdefghijklmnopqrstuvwxyzabcd`,
		"digitless_lower_token_host":   `abcdefghijklmnopqrstuvwxyzabcd@example`,
	}
	for name, in := range redacted {
		t.Run("redacted_"+name, func(t *testing.T) {
			got, red := LoggedUsername(in)
			if got != "" || !red {
				t.Fatalf("LoggedUsername(%q) = %q, %v; want empty, true", in, got, red)
			}
		})
	}
	clear := []string{"alice", "firstname.lastname.contractor", "svc_backup_nightly_runner", `corp\alice`, "alice@example.com",
		"administratorsecondaccount", "FirstnameLastnameContractor"[:20]}
	for _, in := range clear {
		t.Run("clear_"+in, func(t *testing.T) {
			got, red := LoggedUsername(in)
			if red || got != username.Canonical(in) {
				t.Fatalf("LoggedUsername(%q) = %q, %v; want the canonical name in clear", in, got, red)
			}
		})
	}
}
