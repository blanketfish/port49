package labcreds

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "port49d-lab.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSecretsReadsTheSeededTokens: the redactor verifies against this list, so
// it has to hold every token the config seeds plus the breakglass password.
func TestSecretsReadsTheSeededTokens(t *testing.T) {
	got, err := Secrets(write(t, `
lab:
  seed_tokens:
    - {nas: leaf1, username: alice01, secret: p49_labtoken01, kind: login}
    - {nas: srx1, username: alice01, secret: p49_labtoken01, kind: login}
    - {nas: leaf1, username: alice02, secret: p49_labtoken02, kind: login}
`))
	if err != nil {
		t.Fatal(err)
	}
	// Two distinct tokens, deduplicated across NASes, plus the password and
	// the prefix.
	want := []string{"p49_labtoken01", "p49_labtoken02", BreakglassPassword, TokenPrefix}
	if len(got) != len(want) {
		t.Fatalf("got %d secrets, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("secret %d differs from the expected one", i)
		}
	}
}

// TestSecretsRefusesAnEmptyList is the one that matters at 3am. A config the
// parser cannot find tokens in would hand the redactor nothing to search for,
// and it would report a clean file every time.
func TestSecretsRefusesAnEmptyList(t *testing.T) {
	for _, body := range []string{
		"lab:\n  seed_tokens: []\n",
		"lab: {}\n",
		"# nothing at all\n",
		"lab:\n  seed_tokens:\n    - {nas: leaf1, username: alice01, kind: login}\n", // no secret
	} {
		if _, err := Secrets(write(t, body)); err == nil {
			t.Errorf("a config seeding no token must be refused, not verified against")
		} else if !strings.Contains(err.Error(), "empty secret list") {
			t.Errorf("the error must say why it refused, got: %v", err)
		}
	}
	if _, err := Secrets(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing config must be refused")
	}
}

// TestTokenShaped: the shape rule is what audits evidence whose run's tokens
// are gone, so both halves matter — it has to find a minted token wherever it
// sits, and it must not fire on the things a lab capture legitimately carries.
func TestTokenShaped(t *testing.T) {
	tok := "Ab3Df7" + "hJ9kLmNpQrStUvWxYz234567" // 6-char tag + 24-char secret
	if len(tok) != TokenLen {
		t.Fatalf("the fixture is %d characters, not %d", len(tok), TokenLen)
	}
	// A token is not delimited on the wire, so every one of these must be
	// found. The last three are the case an exact-length rule gets wrong: NX-OS
	// puts the PAP password straight after rem_addr, so the token is the tail
	// of one 31-byte base62 run. What is returned is a TokenLen window, not
	// necessarily the token's own offset — detection is the job here.
	for _, in := range []string{
		tok,
		"user=alice01 password=" + tok,
		tok + " trailing",
		"cmd-arg=" + tok + "*",
		"172.100.100.1" + tok, // the NX-OS AuthenStart layout
		tok + "0",             // abuts a digit
		"0" + tok,             // abuts a digit on the left
	} {
		got := TokenShaped([]byte(in))
		if got == "" {
			t.Errorf("a token in %q was not found", in)
			continue
		}
		if len(got) != TokenLen {
			t.Errorf("%q: reported a %d-character window, want %d", in, len(got), TokenLen)
		}
	}
	for _, in := range []string{
		"",
		"user=alice01 port=ssh rem_addr=172.100.100.10",
		BreakglassPassword,
		// The deny prefix L2 types: a 140-character run of one character. The
		// distinct-character floor is what keeps this silent, and it has to,
		// because L2 puts it in a capture every run.
		"show clock | include " + strings.Repeat("A", 140),
		strings.Repeat("x", TokenLen), // a redacted field
		strings.Repeat("A", TokenLen),
		// A redacted field abutting rem_addr's last digit — the committed form
		// of the NX-OS layout above, in evidence/L8-cisco_nxos.pcap packet 0.
		// A 31-byte run that must NOT be reported, which is why the rule counts
		// characters rather than measuring the run.
		"1" + strings.Repeat("x", TokenLen),
		tok[:TokenLen-1], // one short: no window at all
		"p49_labtoken01",
	} {
		if got := TokenShaped([]byte(in)); got != "" {
			t.Errorf("%q is not token-shaped, but %q was reported", in, got)
		}
	}
}

func TestRedacted(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"xxxxxxxx", true},
		{"", true}, // a zero-length credential field carries nothing
		{"xxxxpxxx", false},
		{"p49_labtoken01", false},
	} {
		if got := Redacted([]byte(tc.in)); got != tc.want {
			t.Errorf("Redacted(%d bytes) = %v, want %v", len(tc.in), got, tc.want)
		}
	}
}

func TestContains(t *testing.T) {
	secrets := []string{"p49_labtoken01", BreakglassPassword}
	if hits := Contains([]byte("user=alice01 port=ssh"), secrets); len(hits) != 0 {
		t.Errorf("a clean field reported %d hit(s)", len(hits))
	}
	if hits := Contains([]byte("......p49_labtoken01......"), secrets); len(hits) != 1 {
		t.Errorf("an embedded token reported %d hit(s), want 1", len(hits))
	}
	// An empty secret would match everything and make the verifier useless.
	if hits := Contains([]byte("anything"), []string{""}); len(hits) != 0 {
		t.Errorf("an empty secret matched, which would make every field a hit")
	}
}
