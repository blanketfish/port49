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
