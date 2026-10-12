//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"testing"
)

// TestL61ReadsTheClaims holds the cell readers to the claim shapes Keycloak
// 26.4 sent in the L61 run, as a redacted fixture (iss and aud are fake; no
// token is in it).
func TestL61ReadsTheClaims(t *testing.T) {
	raw, err := os.ReadFile("testdata/l61-claims.json")
	if err != nil {
		t.Fatal(err)
	}
	var cells map[string]map[string]any
	if err := json.Unmarshal(raw, &cells); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]struct {
		cell    string
		carries bool
	}{
		"a_otp_no_mapper":     {`amr absent; acr "1"`, false},
		"b_otp_mapper":        {`amr [pwd otp]; acr "1"`, false},
		"c_password_only":     {`amr []; acr "1"`, false},
		"e_otp_reference_mfa": {`amr [pwd mfa]; acr "1"`, true},
	} {
		claims, ok := cells[name]
		if !ok {
			t.Fatalf("no %s in the fixture", name)
		}
		if got := l61Cell(claims); got != want.cell {
			t.Errorf("%s read as %q, want %q", name, got, want.cell)
		}
		if got := l61Carries(claims, l61DefaultAMR); got != want.carries {
			t.Errorf("%s carries the default words: %v, want %v", name, got, want.carries)
		}
	}
	if got := l61TOTP([]byte("12345678901234567890"), 1); got != "287082" {
		t.Errorf("RFC 6238 vector at step 1: %s", got)
	}
}
