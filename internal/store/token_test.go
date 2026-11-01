package store_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/store"
)

// A token printed with any verb withholds its secret, in a slice too (plan
// 7b final review M-1).
func TestATokenPrintsNoSecret(t *testing.T) {
	tok := store.Token{ID: "t1", Secret: []byte("TOKENSECRET"), Kind: store.KindLogin, Username: "alice"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{tok, &tok, []store.Token{tok}} {
			if got := fmt.Sprintf(verb, v); strings.Contains(got, "TOKENSECRET") || !strings.Contains(got, "alice") {
				t.Fatalf("%s of %T printed a secret, or nothing: %d bytes", verb, v, len(got))
			}
		}
	}
}
