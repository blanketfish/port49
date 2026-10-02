package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A mint item printed with any verb withholds its tokens, in a slice and
// behind a pointer too, while its JSON, the wire form, keeps them (plan 7b
// final review M-1).
func TestAMintItemPrintsNoToken(t *testing.T) {
	it := MintItem{Device: "leaf1", Verdict: "permit", Login: "LOGINSECRET", Enable: "ENABLESECRET"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{it, &it, []MintItem{it}, MintResponse{Results: []MintItem{it}}} {
			if got := fmt.Sprintf(verb, v); strings.Contains(got, "SECRET") || !strings.Contains(got, "leaf1") {
				t.Fatalf("%s of %T printed a token, or nothing: %d bytes", verb, v, len(got))
			}
		}
	}
	if b, _ := json.Marshal(it); !strings.Contains(string(b), `"login":"LOGINSECRET"`) {
		t.Fatal("the wire form lost its login token")
	}
}
