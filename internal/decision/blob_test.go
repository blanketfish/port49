package decision

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// The `blob` event carries the compiled blob itself, so replay depends on the
// log alone (spec §5.1.1; §13, decision 19). It is written as JSON, not as a
// quoted string: a reader queries its fields like any other record's.
func TestABlobEventCarriesTheBodyAsJSON(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventBlob,
		Blob: &Blob{Hash: "sha256:ab", Body: json.RawMessage(`{"platform":"arista_eos"}`)}})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	b, _ := m["blob"].(map[string]any)
	body, ok := b["body"].(map[string]any)
	if !ok || body["platform"] != "arista_eos" || b["hash"] != "sha256:ab" {
		t.Fatalf("blob event: %s", buf.String())
	}
}

// A mint record names the subject and the grants that allowed it (spec §5.7).
func TestAMintRecordCarriesItsPolicyBlock(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventMint, Verdict: VerdictPermit,
		Reason: GrantsMatched, Policy: &Policy{Subject: "netops",
			Grants: []PolicyGrant{{Scope: "all_devices", Roles: []string{"network_admin"}}}}})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	p, _ := m["policy"].(map[string]any)
	g, _ := p["grants"].([]any)
	if p["subject"] != "netops" || len(g) != 1 || g[0].(map[string]any)["scope"] != "all_devices" {
		t.Fatalf("policy block: %s", buf.String())
	}
	if CandidateCapReached != "candidate_cap_reached" {
		t.Fatalf("the §5.7 spelling is candidate_cap_reached, got %q", CandidateCapReached)
	}
}
