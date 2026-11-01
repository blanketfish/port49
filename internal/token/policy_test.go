package token

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/decision"
)

// The minter writes the mint record, so the policy that allowed the mint has
// to reach it through the request: the broker knows the subject and the
// grants, the minter knows nothing of policy.
func TestAMintRecordCarriesThePolicyThatAllowedIt(t *testing.T) {
	m, _, log := minter(t)
	p := &decision.Policy{Subject: "netops", Grants: []decision.PolicyGrant{{Scope: "all_devices", Roles: []string{"network_admin"}}}}
	if _, err := m.Mint(context.Background(), Request{Subject: subject(), Device: "leaf-01", Platform: "arista_eos",
		TTL: time.Minute, Policy: p}); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(log.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if pol, _ := rec["policy"].(map[string]any); pol["subject"] != "netops" {
		t.Fatalf("mint record: %s", log.String())
	}
}
