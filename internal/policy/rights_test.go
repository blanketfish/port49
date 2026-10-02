package policy

import "testing"

// A right is held through the subject a principal's identity list names
// (spec §2): a principal no subject names holds none, and a subject holds
// only what its api: list says.
func TestHasRightReadsTheSubjectsList(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects:
  - {name: oncall, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s, api: [revoke_others, sync]}
  - {name: ops, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
grants: [{subject: ops, scope: all_devices, roles: [r]}]`)
	for _, c := range []struct {
		principal, right string
		want             bool
	}{
		{"user:bob@example.com", RightRevokeOthers, true},
		{"user:bob@example.com", RightSync, true},
		{"user:bob@example.com", RightExplainOthers, false},
		{"user:alice@example.com", RightRevokeOthers, false},
		{"user:carol@example.com", RightRevokeOthers, false},
		{"user:BOB@example.com", RightRevokeOthers, false}, // the caller's spelling is the broker's, lower-cased
	} {
		if got := p.HasRight(c.principal, c.right); got != c.want {
			t.Errorf("HasRight(%s, %s) = %v", c.principal, c.right, got)
		}
	}
}
