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
  - {name: g, group: "CN=g,OU=Groups,DC=example,DC=com", token_ttl: 60s, api: [revoke_others]}
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
		{"user:bob@example.com", "REVOKE_OTHERS", false},   // a right is matched exactly
		{"user:bob@example.com", "", false},
		{"user:bob@example.com", "revoke_everyone", false},
		// A group subject's rights are reached through the directory (plan
		// 7g), never by naming the group or the subject as a principal.
		{"CN=g,OU=Groups,DC=example,DC=com", RightRevokeOthers, false},
		{"g", RightRevokeOthers, false},
	} {
		if got := p.HasRight(c.principal, c.right); got != c.want {
			t.Errorf("HasRight(%s, %s) = %v", c.principal, c.right, got)
		}
	}
}
