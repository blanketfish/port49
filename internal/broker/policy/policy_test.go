package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustLoad(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// good is the shape spec §11 writes, cut down to what the slice reads.
const good = `
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: read_only, privilege: readonly, permit: ["show **"]}
  - {name: no_reload, deny: ["reload **"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com", "user:alice@corp.example"], username: alice,
     enable: token, token_ttl: 60s}
  - {name: noc, identity: ["user:bob@example.com"], username: bob, token_ttl: 900s}
  - {name: idle, identity: ["user:dave@example.com"], username: dave, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin, no_reload], max_privilege: admin}
  - {subject: noc, scope: all_devices, roles: [read_only]}
`

func TestAGoodPolicyLoads(t *testing.T) {
	p := mustLoad(t, good)
	if n, ok := p.SubjectOf("user:alice@corp.example"); !ok || n != "netops" {
		t.Fatalf("either identity resolves to the subject (spec §2): %q %v", n, ok)
	}
	if p.subjects["noc"].Enable != "none" {
		t.Fatalf("an unset enable is none — escalation is refused, never guessed (spec §7): %q", p.subjects["noc"].Enable)
	}
}

const roleOK = "roles:\n  - {name: r, privilege: admin, permit: [\"**\"]}\n"
const subjOK = "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}\n"
const grantOK = "grants:\n  - {subject: s, scope: all_devices, roles: [r]}\n"

// Every refusal names what is wrong and, where the slice is the reason, which
// plan lifts it. A key the slice does not read is refused, not ignored: an
// ignored `scopes:` block would be a policy that looks scoped and is not.
func TestLoadRefusesByName(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"a scopes block", roleOK + subjOK + grantOK + "scopes:\n  - {name: dc, match: {}}\n", "roles, subjects and grants only"},
		{"a second document", roleOK + subjOK + grantOK + "---\nscopes:\n  - {name: dc, match: {}}\n", "one YAML document"},
		{"one identity twice in a subject", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\", \"user:a@example.com\"], username: a, token_ttl: 60s}\n", "listed twice in subject \"s\""},
		{"a group subject", roleOK + "subjects:\n  - {name: s, group: G, username: a, token_ttl: 60s}\n", "field group"},
		{"operator", "roles:\n  - {name: r, privilege: operator}\n", "`operator` has no priv-lvl mapping"},
		{"an unknown level", "roles:\n  - {name: r, privilege: root}\n", "is not a privilege level"},
		{"an entity class", "roles:\n  - {name: r, deny: [\"interface @management\"]}\n", "plan 4"},
		{"a duplicate role", "roles:\n  - {name: r}\n  - {name: r}\n", "declared twice"},
		{"a machine identity", roleOK + "subjects:\n  - {name: s, identity: [\"spiffe://port49/x\"], username: a, token_ttl: 60s}\n", "plan 8"},
		{"no identity", roleOK + "subjects:\n  - {name: s, username: a, token_ttl: 60s}\n", "identity is required"},
		{"one identity, two subjects", roleOK + subjOK + "  - {name: t, identity: [\"user:a@example.com\"], username: b, token_ttl: 60s}\n", "listed by both"},
		{"an upper-case username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: Alice, token_ttl: 60s}\n", "already canonical"},
		{"a DOMAIN username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: 'CORP\\alice', token_ttl: 60s}\n", "already canonical"},
		{"a UPN username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: alice@corp, token_ttl: 60s}\n", "already canonical"},
		{"a shared username", roleOK + subjOK + "  - {name: t, identity: [\"user:b@example.com\"], username: a, token_ttl: 60s}\n", "unique across subjects"},
		{"enable auto", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, enable: auto, token_ttl: 60s}\n", "restricted"},
		{"enable nonsense", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, enable: maybe, token_ttl: 60s}\n", "none or token"},
		{"a short token_ttl", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 10s}\n", "between 30s and 15m0s"},
		{"no token_ttl", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a}\n", "between 30s and 15m0s"},
		{"a grant to nobody", roleOK + subjOK + "grants:\n  - {subject: x, scope: all_devices, roles: [r]}\n", "subject \"x\" is not declared"},
		{"another scope", roleOK + subjOK + "grants:\n  - {subject: s, scope: dc_fabric, roles: [r]}\n", "one scope, all_devices"},
		{"an unknown role", roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [x]}\n", "role \"x\" is not declared"},
		{"a grant with no roles", roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices}\n", "at least one role"},
		{"max_privilege operator", roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: operator}\n", "`operator` has no priv-lvl mapping"},
		{"a ceiling below the landing level", roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: readonly}\n", "above its grants' max_privilege"},
		{"a ceiling from another grant", roleOK + "  - {name: ro, privilege: readonly}\n" + subjOK +
			"grants:\n  - {subject: s, scope: all_devices, roles: [r]}\n  - {subject: s, scope: all_devices, roles: [ro], max_privilege: readonly}\n",
			"above its grants' max_privilege"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}
