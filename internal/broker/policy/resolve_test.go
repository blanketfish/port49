package policy

import (
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/blob"
)

// hashOf names b, failing the test if it does not encode: two refused blobs
// would otherwise compare equal as two empty names.
func hashOf(t *testing.T, b blob.Blob) string {
	t.Helper()
	_, h, err := blob.Encode(b)
	if err != nil || h == "" {
		t.Fatalf("Encode(%+v) = %q, %v", b, h, err)
	}
	return h
}

// Spec §5.1: roles are the union across the grants, privilege the max over the
// roles, max_privilege the max over the grants, and the attributes are
// rendered for the device's platform.
func TestResolveComposesTheGrantsForOnePlatform(t *testing.T) {
	p := mustLoad(t, good)
	r, ok := p.Resolve("user:alice@example.com", "arista_eos")
	if !ok || r.Subject != "netops" || r.Username != "alice" || r.Enable != "token" ||
		r.TokenTTL != 60*time.Second || r.MaxPrivilege != 15 {
		t.Fatalf("resolution: %+v %v", r, ok)
	}
	b := r.Blob
	if b.Platform != "arista_eos" || b.Privilege != 15 || len(b.Attributes) != 1 || b.Attributes[0] != "priv-lvl=15" ||
		len(b.Permit) != 1 || b.Permit[0] != "**" || len(b.Deny) != 1 || b.Deny[0] != "reload **" {
		t.Fatalf("blob: %+v", b)
	}
	if len(r.Grants) != 1 || r.Grants[0].Scope != "all_devices" || len(r.Grants[0].Roles) != 2 {
		t.Fatalf("grants on the record: %+v", r.Grants)
	}
	hashOf(t, b)
}

// One platform's session attributes (plan 3, Decided 6): every other platform
// gets a blob with the same rules and no attributes, and a different hash.
func TestOnlyAristaEOSGetsSessionAttributes(t *testing.T) {
	p := mustLoad(t, good)
	eos, _ := p.Resolve("user:alice@example.com", "arista_eos")
	nx, _ := p.Resolve("user:alice@example.com", "cisco_nxos")
	if len(nx.Blob.Attributes) != 0 || nx.Blob.Privilege != 15 || len(nx.Blob.Deny) != 1 {
		t.Fatalf("nx-os blob: %+v", nx.Blob)
	}
	if hashOf(t, eos.Blob) == hashOf(t, nx.Blob) {
		t.Fatal("two platforms must not share a blob")
	}
	bob, _ := p.Resolve("user:bob@example.com", "arista_eos")
	if bob.Blob.Privilege != 1 || len(bob.Blob.Attributes) != 1 || bob.Blob.Attributes[0] != "priv-lvl=1" ||
		bob.MaxPrivilege != 0 || bob.Enable != "none" {
		t.Fatalf("readonly renders as level 1, and an absent max_privilege is no ceiling: %+v", bob)
	}
}

// The same decision is the same blob: rules are deduplicated, normalized and
// sorted, so role order and repetition across grants do not change the hash.
func TestTheSameDecisionIsTheSameBlob(t *testing.T) {
	p := mustLoad(t, `
roles:
  - {name: a, permit: ["show  version", "show **"]}
  - {name: b, permit: ["show **"], deny: ["reload **"]}
subjects:
  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}
  - {name: t, identity: ["user:b@example.com"], username: b, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [a, b]}
  - {subject: s, scope: all_devices, roles: [b]}
  - {subject: t, scope: all_devices, roles: [b, a]}
`)
	s, _ := p.Resolve("user:a@example.com", "arista_eos")
	tt, _ := p.Resolve("user:b@example.com", "arista_eos")
	if len(s.Blob.Permit) != 2 || s.Blob.Permit[0] != "show **" || s.Blob.Permit[1] != "show version" {
		t.Fatalf("permits: %q", s.Blob.Permit)
	}
	if h1, h2 := hashOf(t, s.Blob), hashOf(t, tt.Blob); h1 != h2 {
		t.Fatalf("one decision, two blobs: %+v vs %+v", s.Blob, tt.Blob)
	}
}

func TestNoSubjectOrNoGrantResolvesToNothing(t *testing.T) {
	p := mustLoad(t, good)
	if _, ok := p.Resolve("user:carol@example.com", "arista_eos"); ok {
		t.Fatal("a principal no subject lists resolves to nothing")
	}
	if _, ok := p.Resolve("user:dave@example.com", "arista_eos"); ok {
		t.Fatal("a subject with no grant resolves to nothing: attached nothing, declared nothing (spec §5.5)")
	}
}
