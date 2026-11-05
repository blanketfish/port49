package broker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
)

const twoPrincipalPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: neteng, identity: ["user:bob@example.com"], username: bob, enable: token, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: neteng, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

// twoPrincipalsOn is a fixture of alice and bob, each holding an unspent
// token on every one of n extra devices, and the two the fixture names.
func twoPrincipalsOn(t *testing.T, n int) (*fixture, []string) {
	t.Helper()
	return twoPrincipalsOnPolicy(t, n, twoPrincipalPolicy)
}

func twoPrincipalsOnPolicy(t *testing.T, n int, policyText string) (*fixture, []string) {
	t.Helper()
	var extra []admission.Device
	for i := range n {
		extra = append(extra, admission.Device{Name: fmt.Sprintf("sw%02d", i), Platform: "cisco_nxos",
			Addresses: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("172.100.101.%d", i+1))}})
	}
	f := newFixtureWith(t, 8, policyText, extra...)
	bob := f.client(t, "bob@example.com", f.now.Add(24*3600e9))
	names := []string{"leaf1", "nx1"}
	for _, d := range extra {
		names = append(names, d.Name)
	}
	for _, c := range []string{"alice", "bob"} {
		cert := f.alice
		if c == "bob" {
			cert = bob
		}
		for _, name := range names {
			body := fmt.Sprintf(`{"devices":[%q]}`, name)
			if it := decodeMint(t, f.post(context.Background(), f.state(cert), body, "")).Results[0]; it.Verdict != "permit" {
				t.Fatalf("%s on %s: %+v", c, name, it)
			}
		}
	}
	return f, names
}

func (f *fixture) reloadTwo(t *testing.T, body string) []Prior {
	t.Helper()
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: f.inventory(), Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
}

// A pass over two principals on N devices supersedes what it did before the
// memo held digests: a shortened token_ttl for alice alone supersedes alice's
// token on every device, and bob's stands.
func TestASupersedePassOverTwoPrincipalsSupersedesTheSameKeys(t *testing.T) {
	f, names := twoPrincipalsOn(t, 6)
	alice := strings.Replace(twoPrincipalPolicy, "username: alice, enable: token, token_ttl: 60s",
		"username: alice, enable: token, token_ttl: 30s", 1)
	rep, err := f.b.Refresh(context.Background(), f.reloadTwo(t, alice))
	if err != nil {
		t.Fatal(err)
	}
	if rep.TokenKeys != len(names) {
		t.Fatalf("%d keys superseded, want %d: %+v", rep.TokenKeys, len(names), rep)
	}
	for _, name := range names {
		if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: name, Username: "alice"}); len(toks) != 0 {
			t.Fatalf("alice's token on %s stands", name)
		}
		if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: name, Username: "bob"}); len(toks) != 1 {
			t.Fatalf("bob's token on %s: %d standing", name, len(toks))
		}
	}
}

// The pass's memo of what the policy in force mints holds one principal's
// devices at a time, not every (principal, device) of the pass: at 500
// principals on 10 000 devices the blobs it held reached 3.4 GB.
func TestTheSupersedeMemoIsBoundedByTheDeviceCount(t *testing.T) {
	f, names := twoPrincipalsOn(t, 6)
	peak := 0
	supersedeMemoSize = func(n int) { peak = max(peak, n) }
	t.Cleanup(func() { supersedeMemoSize = nil })
	alice := strings.Replace(twoPrincipalPolicy, "token_ttl: 60s", "token_ttl: 30s", 2)
	if _, err := f.b.Refresh(context.Background(), f.reloadTwo(t, alice)); err != nil {
		t.Fatal(err)
	}
	if peak == 0 || peak > len(names) {
		t.Fatalf("the memo peaked at %d entries over %d devices", peak, len(names))
	}
}

// Two answers that differ in their body alone, a role's permit list, are
// not kept as one: the digest tells them apart, as the body did.
func TestABodyOnlyChangeSupersedesAndLeavesTheRestAlone(t *testing.T) {
	const split = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: alice_role, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: neteng, identity: ["user:bob@example.com"], username: bob, enable: token, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [alice_role], max_privilege: admin}
  - {subject: neteng, scope: all_devices, roles: [network_admin], max_privilege: admin}
`
	f, names := twoPrincipalsOnPolicy(t, 6, split)
	narrowed := strings.Replace(split, `{name: alice_role, privilege: admin, permit: ["**"]}`,
		`{name: alice_role, privilege: admin, permit: ["show **"]}`, 1)
	rep, err := f.b.Refresh(context.Background(), f.reloadTwo(t, narrowed))
	if err != nil {
		t.Fatal(err)
	}
	if rep.TokenKeys != len(names) {
		t.Fatalf("%d keys superseded, want %d: %+v", rep.TokenKeys, len(names), rep)
	}
	for _, name := range names {
		if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: name, Username: "alice"}); len(toks) != 0 {
			t.Fatalf("alice's token on %s stands after her blob changed", name)
		}
		if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: name, Username: "bob"}); len(toks) != 1 {
			t.Fatalf("bob's token on %s: %d standing", name, len(toks))
		}
	}
}

// keeps tells two bodies apart by their digests.
func TestKeepsComparesTheBodyDigest(t *testing.T) {
	a := minted{username: "a", ttl: time.Minute, body: sha256.Sum256([]byte("one"))}
	b := a
	b.body = sha256.Sum256([]byte("two"))
	if !a.keeps(a) || a.keeps(b) {
		t.Fatal("keeps must keep an equal body and supersede a different one")
	}
}
