package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
)

// spec11Env is the corpus's environment: its own inventory file and the
// built-in platforms as shipped. §11 lands bgp_operator and interface_tech at
// `operator`, which arista_eos renders as admin's level since the owner's
// ruling of 2026-09-24 (spec §6, decision 23), so §11 loads without a
// test-only mapping.
func spec11Env(t *testing.T) Env {
	t.Helper()
	inv, err := admission.LoadFile("testdata/spec11-inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return Env{Devices: inv.Devices}
}

func spec11(t *testing.T, raw []byte) *Policy {
	t.Helper()
	p, err := Parse(raw, spec11Env(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func spec11Raw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/spec11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Spec §11's own tests pass, on the day the corpus was written: its dc_fabric
// grant expires 2026-12-01.
func TestTheCompletePolicyExamplePassesItsOwnTests(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	if q := p.Quarantines(noon); len(q) != 0 {
		t.Fatalf("§11 quarantines nothing on its own inventory: %+v", q)
	}
	results := p.RunTests(noon)
	if len(results) != 8 {
		t.Fatalf("%d results", len(results))
	}
	for _, r := range results {
		if !r.Pass {
			t.Errorf("%s on %s %q: got permit=%v %s (err %v), want %s", r.Test.Subject, r.Test.Device,
				r.Test.Command, r.Permit, r.Reason, r.Err, r.Test.Expect)
		}
	}
	// The pipeline test passes on port49's evaluation, denied at the redirect
	// stage and not for want of a permit, and says the device would never
	// have sent the pipeline (tests/lab/results/L2-arista_eos.md).
	if results[2].Reason != decision.PipeStageDenied || results[2].Outcome.Stage != 1 {
		t.Errorf("the redirect test is denied at its pipe stage: %s stage %d", results[2].Reason, results[2].Outcome.Stage)
	}
	if c := results[2].Caveats; len(c) != 1 || !strings.Contains(c[0], "pipe_authorized: false") {
		t.Errorf("caveats on the redirect test: %q", c)
	}
	// And Junos never asks at all (decision 21).
	if c := results[4].Caveats; len(c) != 1 || !strings.Contains(c[0], "does not send per-command authorization") {
		t.Errorf("caveats on the SRX test: %q", c)
	}
}

// The three things spec §11 says it is chosen to show, as decisions.
func TestTheCompletePolicyExampleShowsWhatItSays(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	leaf, _ := p.Device("leaf-01")
	campus, _ := p.Device("campus-sw-7")
	srx, _ := p.Device("srx-fw-04")
	patched, _ := p.Device("srx-fw-05")
	type claim struct {
		subject string
		device  admission.Device
		line    string
		permit  bool
		reason  decision.Reason
		deny    string // the matched deny, role/rule, where the claim names one
	}
	for _, tt := range []claim{
		// "interface @management carries all the platform-specific knowledge".
		{"noc_tier1", leaf, "interface Ethernet3", true, decision.PermitDominates, ""},
		{"noc_tier1", leaf, "interface Management1", false, decision.NoRuleMatched, "interface_tech/interface @management"},
		{"noc_tier1", campus, "interface Ethernet3", false, decision.NoRuleMatched, ""}, // dc_fabric only
		{"noc_tier1", leaf, "clear counters", false, decision.NoRuleMatched, ""},
		{"noc_tier1", leaf, "reload", false, decision.NoRuleMatched, "no_disruptive/reload **"},
		// svc_oxidized composes two roles: commands from one, level from the other.
		{"svc_oxidized", leaf, "configure terminal", false, decision.NoRuleMatched, ""},
		// The mitigation lifts per device as it is remediated.
		{"noc_tier1", patched, "show chassis cluster status", true, decision.PermitDominates, ""},
		{"noc_tier1", srx, "show chassis cluster", false, decision.NoPermitDominatesDeny, "cve_2026_xxxx/show chassis cluster **"},
		{"netops_admins", srx, "show chassis cluster status", false, decision.NoPermitDominatesDeny, "cve_2026_xxxx/show chassis cluster **"},
		{"netops_admins", leaf, "show run | redirect ftp://x", true, decision.PermitDominates, ""},
		{"security_ir", leaf, "show version", false, decision.NoGrantsMatched, ""},
	} {
		checkClaim(t, p, tt.subject, tt.device, tt.line, tt.permit, tt.reason, tt.deny)
	}
	// The denies above that decide nothing on §11 as written, because no
	// permit reaches their commands, decide once one does: noc_tier1 also
	// holding network_admin's `**`, which dominates none of them.
	broad, err := Parse([]byte(strings.Replace(string(spec11Raw(t)),
		"roles: [read_only, no_disruptive]}", "roles: [read_only, no_disruptive, network_admin]}", 1)), spec11Env(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []claim{
		{"noc_tier1", leaf, "interface Ethernet3", true, decision.PermitDominates, ""},
		{"noc_tier1", leaf, "interface Management1", false, decision.NoPermitDominatesDeny, "interface_tech/interface @management"},
		{"noc_tier1", leaf, "reload", false, decision.NoPermitDominatesDeny, "no_disruptive/reload **"},
		{"noc_tier1", leaf, "write erase startup-config", false, decision.NoPermitDominatesDeny, "no_disruptive/write erase **"},
		{"noc_tier1", srx, "show chassis cluster status", false, decision.NoPermitDominatesDeny, "cve_2026_xxxx/show chassis cluster **"},
	} {
		checkClaim(t, broad, tt.subject, tt.device, tt.line, tt.permit, tt.reason, tt.deny)
	}
	res, err := p.ResolveSubject("svc_oxidized", leaf, noon)
	if err != nil || res.Level != "admin" || len(res.Blob.Attributes) == 0 || res.Blob.Attributes[0] != "priv-lvl=15" {
		t.Fatalf("svc_oxidized lands at admin, from elevated_session: %+v %v", res, err)
	}
	limited, err := Parse([]byte(strings.Replace(string(spec11Raw(t)),
		"roles: [read_only, no_disruptive]}", "roles: [read_only_limited, no_disruptive]}", 1)), spec11Env(t))
	if err != nil {
		t.Fatal(err)
	}
	r, err := limited.ResolveSubject("noc_tier1", campus, noon)
	if err != nil || len(r.Blob.Attributes) == 0 || r.Blob.Attributes[0] != "priv-lvl=1" {
		t.Fatalf("read_only_limited renders as its parent readonly: %+v %v", r.Blob.Attributes, err)
	}
}

// checkClaim decides one line and checks the verdict, the reason and, where
// deny is set, the deny the record names as role/rule.
func checkClaim(t *testing.T, p *Policy, subject string, d admission.Device, line string, permit bool,
	reason decision.Reason, deny string) {
	t.Helper()
	_, o, err := p.Decide(subject, "", d, line, noon)
	if reason == decision.NoGrantsMatched {
		if !errors.Is(err, ErrNoGrants) {
			t.Errorf("%s on %s: %v, want no grants", subject, d.Name, err)
		}
		return
	}
	if err != nil || o.Permit != permit || o.Reason != reason {
		t.Errorf("%s on %s %q: permit=%v %s %v, want %v %s", subject, d.Name, line, o.Permit, o.Reason, err,
			permit, reason)
		return
	}
	if deny == "" {
		return
	}
	if o.Deny == nil || o.Deny.Role+"/"+o.Deny.Rule != deny {
		t.Errorf("%s on %s %q: matched deny %+v, want %s", subject, d.Name, line, o.Deny, deny)
	}
}

// What CI reports about §11: three group subjects nobody can mint for until
// plan 7, and the SRX whose version the comparator could not order, included
// in the mitigation and named (spec §5.5).
func TestTheCompletePolicyExampleReportsWhatItShould(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	var kinds []string
	var incomparable string
	for _, f := range p.Lint(noon) {
		kinds = append(kinds, f.Kind)
		if f.Kind == FindingIncomparableVersion {
			incomparable = f.Message
		}
	}
	want := []string{FindingGroupSubject, FindingGroupSubject, FindingGroupSubject, FindingIncomparableVersion}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("findings %q, want %q", kinds, want)
	}
	if !strings.Contains(incomparable, "srx-fw-22") || !strings.Contains(incomparable, "os_version 21.4X75-D40 lt 21.4R3-S5") {
		t.Fatalf("the report names the device and the comparison: %s", incomparable)
	}
}

// Order independence (spec §5.4; §14): the same policy with its roles, scopes,
// subjects, grants and every rule list shuffled decides every test identically,
// down to which rule and role each decision names, and compiles every subject
// on every device to the same level and the same blob bytes.
func TestShufflingThePolicyChangesNoDecision(t *testing.T) {
	raw := spec11Raw(t)
	want := decisions(t, spec11(t, raw))
	wantBlobs := blobs(t, spec11(t, raw))
	r := rand.New(rand.NewSource(49))
	for i := 0; i < 10; i++ {
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		shuffle(r, doc.Content[0])
		out, err := yaml.Marshal(&doc)
		if err != nil {
			t.Fatal(err)
		}
		shuffled := spec11(t, out)
		if got := decisions(t, shuffled); !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d changed a decision:\n got %s\nwant %s\npolicy:\n%s", i, got, want, out)
		}
		if got := blobs(t, shuffled); !reflect.DeepEqual(got, wantBlobs) {
			t.Fatalf("shuffle %d changed a blob:\n got %s\nwant %s\npolicy:\n%s", i, got, wantBlobs, out)
		}
	}
}

// decisions renders every test's outcome as its record's policy block, with
// the bundle and blob hashes left out: those name the file's bytes, which a
// shuffle changes by design.
func decisions(t *testing.T, p *Policy) []string {
	t.Helper()
	var out []string
	for _, r := range p.RunTests(noon) {
		pol := r.Outcome.Policy("", "")
		b, err := json.Marshal(struct {
			Permit bool
			Reason decision.Reason
			Policy *decision.Policy
		}{r.Permit, r.Reason, pol})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

// blobs renders every subject on every device as its level, its encoded blob
// and its rules as Resolve returns them (what explain reads), with the bundle
// fixed: it names the file's bytes, which a shuffle changes by design.
func blobs(t *testing.T, p *Policy) []string {
	t.Helper()
	names := make([]string, 0, len(p.subs))
	for name := range p.subs {
		names = append(names, name)
	}
	slices.Sort(names)
	var out []string
	for _, name := range names {
		for _, d := range p.env.Devices {
			res, err := p.ResolveSubject(name, d, noon)
			if err != nil {
				out = append(out, fmt.Sprintf("%s on %s: %v", name, d.Name, err))
				continue
			}
			res.Blob.Bundle = "sha256:fixed"
			body, _, err := engine.Encode(res.Blob)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%s on %s: %s %s %v", name, d.Name, res.Level, body, res.Blob.Rules))
		}
	}
	return out
}

// shuffle permutes every sequence under the top-level keys that order must not
// matter for: the lists themselves and every list inside their entries.
func shuffle(r *rand.Rand, top *yaml.Node) {
	for i := 0; i+1 < len(top.Content); i += 2 {
		switch top.Content[i].Value {
		case "roles", "scopes", "subjects", "grants":
			shuffleDeep(r, top.Content[i+1])
		}
	}
}

func shuffleDeep(r *rand.Rand, n *yaml.Node) {
	if n.Kind == yaml.SequenceNode {
		r.Shuffle(len(n.Content), func(i, j int) { n.Content[i], n.Content[j] = n.Content[j], n.Content[i] })
	}
	for _, c := range n.Content {
		shuffleDeep(r, c)
	}
}
