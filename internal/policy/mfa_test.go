package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
)

// mfaBase is what every per_login_mfa test file shares: two devices, a
// person (alice) granted netadmin and a workload (oxidized) granted backup on
// all of them, and two more identities for the tests that compose subjects.
// A test's own YAML is merged over it: a role, scope or subject it names
// replaces the base's of that name.
const mfaBase = `
subjects:
  - {name: alice, identity: ["user:alice@example.com"], token_ttl: 5m}
  - {name: alice-group, identity: ["user:alice-g@example.com"], token_ttl: 5m}
  - {name: alice-core, identity: ["user:alice-c@example.com"], token_ttl: 5m}
  - {name: oxidized, identity: ["spiffe://example.com/oxidized"], username: oxidized, token_ttl: 5m}
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: netadmin, privilege: admin, permit: ["**"]}
  - {name: backup, privilege: readonly, permit: ["show **"]}
grants:
  - {subject: alice, scope: all_devices, roles: [netadmin]}
  - {subject: oxidized, scope: all_devices, roles: [backup]}
`

func mfaEnv() Env {
	dev := func(name, tier, addr string) admission.Device {
		return admission.Device{Name: name, Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr(addr)},
			Attributes: map[string]string{"tier": tier}}
	}
	return Env{Now: noon, Devices: []admission.Device{dev("core-sw01", "core", "10.9.0.1"),
		dev("edge-sw01", "edge", "10.9.0.2")}}
}

// mfaYAML is user merged over mfaBase.
func mfaYAML(user string) ([]byte, error) {
	var base, extra map[string]any
	if err := yaml.Unmarshal([]byte(mfaBase), &base); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal([]byte(user), &extra); err != nil {
		return nil, err
	}
	for key, v := range extra {
		list, isList := v.([]any)
		have, hadList := base[key].([]any)
		switch {
		case !isList || !hadList:
			base[key] = v
		case key == "grants" || key == "tests":
			base[key] = append(have, list...)
		default:
			named := map[string]bool{}
			for _, e := range list {
				named[fmt.Sprint(e.(map[string]any)["name"])] = true
			}
			for _, e := range have {
				if !named[fmt.Sprint(e.(map[string]any)["name"])] {
					list = append(list, e)
				}
			}
			base[key] = list
		}
	}
	return yaml.Marshal(base)
}

// bundleMFA loads user as a start does: a device whose requirement no
// method meets is quarantined, not a load error.
func bundleMFA(user string) (*Policy, error) {
	raw, err := mfaYAML(user)
	if err != nil {
		return nil, err
	}
	return Parse(raw, mfaEnv())
}

// loadMFA loads user as `policy test` reads it: every quarantine is a failure,
// the first an MFA one named as ErrMFADisjoint.
func loadMFA(user string) (*Policy, error) {
	p, err := bundleMFA(user)
	if err != nil {
		return nil, err
	}
	if q := p.MFADisjoint(); len(q) > 0 {
		return nil, fmt.Errorf("%w: %s: %s", ErrMFADisjoint, q[0].Device, q[0].Entries[0].Cause)
	}
	return p, nil
}

func mfaPolicy(t *testing.T, user string) *Policy {
	t.Helper()
	p, err := loadMFA(user)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mfaBundle(t *testing.T, user string) *Policy {
	t.Helper()
	p, err := bundleMFA(user)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// resolve resolves a subject by name, as the offline tools do.
func resolve(t *testing.T, p *Policy, subject, deviceName string) Resolution {
	t.Helper()
	res, err := p.ResolveSubject(subject, device(t, p, deviceName), noon)
	if err != nil {
		t.Fatalf("%s on %s: %v", subject, deviceName, err)
	}
	return res
}

// sessionTest is one session test's run: OK, and when it failed what it
// asserted against what the policy resolved.
type sessionTest struct {
	OK      bool
	Message string
}

// runSessionTest adds entry, a flow-style `tests:` item, to p's file and runs
// it.
func runSessionTest(t *testing.T, p *Policy, entry string) sessionTest {
	t.Helper()
	q, err := Parse(append(append([]byte(nil), p.raw...), []byte("\ntests:\n  - "+entry+"\n")...), p.env)
	if err != nil {
		t.Fatal(err)
	}
	results := q.RunTests(noon)
	if len(results) != 1 {
		t.Fatalf("%d results for one test", len(results))
	}
	r := results[0]
	if r.Pass {
		return sessionTest{OK: true}
	}
	return sessionTest{Message: fmt.Sprintf("per_login_mfa: asserted %s, resolved %s", r.Test.MFA, r.PerLoginMFA)}
}

// diffRun is `port49 policy diff` over two policy texts: the per_login_mfa
// lines it prints, and the exit code it would give.
func diffRun(t *testing.T, oldYAML, newYAML string) (string, int) {
	t.Helper()
	before, after := mfaBundle(t, oldYAML), mfaBundle(t, newYAML)
	d := Compare(before, after, noon)
	var out strings.Builder
	for _, c := range d.MFA {
		out.WriteString(c.Line("") + "\n")
	}
	code := 0
	if d.UnacknowledgedMFA() > 0 || len(d.Quarantined) > 0 {
		code = 1
	}
	return out.String(), code
}

// strictestPolicy is three levels on core-sw01 and two on edge-sw01.
const strictestPolicy = `
defaults:
  per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}
roles:
  - name: netadmin
    permit: ["**"]
    per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 30m}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include
    security_log: true
    per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}
`

func TestTheStrictestLevelWins(t *testing.T) {
	p := mfaPolicy(t, strictestPolicy)
	res := resolve(t, p, "alice", "core-sw01")
	want := MFARequirement{Accept: []MFAMethod{HardwareKeyTouch}, ReuseFor: 5 * time.Minute, ReuseFrom: "scope core",
		Levels: []MFALevel{
			{Level: "defaults", Accept: []MFAMethod{HardwareKeyTouch, IdPMFA}, ReuseFor: 15 * time.Minute},
			{Level: "role netadmin", Accept: []MFAMethod{HardwareKeyTouch, IdPMFA}, ReuseFor: 30 * time.Minute},
			{Level: "scope core", Accept: []MFAMethod{HardwareKeyTouch}, ReuseFor: 5 * time.Minute,
				Select: `match {"tier" in ["core"]} on_missing "include"`},
		}}
	if !reflect.DeepEqual(res.PerLoginMFA, want) {
		t.Fatalf("core-sw01: %+v\nwant %+v", res.PerLoginMFA, want)
	}
	edge := resolve(t, p, "alice", "edge-sw01")
	if edge.PerLoginMFA.ReuseFor != 15*time.Minute || len(edge.PerLoginMFA.Accept) != 2 {
		t.Fatalf("edge-sw01: %+v", edge.PerLoginMFA)
	}
}

func TestOneDeviceIsAScopeByName(t *testing.T) {
	p := mfaPolicy(t, `
scopes:
  - name: core-sw01
    match: {name: core-sw01}
    per_login_mfa: {accept: [hardware_key_touch], reuse_for: 0m}
`)
	if r := resolve(t, p, "alice", "core-sw01").PerLoginMFA; !r.Required() || r.ReuseFor != 0 {
		t.Fatalf("core-sw01: %+v", r)
	}
	if r := resolve(t, p, "alice", "edge-sw01").PerLoginMFA; r.Required() {
		t.Fatalf("edge-sw01 has a requirement: %+v", r)
	}
}

// disjointPolicy's role and scope share no method on core-sw01 alone.
const disjointPolicy = `
roles:
  - name: netadmin
    permit: ["**"]
    per_login_mfa: {accept: [idp_mfa]}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include
    security_log: true
    per_login_mfa: {accept: [hardware_key_touch]}
`

func TestDisjointLevelsRefuseTheLoad(t *testing.T) {
	_, err := loadMFA(disjointPolicy)
	if !errors.Is(err, ErrMFADisjoint) || !strings.Contains(err.Error(), "role netadmin") ||
		!strings.Contains(err.Error(), "scope core") || !strings.Contains(err.Error(), "core-sw01") {
		t.Fatalf("load = %v, want ErrMFADisjoint naming both levels and the device", err)
	}
	// loadMFA is `policy test`'s reading: a load error. The bundle itself,
	// loaded as a start or an inventory reload loads it, quarantines core-sw01
	// alone with the same cause, and edge-sw01 resolves (ruling 11; pre-flight
	// I4).
	p := mfaBundle(t, disjointPolicy)
	if q := p.MFADisjoint(); len(q) != 1 || q[0].Device != "core-sw01" || !strings.Contains(q[0].Entries[0].Cause, "scope core") {
		t.Fatalf("MFADisjoint = %+v, want core-sw01 alone", q)
	}
	// Resolve(principal, d, now): resolve.go:102 (re-review R7).
	if _, err := p.Resolve("user:alice@example.com", device(t, p, "edge-sw01"), time.Now()); err != nil {
		t.Fatalf("edge-sw01 under a disjoint core-sw01: %v", err)
	}
	// A machine-applying level that leaves a machine only idp_mfa: a machine
	// has no sign-in.
	_, err = loadMFA(`
defaults:
  per_login_mfa: {accept: [idp_mfa], applies_to_machines: true}
`)
	if err == nil || !strings.Contains(err.Error(), "machine") || !strings.Contains(err.Error(), "hardware_key_touch") {
		t.Fatalf("load = %v, want a refusal saying a machine proves by hardware_key_touch", err)
	}
}

func TestMachinesAreExemptUnlessALevelSaysSo(t *testing.T) {
	p := mfaPolicy(t, `
defaults:
  per_login_mfa: {accept: [hardware_key_touch]}
`)
	if r := resolve(t, p, "oxidized", "core-sw01").PerLoginMFA; r.Required() {
		t.Fatalf("a machine under defaults alone has a requirement: %+v", r)
	}
	p = mfaPolicy(t, `
defaults:
  per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}
`)
	if r := resolve(t, p, "oxidized", "core-sw01").PerLoginMFA; !r.Required() {
		t.Fatal("applies_to_machines: true did not apply")
	}
}

func TestPerLoginMFASchemaRefusals(t *testing.T) {
	for _, bad := range []struct{ yaml, says string }{
		{`defaults: {per_login_mfa: {accept: []}}`, "accept"},
		{`defaults: {per_login_mfa: {}}`, "accept"},
		{`defaults: {per_login_mfa: {accept: [none]}}`, "none"},
		{`defaults: {per_login_mfa: {accept: [touch]}}`, "hardware_key_touch or idp_mfa"},
		// A boolean fails yaml.v3's strict decode before the vocabulary
		// check reads it (pre-flight minor 12): refused all the same.
		{`defaults: {per_login_mfa: {accept: [true]}}`, "true"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa, idp_mfa]}}`, "twice"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa], reuse_for: 9h}}`, "8h"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa], reuse_for: -1m}}`, "reuse_for"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa], required: true}}`, "required"},
		{`defaults: {mfa: required}`, "mfa"},
		{"scopes:\n  - name: core\n    match: {tier: core}\n    security_log: true\n    per_login_mfa: {accept: [idp_mfa]}", "on_missing"},
		{"scopes:\n  - name: core\n    match: {tier: core}\n    on_missing: include\n    per_login_mfa: {accept: [idp_mfa]}", "security_log"},
	} {
		if _, err := loadMFA(bad.yaml); err == nil || !strings.Contains(err.Error(), bad.says) {
			t.Errorf("load %q = %v, want an error naming %q", bad.yaml, err, bad.says)
		}
	}
	// A scope pinned by name alone needs neither on_missing nor security_log:
	// name is always present and no attribute edit lifts it (ruling 11;
	// pre-flight I2).
	if _, err := loadMFA("scopes:\n  - name: core-sw01\n    match: {name: core-sw01}\n    per_login_mfa: {accept: [idp_mfa]}"); err != nil {
		t.Errorf("a name-pinned scope: %v", err)
	}
	// name with another key is an attribute scope: both still required.
	if _, err := loadMFA("scopes:\n  - name: c\n    match: {name: core-sw01, tier: core}\n    per_login_mfa: {accept: [idp_mfa]}"); err == nil {
		t.Error("a scope matching name and tier loaded without on_missing")
	}
}

// Two subjects of one principal compose only at mint: a disjoint pair there
// is composition_refused, never a broker fault (ruling 11; pre-flight I3).
func TestADisjointCompositionIsRefusedNotAFault(t *testing.T) {
	p := mfaPolicy(t, `
roles:
  - name: netadmin
    permit: ["**"]
    per_login_mfa: {accept: [idp_mfa]}
  - name: core-ops
    permit: ["show **"]
    per_login_mfa: {accept: [hardware_key_touch]}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include
grants:
  - {subject: alice-group, scope: all_devices, roles: [netadmin]}
  - {subject: alice-core, scope: core, roles: [core-ops]}
`) // alice-group and alice-core are two subjects one principal matches.
	// Each alone loads; only their composition on core-sw01 is disjoint.
	_, err := p.ResolveSubjects([]string{"alice-group", "alice-core"}, "", device(t, p, "core-sw01"), time.Now())
	if !errors.Is(err, ErrCompositionRefused) || !strings.Contains(err.Error(), "per_login_mfa") {
		t.Fatalf("ResolveSubjects = %v, want ErrCompositionRefused naming per_login_mfa", err)
	}
}

func TestExplainPrintsTheEffectiveRequirement(t *testing.T) {
	p := mfaPolicy(t, strictestPolicy)
	for device, want := range map[string]string{
		"core-sw01": "  per_login_mfa accept hardware_key_touch (defaults ∩ role netadmin ∩ scope core); " +
			"reuse_for 5m (scope core); applies to humans\n",
		"edge-sw01": "  per_login_mfa accept hardware_key_touch, idp_mfa (defaults ∩ role netadmin); " +
			"reuse_for 15m (defaults); applies to humans\n",
	} {
		e, err := p.Explain("alice", "", device, "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		e.RenderWithoutAttributes(&b)
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s: explain says\n%s\nwant the line %q", device, b.String(), want)
		}
	}
	none := mfaPolicy(t, "")
	e, _ := none.Explain("alice", "", "core-sw01", "", time.Now())
	var b strings.Builder
	e.RenderWithoutAttributes(&b)
	if !strings.Contains(b.String(), "  per_login_mfa none\n") {
		t.Errorf("no requirement: explain says\n%s", b.String())
	}
}

func TestPolicyTestAssertsTheRequirement(t *testing.T) {
	p := mfaPolicy(t, strictestPolicy)
	pass := runSessionTest(t, p, `{subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}`)
	if !pass.OK {
		t.Fatalf("the matching assertion failed: %s", pass.Message)
	}
	fail := runSessionTest(t, p, `{subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 15m}}`)
	if fail.OK || !strings.Contains(fail.Message, "15m") || !strings.Contains(fail.Message, "5m") {
		t.Fatalf("a wrong reuse_for: %+v, want a failure naming both", fail)
	}
	none := runSessionTest(t, p, `{subject: alice, device: core-sw01, per_login_mfa: none}`)
	if none.OK {
		t.Fatal("per_login_mfa: none passed on a device with a requirement")
	}
}

func TestPolicyDiffGatesAWeakening(t *testing.T) {
	weaker := strings.Replace(strictestPolicy, "accept: [hardware_key_touch], reuse_for: 5m",
		"accept: [hardware_key_touch, idp_mfa], reuse_for: 5m", 1)
	out, code := diffRun(t, strictestPolicy, weaker)
	if !strings.Contains(out, "per_login_mfa:") || !strings.Contains(out, "core-sw01") ||
		!strings.Contains(out, "per_login_mfa_weakened:") || code == 0 {
		t.Fatalf("an unacknowledged weakening must print and fail (exit %d):\n%s", code, out)
	}
	// A session test asserting the new requirement acknowledges it, as for a privilege raise.
	acked := weaker + `
tests:
  - {subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 5m}}
`
	if out, code := diffRun(t, strictestPolicy, acked); code != 0 {
		t.Fatalf("an acknowledged weakening failed (exit %d):\n%s", code, out)
	}
	// A test asserting the old requirement does not acknowledge the new one.
	stale := weaker + `
tests:
  - {subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}
`
	if _, code := diffRun(t, strictestPolicy, stale); code == 0 {
		t.Fatal("a test asserting the old requirement acknowledged the weakening")
	}
	// A longer reuse_for is a weakening too.
	longer := strings.Replace(strictestPolicy, "reuse_for: 5m", "reuse_for: 30m", 1)
	if _, code := diffRun(t, strictestPolicy, longer); code == 0 {
		t.Fatal("a longer reuse_for passed the gate")
	}
	tighter := strings.Replace(strictestPolicy, "reuse_for: 5m", "reuse_for: 1m", 1)
	if out, code := diffRun(t, strictestPolicy, tighter); !strings.Contains(out, "per_login_mfa:") || code != 0 {
		t.Fatalf("a tightening must print and pass (exit %d):\n%s", code, out)
	}
}

// A name-pinned scope swapped for an attribute scope at the same level count
// and the same accept and reuse_for is a level removed: a sync that drops the
// attribute lifts what no attribute edit could (spec §12; decision 45 ruling
// 24). The line names the levels, so before and after read differently.
func TestPolicyDiffGatesAReplacedLevel(t *testing.T) {
	const pinned = `
defaults: {per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}}
scopes:
  - {name: core-sw01, match: {name: core-sw01}, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}
`
	const byTier = `
defaults: {per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}}
scopes:
  - {name: core, match: {tier: core}, on_missing: exclude, security_log: true,
     per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}
`
	out, code := diffRun(t, pinned, byTier)
	if code == 0 || !strings.Contains(out, "per_login_mfa_weakened: alice on core-sw01") ||
		!strings.Contains(out, "(defaults ∩ scope core-sw01) -> accept [hardware_key_touch] reuse_for 5m (defaults ∩ scope core)") {
		t.Fatalf("a replaced level passed the gate (exit %d):\n%s", code, out)
	}
	// The same swap with a session test asserting the requirement is acknowledged.
	if out, code := diffRun(t, pinned, byTier+"tests:\n  - {subject: alice, device: core-sw01, per_login_mfa: "+
		"{accept: [hardware_key_touch], reuse_for: 5m}}\n"); code != 0 {
		t.Fatalf("an acknowledged replacement failed (exit %d):\n%s", code, out)
	}
}

// A level's identity is the scope's selector and on_missing as well as its
// name: any change to either is a weakening, fail-closed, because no one can
// prove the new selector covers a superset of devices now and after a later
// inventory sync (the controller's Task 9 re-review ruling, decision 45
// ruling 24).
func TestPolicyDiffGatesAScopeWhoseSelectorMoved(t *testing.T) {
	const mfa = `per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}`
	const assertion = "tests:\n  - {subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}\n"
	for name, c := range map[string]struct{ old, new string }{
		"name pin to attribute, same name (P4)": {
			"scopes:\n  - {name: hot, match: {name: core-sw01}, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {tier: core}, on_missing: exclude, security_log: true, " + mfa + "\n"},
		"on_missing include to exclude (P5)": {
			"scopes:\n  - {name: hot, match: {tier: core}, on_missing: include, security_log: true, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {tier: core}, on_missing: exclude, security_log: true, " + mfa + "\n"},
		"name pin gains an attribute (P9)": {
			"scopes:\n  - {name: hot, match: {name: core-sw01}, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {name: core-sw01, tier: core}, on_missing: exclude, security_log: true, " + mfa + "\n"},
		// Values that contain the old encoding's separators must not collide
		// with the same text split into separate values (E1e).
		"a value with a separator becomes two values (E1e)": {
			"scopes:\n  - {name: hot, match: {tier: [core, \"a|b\"]}, on_missing: include, security_log: true, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {tier: [core, a, b]}, on_missing: include, security_log: true, " + mfa + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			out, code := diffRun(t, c.old, c.new)
			if code == 0 || !strings.Contains(out, "per_login_mfa_weakened: alice on core-sw01") {
				t.Fatalf("a moved selector passed the gate (exit %d):\n%s", code, out)
			}
			// The line does not read the same on both sides.
			if !strings.Contains(out, "scope hot [match {") {
				t.Fatalf("the line does not say what the scope selects now:\n%s", out)
			}
			if out, code := diffRun(t, c.old, c.new+assertion); code != 0 {
				t.Fatalf("an acknowledged selector change failed (exit %d):\n%s", code, out)
			}
		})
	}
	// Edits that change nothing a device can see are no weakening: the order
	// and repeats of a value list carry no meaning (scope.go matches by
	// membership), and on_missing is never read when no key can be missing.
	for name, c := range map[string]struct{ old, new string }{
		"value list reordered (E1c)": {
			"scopes:\n  - {name: hot, match: {tier: [core, edge]}, on_missing: include, security_log: true, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {tier: [edge, core]}, on_missing: include, security_log: true, " + mfa + "\n"},
		"duplicate value removed (E1d)": {
			"scopes:\n  - {name: hot, match: {tier: [core, core]}, on_missing: include, security_log: true, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {tier: core}, on_missing: include, security_log: true, " + mfa + "\n"},
		"on_missing flipped on an empty match (E1f)": {
			"scopes:\n  - {name: hot, match: {}, on_missing: include, security_log: true, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {}, on_missing: exclude, security_log: true, " + mfa + "\n"},
		"on_missing flipped on a name-only match": {
			"scopes:\n  - {name: hot, match: {name: core-sw01}, on_missing: include, " + mfa + "\n",
			"scopes:\n  - {name: hot, match: {name: core-sw01}, on_missing: exclude, " + mfa + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if out, code := diffRun(t, c.old, c.new); code != 0 || strings.Contains(out, "_weakened") {
				t.Fatalf("an edit that changes nothing is a weakening (exit %d):\n%s", code, out)
			}
		})
	}
	// A real narrowing, a value dropped, still fails (edge-sw01 loses its level).
	if out, code := diffRun(t,
		"scopes:\n  - {name: hot, match: {tier: [core, edge]}, on_missing: include, security_log: true, "+mfa+"\n",
		"scopes:\n  - {name: hot, match: {tier: core}, on_missing: include, security_log: true, "+mfa+"\n"); code == 0 ||
		!strings.Contains(out, "per_login_mfa_weakened: alice on edge-sw01") {
		t.Fatalf("a narrowed value list passed the gate (exit %d):\n%s", code, out)
	}
	// An unchanged scope, and a scope added, are no weakening.
	const same = "scopes:\n  - {name: hot, match: {tier: core}, on_missing: include, security_log: true, " + mfa + "\n"
	if out, code := diffRun(t, same, same); code != 0 || out != "" {
		t.Fatalf("an unchanged scope is a change (exit %d):\n%s", code, out)
	}
	if out, code := diffRun(t, "", same); code != 0 {
		t.Fatalf("a level added failed the gate (exit %d):\n%s", code, out)
	}
}

// An unchanged test carried over from the old version is no deliberate act: it
// does not acknowledge a weakening, only a test new or changed in the new
// version does (the controller's Task 9 re-review ruling, decision 45
// ruling 26).
func TestPolicyDiffAnUnchangedTestDoesNotAcknowledgeAnMFAWeakening(t *testing.T) {
	const pinned = `
defaults: {per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}}
scopes:
  - {name: core-sw01, match: {name: core-sw01}, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}
`
	const byTier = `
defaults: {per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}}
scopes:
  - {name: core, match: {tier: core}, on_missing: exclude, security_log: true,
     per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}
`
	const kept = "tests:\n  - {subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}\n"
	out, code := diffRun(t, pinned+kept, byTier+kept)
	if code == 0 || !strings.Contains(out, "per_login_mfa_weakened: alice on core-sw01") {
		t.Fatalf("the old test acknowledged the swap (exit %d):\n%s", code, out)
	}
	// A test changed in the new version acknowledges it.
	const edited = "tests:\n  - {subject: alice, device: core-sw01, command: show version, expect: permit, " +
		"per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}\n"
	if out, code := diffRun(t, pinned+kept, byTier+edited); code != 0 {
		t.Fatalf("a changed test did not acknowledge (exit %d):\n%s", code, out)
	}
	// And a test added beside the old one.
	if out, code := diffRun(t, pinned+kept, byTier+kept+strings.Replace(edited, "tests:\n", "", 1)); code != 0 {
		t.Fatalf("a new test did not acknowledge (exit %d):\n%s", code, out)
	}
}

// policy diff decides a quarantine is new by the reloader's rule, a device and
// a conflicting level pair, not by the subject its cause names: an emergency
// grant through the same role onto a device already quarantined fails
// nothing (decision 45 ruling 25).
func TestPolicyDiffASameQuarantinePairIsNoNewQuarantine(t *testing.T) {
	before := mfaBundle(t, disjointPolicy)
	after := mfaBundle(t, disjointPolicy+`
subjects:
  - {name: oncall, identity: ["user:oncall@example.com"], token_ttl: 5m}
grants:
  - {subject: oncall, scope: all_devices, roles: [netadmin]}
`)
	if d := Compare(before, after, noon); len(d.Quarantined) != 0 {
		t.Fatalf("a same-pair emergency grant is a new quarantine: %+v", d.Quarantined)
	}
	// A new conflicting pair on the already-quarantined device is still new.
	pair := mfaBundle(t, strings.Replace(disjointPolicy, "scopes:\n",
		"  - {name: emerg, permit: [\"show **\"], per_login_mfa: {accept: [idp_mfa]}}\nscopes:\n", 1)+`
subjects:
  - {name: oncall, identity: ["user:oncall@example.com"], token_ttl: 5m}
grants:
  - {subject: oncall, scope: all_devices, roles: [emerg]}
`)
	if d := Compare(before, pair, noon); len(d.Quarantined) != 1 {
		t.Fatalf("a new conflicting pair on a quarantined device is not one new quarantine: %+v", d.Quarantined)
	}
}

// applies_to_machines turned off on a level while another level takes it up
// leaves a machine's level count and requirement as they were, and is a
// weakening all the same.
func TestPolicyDiffGatesAppliesToMachinesTurnedOff(t *testing.T) {
	const old = `
defaults: {per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}}
`
	const moved = `
defaults: {per_login_mfa: {accept: [hardware_key_touch]}}
roles:
  - {name: backup, privilege: readonly, permit: ["show **"], per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}}
`
	out, code := diffRun(t, old, moved)
	if code == 0 || !strings.Contains(out, "per_login_mfa_weakened: oxidized on core-sw01, edge-sw01") {
		t.Fatalf("applies_to_machines turned off passed the gate (exit %d):\n%s", code, out)
	}
	// Turned off on a level that stays, with a stricter level above it, no
	// requirement moves for anyone and the level still counts.
	const strict = `
scopes:
  - {name: core, match: {tier: core}, on_missing: include, security_log: true, per_login_mfa: {accept: [hardware_key_touch]}}
`
	if _, code := diffRun(t, old+strict, strings.Replace(old, "applies_to_machines: true", "applies_to_machines: false", 1)+strict); code == 0 {
		t.Fatal("a level's applies_to_machines turned off passed the gate")
	}
}

func TestLintWarnsOfAPerLoginMFAThatAnAttributeLifts(t *testing.T) {
	p := mfaPolicy(t, `
defaults: {per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}}
roles:
  - {name: netadmin, permit: ["**"], per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}}
scopes:
  - {name: core, match: {tier: core}, on_missing: exclude, security_log: true, per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}}
`)
	kinds := map[string]string{}
	for _, f := range p.Lint(noon) {
		kinds[f.Kind] += f.Message + "\n"
	}
	if m := kinds[FindingPerLoginMFAExclude]; !strings.Contains(m, `scope "core"`) || !strings.Contains(m, "tier") {
		t.Errorf("per_login_mfa_on_missing_exclude: %q", m)
	}
	m := kinds[FindingPerLoginMFAMachines]
	for _, at := range []string{"defaults:", `role "netadmin"`, `scope "core"`} {
		if !strings.Contains(m, at) || !strings.Contains(m, "pkcs11 key and a touch key on one token") {
			t.Errorf("per_login_mfa_machines does not name %s: %q", at, m)
		}
	}
	// A name pin loses nothing to a sync, so it is no finding.
	pinned := mfaPolicy(t, "scopes:\n  - {name: core-sw01, match: {name: core-sw01}, on_missing: exclude, per_login_mfa: {accept: [idp_mfa]}}\n")
	for _, f := range pinned.Lint(noon) {
		if f.Kind == FindingPerLoginMFAExclude {
			t.Errorf("a name-pinned scope is a finding: %s", f.Message)
		}
	}
}

func TestExplainSaysWhatAMachineMeets(t *testing.T) {
	p := mfaPolicy(t, `
defaults: {per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}}
`)
	for subject, want := range map[string]string{
		"oxidized": "applies to this machine: provable only with a pkcs11 key and touch key on one token\n",
		"alice":    "applies to machines too\n",
	} {
		e, err := p.Explain(subject, "", "core-sw01", "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		e.RenderWithoutAttributes(&b)
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s: explain says\n%s\nwant %q", subject, b.String(), want)
		}
	}
}

// `policy test` says the same on a machine's session test (decision 45
// ruling 21), as a note on its line; a human's carries none.
func TestPolicyTestSaysWhatAMachineMeets(t *testing.T) {
	p := mfaPolicy(t, `
defaults: {per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}}
`)
	notes := func(subject string) []string {
		q, err := Parse(append(append([]byte(nil), p.raw...), []byte("\ntests:\n  - {subject: "+subject+
			", device: core-sw01, per_login_mfa: {accept: [hardware_key_touch]}}\n")...), p.env)
		if err != nil {
			t.Fatal(err)
		}
		return q.RunTests(noon)[0].Caveats
	}
	if got := strings.Join(notes("oxidized"), "\n"); !strings.Contains(got,
		"applies to this machine: provable only with a pkcs11 key and touch key on one token") {
		t.Errorf("a machine's session test: notes %q", got)
	}
	if got := strings.Join(notes("alice"), "\n"); strings.Contains(got, "applies to this machine") {
		t.Errorf("a human's session test says it applies to a machine: %q", got)
	}
}

// An entry is new by its device and the level pair that conflicts, not by the
// subject its cause names: a grant that only reaches a device already
// quarantined over the same pair introduces nothing (the controller's Task 9
// review ruling, decision 45 ruling 11).
func TestNewMFADisjointIsByDeviceAndLevelPair(t *testing.T) {
	base := mfaBundle(t, disjointPolicy)
	same := mfaBundle(t, disjointPolicy+`
subjects:
  - {name: oncall, identity: ["user:oncall@example.com"], token_ttl: 5m}
grants:
  - {subject: oncall, scope: all_devices, roles: [netadmin]}
`)
	if got := NewMFADisjoint(base, same); len(got) != 0 {
		t.Fatalf("a grant reaching a device already quarantined over the same pair is new: %+v", got)
	}
	// A level pair on a device the base does not hold, and a new pair on one it does.
	other := mfaBundle(t, strings.Replace(disjointPolicy, "roles:\n",
		"roles:\n  - {name: noc, permit: [\"show **\"], per_login_mfa: {accept: [idp_mfa]}}\n", 1)+`
subjects:
  - {name: oncall, identity: ["user:oncall@example.com"], token_ttl: 5m}
grants:
  - {subject: oncall, scope: all_devices, roles: [noc]}
`)
	if got := NewMFADisjoint(base, other); len(got) != 1 || got[0].Device != "core-sw01" ||
		!strings.Contains(got[0].Entries[0].Cause, "role noc") {
		t.Fatalf("a new level pair on a quarantined device: %+v, want it new", got)
	}
}

// applies_to_machines turned off changes nothing for a person, so it is no
// weakening of a person's requirement; for a machine it still is (final
// review broker minor 11).
func TestAppliesToMachinesOffWeakensOnlyAMachine(t *testing.T) {
	req := func(machine, applies bool) MFARequirement {
		return MFARequirement{Accept: []MFAMethod{HardwareKeyTouch}, ReuseFor: 5 * time.Minute, Machine: machine,
			Levels: []MFALevel{{Level: "scope core", Accept: []MFAMethod{HardwareKeyTouch}, ReuseFor: 5 * time.Minute,
				AppliesToMachines: applies}}}
	}
	if mfaWeakened(req(false, true), req(false, false)) {
		t.Error("a person's requirement read as weakened by applies_to_machines turned off")
	}
	if !mfaWeakened(req(true, true), req(true, false)) {
		t.Error("a machine's requirement did not read as weakened by applies_to_machines turned off")
	}
}

// A selector prints in ASCII, so a value in NFC and the same value in NFD,
// which select different devices, never read alike on the two sides of a diff
// line (final review broker minor 9).
func TestScopeSelectPrintsInASCII(t *testing.T) {
	nfc, nfd := "café", "café"
	a := scopeSelect(&Scope{Match: map[string]matchValue{"site": {Equal: []string{nfc}}}, OnMissing: "exclude"})
	b := scopeSelect(&Scope{Match: map[string]matchValue{"site": {Equal: []string{nfd}}}, OnMissing: "exclude"})
	for _, s := range []string{a, b} {
		for _, r := range s {
			if r > 0x7e {
				t.Fatalf("%q prints a non-ASCII character", s)
			}
		}
	}
	if a == b {
		t.Fatalf("NFC and NFD print alike: %q", a)
	}
}

// MetBy: a login under prior meets r when r asks nothing, or prior asked a
// proof from methods r accepts, reusable no longer than r allows.
func TestMFARequirementMetBy(t *testing.T) {
	req := func(reuse time.Duration, accept ...MFAMethod) MFARequirement {
		return MFARequirement{Accept: accept, ReuseFor: reuse, Levels: []MFALevel{{Level: "scope core"}}}
	}
	none := MFARequirement{}
	both := req(15*time.Minute, HardwareKeyTouch, IdPMFA)
	for _, c := range []struct {
		name     string
		r, prior MFARequirement
		want     bool
	}{
		{"none under none", none, none, true},
		{"none under a requirement", none, both, true},
		{"added", both, none, false},
		{"unchanged", both, both, true},
		{"accept narrowed", req(15*time.Minute, HardwareKeyTouch), both, false},
		{"accept widened", both, req(15*time.Minute, HardwareKeyTouch), true},
		{"reuse_for shortened", req(0, HardwareKeyTouch, IdPMFA), both, false},
		{"reuse_for lengthened", req(time.Hour, HardwareKeyTouch, IdPMFA), both, true},
	} {
		if got := c.r.MetBy(c.prior); got != c.want {
			t.Errorf("%s: MetBy = %v, want %v", c.name, got, c.want)
		}
	}
}
