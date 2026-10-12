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
			{Level: "scope core", Accept: []MFAMethod{HardwareKeyTouch}, ReuseFor: 5 * time.Minute},
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
