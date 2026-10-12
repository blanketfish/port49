package policy

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/projection"
)

// projectedSet is the test's second platform set: 1.0.0 with juniper_junos
// projected as spec §8 writes it, the bits the lab measures standing in for
// the ones platforms/1.1.0 ships.
const projectedSet = "9.0.0"

func projectedEnv(delivery string) Env {
	e := env()
	first, _ := platform.Set(platform.UnpinnedSet)
	second, _ := platform.Set(platform.UnpinnedSet)
	p, d := platform.ProjectionJunosRegex, delivery
	spec := platform.Spec{CommandProjection: &p, BitDelivery: &d,
		Bits: &map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
			"clear": {"clear **"}, "network": {"ping **", "traceroute **"}, "all": {"**"}},
		CarveOuts: &map[string][]string{"view-configuration": {"show configuration **"}},
		Privilege: &map[string][]string{"readonly": {"view", "view-configuration"},
			"operator": {"view", "view-configuration", "clear", "network"}, "admin": {"all"}},
		CeilingLevels: &map[string]uint8{"readonly": 1, "operator": 15, "admin": 15}}
	if delivery == platform.BitDeliveryLocalUserName {
		spec.LocalUserNames = &map[string]string{"readonly": "p49-readonly", "operator": "p49-operator",
			"admin": "p49-admin"}
	}
	second["juniper_junos"] = spec.Over(second["juniper_junos"])
	e.Sets = map[string]map[string]platform.Dialect{platform.UnpinnedSet: first, projectedSet: second}
	return e
}

func parseProjected(t *testing.T, delivery, body string) *Policy {
	t.Helper()
	p, err := Parse([]byte("platform_set: "+projectedSet+"\n"+body), projectedEnv(delivery))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const readonlyCarveOut = scopeOK + `roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}
` + subjOK + grantOK

// bindingRPCs stands in a Junos whose wire deny binds native RPCs, where a
// carve-out leaves its deny off the wire (readonlyCarveOut's `view` alone).
// Set 1.1.0 is not one until L26c closes, and no carve-out omits a deny there
// (final review I-3); the tests that call it are about what the reply, CI and
// explain say of an omitted deny, not whether one is omitted. Parse after it.
func bindingRPCs(t *testing.T) {
	t.Helper()
	saved := projection.JunosFacts
	projection.JunosFacts.DenyBindsRPCs = true
	t.Cleanup(func() { projection.JunosFacts = saved })
}

// A block keeps the set's projection and every rule of a bit's reach, and a
// level's ceiling bits rise with the policy's level order.
func TestABlockKeepsTheProjection(t *testing.T) {
	for _, c := range []struct{ block, want string }{
		{"bits: {view: [\"show version\"]}", "a block may add to a bit's reach, not take from it"},
		{"bits: {maintenance: [\"request system **\"]}", "a block may not add a bit"},
		{"privilege: {readonly: [all]}", "privilege.readonly: all is not in operator's bits"},
		{"local_user_names: {operator: p49-operator}", "read only under bit_delivery"},
		{"carve_outs: {view: [\"show log **\"]}", "a block may drop one, not add one"},
	} {
		_, err := Parse([]byte("platform_set: "+projectedSet+"\nplatforms:\n  juniper_junos:\n    "+c.block+"\n"+
			readonlyCarveOut), projectedEnv(platform.BitDeliveryUserPermissions))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.block, err)
		}
	}
	// Adding to a bit's reach loads, and so does dropping a carve-out: each
	// claims the bits reach more. The diff gates both as adapter edits.
	parseProjected(t, platform.BitDeliveryUserPermissions, "platforms:\n  juniper_junos:\n"+
		"    bits: {view: [\"show **\", \"monitor **\"]}\n    carve_outs: {view-configuration: []}\n"+readonlyCarveOut)
}

// A pinned set that projects Junos renders the composition's rules into the
// session reply, at the platform layer, and every other platform as before.
func TestAJunosSessionReplyIsTheProjection(t *testing.T) {
	// On the shipped facts the carve-out omits nothing until L26c closes: the
	// deny is sent beneath `view`, and the subject fails closed (I-3).
	res, err := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut).
		ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil || res.Blob.FailClosed != projection.FailRefusedShape ||
		!reflect.DeepEqual(res.Blob.Attributes, []string{"deny-commands=^.*$"}) {
		t.Fatalf("shipped facts: %q %q %v", res.Blob.Attributes, res.Blob.FailClosed, err)
	}
	bindingRPCs(t)
	p := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
	res, err = p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Blob.Attributes, []string{"user-permissions=view"}) || res.Blob.FailClosed != "" ||
		res.Attributes[0].Source != "platform juniper_junos, projection (capability)" || res.Projection == nil {
		t.Fatalf("%q %+v", res.Blob.Attributes, res.Attributes)
	}
	if q := p.Quarantines(noon); len(q) != 0 {
		t.Fatalf("quarantines: %+v", q)
	}
	// The unpinned policy renders Junos with 1.0.0: nothing.
	if res, _ := mustParse(t, readonlyCarveOut).ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon); len(res.Blob.Attributes) != 0 {
		t.Errorf("1.0.0 projects nothing: %q", res.Blob.Attributes)
	}
}

// The refused shape gets that subject the fail-closed reply, and quarantines
// nothing: every other subject on the device keeps its reply (decision 26).
// So does a bit whose reach a block widened past what the grant decides.
func TestTheRefusedShapeFailsClosedForThatSubjectOnly(t *testing.T) {
	body := scopeOK + `roles:
  - {name: r, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
  - {name: ok, privilege: readonly, permit: ["show version"]}
subjects:
  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}
  - {name: t, identity: ["user:b@example.com"], username: b, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [r]}
  - {subject: t, scope: all_devices, roles: [ok]}
`
	for _, block := range []string{"", "platforms:\n  juniper_junos:\n    bits: {view: [\"show **\", \"monitor **\"]}\n"} {
		p := parseProjected(t, platform.BitDeliveryUserPermissions, block+body)
		if q := p.Quarantines(noon); len(q) != 0 {
			t.Fatalf("a projection refusal quarantines nothing: %+v", q)
		}
		res, err := p.ResolveSubject("t", deviceNamed(t, "srx-fw-04"), noon)
		if err != nil || res.Blob.FailClosed != "" {
			t.Fatalf("the other subject: %q %v", res.Blob.Attributes, err)
		}
		res, err = p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
		if err != nil || res.Blob.FailClosed != "refused_shape" ||
			!reflect.DeepEqual(res.Blob.Attributes, []string{"deny-commands=^.*$"}) {
			t.Fatalf("%q %q %v", res.Blob.Attributes, res.Blob.FailClosed, err)
		}
		// explain says which reply the login would be told, by reason.
		_, out := explained(t, p, "s", "", "srx-fw-04", "", false)
		mustContain(t, out, "permit projection_fail_closed (session)")
		_, out = explained(t, p, "t", "", "srx-fw-04", "", false)
		mustContain(t, out, "permit context_matched (session)")
	}
}

// A level the adapter maps to no bits is that subject's fail-closed reply,
// `deny-commands` `.*` and nothing else, not a quarantine: the other subjects
// on the device keep theirs, and CI names the subject, device and why (spec
// §8, "Generator constraints" 5; decision 26; final review I-1).
func TestALevelWithNoBitsFailsClosedForThatSubjectOnly(t *testing.T) {
	body := unmappedLevel + scopeOK + `roles:
  - {name: r, privilege: unmapped, permit: ["show **"]}
  - {name: ok, privilege: readonly, permit: ["show version"]}
subjects:
  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}
  - {name: t, identity: ["user:b@example.com"], username: b, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [r]}
  - {subject: t, scope: all_devices, roles: [ok]}
`
	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
		p := parseProjected(t, delivery, body)
		for _, q := range p.Quarantines(noon) {
			if q.Platform == "juniper_junos" {
				t.Fatalf("%s: a level with no bits quarantines %s: %+v", delivery, q.Device, q)
			}
		}
		res, err := p.ResolveSubject("t", deviceNamed(t, "srx-fw-04"), noon)
		if err != nil || res.Blob.FailClosed != "" {
			t.Fatalf("%s: the other subject: %q %v", delivery, res.Blob.Attributes, err)
		}
		res, err = p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
		if err != nil || res.Blob.FailClosed != projection.FailUnwritable ||
			!reflect.DeepEqual(res.Blob.Attributes, []string{"deny-commands=^.*$"}) {
			t.Fatalf("%s: %q %q %v", delivery, res.Blob.Attributes, res.Blob.FailClosed, err)
		}
		if r := res.Projection.Refusal; r == nil || !strings.Contains(r.Why, "level unmapped maps to no permission bits") {
			t.Fatalf("%s: %+v", delivery, res.Projection.Refusal)
		}
		var got []string
		for _, f := range p.Lint(noon) {
			if f.Kind == FindingProjectionRefused {
				got = append(got, f.Message)
			}
		}
		if len(got) != 1 || !strings.HasPrefix(got[0], `subject "s" on juniper_junos gets the fail-closed reply `+
			`(unwritable)`) || !strings.Contains(got[0], "level unmapped maps to no permission bits") ||
			!strings.HasSuffix(got[0], "srx-fw-04, srx-fw-05, srx-fw-22, srx-lab-01") {
			t.Errorf("%s: CI does not name s, the devices and why: %q", delivery, got)
		}
	}
}

// Moving the pin to the shipped set 1.1.0 with a custom level no adapter maps
// quarantines no SRX: the platforms that render levels quarantine as before
// (decision 20), and every Junos device still mints (final review I-1).
func TestPinningTheShippedSetWithABitlessLevelQuarantinesNoSRX(t *testing.T) {
	p := mustParse(t, "platform_set: 1.1.0\n"+unmappedLevel+scopeOK+`roles:
  - {name: r, privilege: unmapped, permit: ["show **"]}
`+subjOK+grantOK)
	var got []string
	for _, q := range p.Quarantines(noon) {
		got = append(got, q.Device)
	}
	if want := []string{"campus-sw-7", "leaf-01", "nx-01", "xe-01"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("quarantined %v, want %v", got, want)
	}
	for _, d := range []string{"srx-fw-04", "srx-fw-05", "srx-fw-22", "srx-lab-01"} {
		res, err := p.ResolveSubject("s", deviceNamed(t, d), noon)
		if err != nil || res.Blob.FailClosed != projection.FailUnwritable {
			t.Errorf("%s: %q %q %v", d, res.Blob.Attributes, res.Blob.FailClosed, err)
		}
	}
}

// No role or grant sets an attribute the projection renders, in any case or
// numbered variant the device reads (I1).
func TestARoleCannotSetAProjectedAttribute(t *testing.T) {
	for _, key := range []string{"juniper_junos", "all"} {
		for _, a := range []string{"deny-commands=^request.*$", "allow-commands2=^request.*$",
			"User-Permissions=all", "local-user-name1=p49-admin", "allow-configuration-regexps=.*"} {
			_, err := Parse([]byte("platform_set: "+projectedSet+"\n"+scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], attributes: {`+key+`: ["`+a+`"]}}
`+subjOK+grantOK), projectedEnv(platform.BitDeliveryUserPermissions))
			if err == nil || !strings.Contains(err.Error(), "rendered by juniper_junos's projection") {
				t.Errorf("%s %s: %v", key, a, err)
			}
		}
	}
}

// A subject may not take a device template user's name: a session under one
// lands in that template's class whatever the reply says (I9).
func TestATemplateUsernameIsReserved(t *testing.T) {
	for _, u := range []string{"remote", "p49-admin", "p49-remote", "root"} {
		_, err := Parse([]byte(scopeOK+roleOK+"subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: "+
			u+", token_ttl: 60s}\n"+grantOK), env())
		if err == nil || !strings.Contains(err.Error(), "is reserved") {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// A ceiling is held by the projection: a readonly grant capped at readonly
// loads, and its reply is the projection's, not a raise.
func TestACeilingOnJunos(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryLocalUserName, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"]}
`+subjOK+"grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: readonly}\n")
	if q := p.Quarantines(noon); len(q) != 0 {
		t.Fatalf("%+v", q)
	}
	res, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil || res.Blob.Attributes[0] != "local-user-name=p49-readonly" || res.MaxPrivilege != 1 {
		t.Fatalf("%q %d %v", res.Blob.Attributes, res.MaxPrivilege, err)
	}
}

// Each composition is projected once per policy, however many devices it
// lands on: 1,000 SRXs and 20 subjects load within 2 s (I12; spec §8).
func TestProjectionLoadTime(t *testing.T) {
	if testing.Short() || raceBuild {
		t.Skip("load-time bound; the race detector's slowdown alone breaks it")
	}
	e := projectedEnv(platform.BitDeliveryUserPermissions)
	e.Devices = nil
	for i := range 1000 {
		e.Devices = append(e.Devices, admission.Device{Name: fmt.Sprintf("srx-%04d", i), Platform: "juniper_junos",
			Addresses:  []netip.Addr{netip.AddrFrom4([4]byte{10, 9, byte(i >> 8), byte(i)})},
			Attributes: map[string]string{"site": fmt.Sprintf("s%d", i%10)}})
	}
	var b strings.Builder
	b.WriteString("platform_set: " + projectedSet + "\n" + scopeOK + `roles:
  - {name: ro, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}
  - {name: narrow, privilege: readonly, permit: ["show version", "show interfaces **"]}
  - {name: op, privilege: operator, permit: ["show **", "clear **", "ping **"], deny: ["clear bgp **"]}
  - {name: refused, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
subjects:
`)
	roles := []string{"ro", "narrow", "op", "refused"}
	for i := range 20 {
		fmt.Fprintf(&b, "  - {name: s%d, identity: [\"user:u%d@example.com\"], username: u%d, token_ttl: 60s}\n", i, i, i)
	}
	b.WriteString("grants:\n")
	for i := range 20 {
		fmt.Fprintf(&b, "  - {subject: s%d, scope: all_devices, roles: [%s]}\n", i, roles[i%len(roles)])
	}
	start := time.Now()
	p, err := Parse([]byte(b.String()), e)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("1,000 SRXs x 20 subjects loaded in %v; the bound is 2 s", d)
	} else {
		t.Logf("1,000 SRXs x 20 subjects loaded in %v", d)
	}
	// Four compositions, four projections, however many devices.
	if n := memoized(p); n != 4 {
		t.Fatalf("four compositions, %d projections memoized", n)
	}
}

// A composition is projected once per policy and every later device reads the
// memo: a result planted in it is what the next resolution returns (I12).
func TestARepeatedCompositionIsNotReprojected(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
	n := 0
	p.projected.Range(func(k, _ any) bool {
		p.projected.Store(k, projection.Result{Shape: "memo", Attributes: []string{"user-permissions=memo"}})
		n++
		return true
	})
	if n != 1 {
		t.Fatalf("one composition, %d projections memoized", n)
	}
	res, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil || res.Attributes[0].Source != "platform juniper_junos, projection (memo)" {
		t.Fatalf("%+v %v", res.Attributes, err)
	}
}

// The memo is keyed finely enough: two compositions with the same rules, role
// for role, at different levels are two projections with two replies.
func TestTheMemoKeysOnTheLevel(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: ro, privilege: readonly, permit: ["show **", "clear **"]}
  - {name: op, privilege: operator}
subjects:
  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}
  - {name: t, identity: ["user:b@example.com"], username: b, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [ro]}
  - {subject: t, scope: all_devices, roles: [ro, op]}
`)
	if n := memoized(p); n != 2 {
		t.Fatalf("two compositions, %d projections memoized", n)
	}
	s, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil {
		t.Fatal(err)
	}
	u, err := p.ResolveSubject("t", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil || reflect.DeepEqual(s.Blob.Attributes, u.Blob.Attributes) {
		t.Fatalf("%q %q %v", s.Blob.Attributes, u.Blob.Attributes, err)
	}
}

func memoized(p *Policy) int {
	n := 0
	p.projected.Range(func(_, _ any) bool { n++; return true })
	return n
}

// A resolution's projection is its own: what one caller does to it never
// reaches another resolution of the same composition, however concurrent.
func TestAProjectionIsNotSharedAcrossResolutions(t *testing.T) {
	// The second composition leaves an allow off the wire (Result.Unsent);
	// the third, on the shipped set, sends a deny (the baseline's and its
	// own) and leaves `**` beyond the bits it keeps (Task 9 review, parked).
	for i, p := range []*Policy{
		parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut),
		parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show version", "show interfaces terse"]}
`+subjOK+grantOK),
		mustParse(t, "platform_set: 1.1.0\n"+scopeOK+`roles:
  - {name: r, privilege: admin, permit: ["**"], deny: ["restart **"]}
`+subjOK+grantOK),
	} {
		want, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
		if err != nil {
			t.Fatal(err)
		}
		wantAttrs, wantBeyond := slices.Clone(want.Projection.Attributes), slices.Clone(want.Projection.Beyond)
		wantUnsent, wantDenies := slices.Clone(want.Projection.Unsent), slices.Clone(want.Projection.Denies)
		if i == 1 && len(wantUnsent) != 1 {
			t.Fatalf("unsent: %+v", want.Projection)
		}
		if i == 2 && (len(wantDenies) == 0 || len(wantBeyond) == 0) {
			t.Fatalf("denies and beyond: %+v", want.Projection)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
				if err != nil {
					t.Error(err)
					return
				}
				res.Projection.Attributes[0] = "user-permissions=all"
				if len(res.Projection.Beyond) > 0 {
					res.Projection.Beyond[0].Rule = "changed"
				}
				res.Projection.Beyond = append(res.Projection.Beyond[:0], engine.Rule{Verdict: engine.Permit, Rule: "**"})
				if len(res.Projection.Denies) > 0 {
					res.Projection.Denies[0].Rule = "changed"
				}
				res.Projection.Denies = slices.DeleteFunc(res.Projection.Denies, func(engine.Rule) bool { return true })
				if len(res.Projection.Unsent) > 0 {
					res.Projection.Unsent[0].Why = "changed"
				}
				res.Projection.Unsent = append(res.Projection.Unsent[:0], projection.Unsent{Why: "added"})
			}()
		}
		wg.Wait()
		got, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
		if err != nil || !reflect.DeepEqual(got.Projection.Attributes, wantAttrs) ||
			!reflect.DeepEqual(got.Projection.Beyond, wantBeyond) ||
			!reflect.DeepEqual(got.Projection.Denies, wantDenies) ||
			!reflect.DeepEqual(got.Projection.Unsent, wantUnsent) {
			t.Fatalf("%q %+v %v", got.Projection.Attributes, got.Projection.Unsent, err)
		}
	}
}

// The projection holds its own attributes to the level's bits, not to the
// grant's ceiling: a role above max_privilege still quarantines the device.
func TestAProjectionDoesNotMaskALevelAboveTheCeiling(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryLocalUserName, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"]}
  - {name: o, privilege: operator, permit: ["clear **"]}
`+subjOK+"grants:\n  - {subject: s, scope: all_devices, roles: [r, o], max_privilege: readonly}\n")
	if cause, ok := p.Quarantined("srx-fw-04", noon); !ok || !strings.Contains(cause, "above its grants' max_privilege readonly") {
		t.Fatalf("%q %v", cause, ok)
	}
}

// explain says what the device does with a command under the projection, and
// that the class half of what it runs is outside port49 (spec §8,
// "Verification").
func TestExplainSaysWhatTheDeviceDoes(t *testing.T) {
	bindingRPCs(t)
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **", "clear counters"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	for line, want := range map[string]string{
		"show configuration system": "the device refuses it",
		"show version":              "the device runs it",
		"clear counters":            "the projection does not carry it to juniper_junos",
	} {
		e, err := p.Explain("s", "", "srx-fw-04", line, noon)
		if err != nil || !strings.Contains(strings.Join(e.Caveats, "\n"), want) {
			t.Errorf("%s: %q %v", line, e.Caveats, err)
		}
	}
	e, err := p.Explain("s", "", "srx-fw-04", "", noon)
	if err != nil || !strings.Contains(strings.Join(e.Caveats, "\n"), "the reply projects these rules as the capability shape") {
		t.Errorf("session: %q %v", e.Caveats, err)
	}
}

// policy test reports each composition's projection, and a reply past RFC
// 8907's length with the class line that carries it instead.
func TestProjectionFindings(t *testing.T) {
	saved := projection.JunosFacts
	projection.JunosFacts.DenyBindsRPCs = true // as bindingRPCs, for this composition only
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **", "clear counters"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	projection.JunosFacts = saved
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjection {
			got = append(got, f.Message)
		}
	}
	want := `subject "s" on juniper_junos: capability shape, bits view; refused by the bits, sent as nothing: ` +
		`show configuration **; beyond the level's bits, not sent: clear counters; the device refuses what port49 ` +
		`permits, e.g. these probe commands: clear counters`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("%q", got)
	}
	// Sixteen permits narrower than view: the narrow shape's one allow
	// alternation is past 255 bytes.
	body := scopeOK + "roles:\n  - {name: r, privilege: readonly, permit: ["
	for i, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
		"juliett", "kilo", "lima", "mike", "november", "oscar", "papa"} {
		if i > 0 {
			body += ", "
		}
		body += `"show ` + w + ` **"`
	}
	// That subject gets the fail-closed reply, and the finding prints no class
	// line: a class allow would run for every subject at that template, past
	// their own denies (C2).
	p = parseProjected(t, platform.BitDeliveryUserPermissions, body+"]}\n"+subjOK+grantOK)
	var over []Finding
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionOverflow {
			over = append(over, f)
		}
	}
	if len(over) != 1 || strings.Contains(over[0].Message, "set system login class") ||
		!strings.Contains(over[0].Message, "narrow the grant") ||
		!strings.HasPrefix(over[0].Message, `subject "s" on juniper_junos gets the fail-closed reply (overflow)`) ||
		!strings.HasSuffix(over[0].Message, "; on 4 devices: srx-fw-04, srx-fw-05, srx-fw-22, srx-lab-01") ||
		ProjectionRefusals(p.Lint(noon)) != 1 {
		t.Fatalf("%+v", over)
	}
	// Past the budget in deny-commands, the class line carries the denies,
	// and says it binds every subject at that template. On Junos the denies
	// sit beneath the template's view, and a wire deny binds no RPC, so the
	// composition is refused first, naming RPC reach (L26c); on a device
	// whose denies bound RPCs, the overflow would be what CI reports.
	body = scopeOK + "roles:\n  - {name: r, privilege: readonly, permit: [\"show **\"], deny: ["
	for i, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
		"juliett", "kilo", "lima", "mike", "november", "oscar", "papa"} {
		if i > 0 {
			body += ", "
		}
		body += `"show ` + w + ` **"`
	}
	body += "]}\n" + subjOK + grantOK
	p = parseProjected(t, platform.BitDeliveryLocalUserName, body)
	var refused []Finding
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionRefused {
			refused = append(refused, f)
		}
	}
	if len(refused) != 1 || !strings.Contains(refused[0].Message, "xml-mode") {
		t.Fatalf("junos: %+v", refused)
	}
	bindingRPCs(t)
	p = parseProjected(t, platform.BitDeliveryLocalUserName, body)
	over = nil
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionOverflow {
			over = append(over, f)
		}
	}
	if len(over) != 1 || !strings.Contains(over[0].Message, "binding every subject at that template: "+
		"set system login class p49-readonly deny-commands \"^( *s") {
		t.Fatalf("%+v", over)
	}
}

// A refused composition is a projection_refused finding naming the subject,
// every device, and why, and it is what fails policy test (I10).
func TestARefusalIsAFinding(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show interfaces **", "show version"], deny: ["show interfaces terse"]}
`+subjOK+grantOK)
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionRefused {
			got = append(got, f.Message)
		}
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], `subject "s" on juniper_junos gets the fail-closed reply `+
		`(refused_shape)`) || !strings.HasSuffix(got[0], "; on 4 devices: srx-fw-04, srx-fw-05, srx-fw-22, srx-lab-01") ||
		!strings.Contains(got[0], `it is told every command denied but show version`) {
		t.Fatalf("%q", got)
	}
	e, err := p.Explain("s", "", "srx-fw-04", "show interfaces em0", noon)
	if err != nil || !strings.Contains(strings.Join(e.Caveats, "\n"), "gets the fail-closed reply there") ||
		!strings.Contains(strings.Join(e.Caveats, "\n"), "the device refuses it") {
		t.Fatalf("%q %v", e.Caveats, err)
	}
}

// An allow sent under bits that do not reach it is reported beside what the
// device refuses: whether a Junos allow runs a command its bits do not reach
// is unmeasured, so the operator sees both what was narrowed and what may not
// be reached, and explain says the device may refuse it.
func TestAnUnreachedAllowIsReported(t *testing.T) {
	bindingRPCs(t)
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: operator, permit: ["show **", "clear counters", "ping **"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjection {
			got = append(got, f.Message)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "; sent under bits that do not reach them, which the device may "+
		"refuse (whether a Junos allow runs without its bit is unmeasured): clear counters; ping **") {
		t.Fatalf("%q", got)
	}
	e, err := p.Explain("s", "", "srx-fw-04", "ping 192.0.2.1", noon)
	if c := strings.Join(e.Caveats, "\n"); err != nil || !strings.Contains(c, "the device may refuse it: "+
		`the allow that carries it, "ping **", is sent under bits that do not reach it`) {
		t.Fatalf("%q %v", e.Caveats, err)
	}
	e, err = p.Explain("s", "", "srx-fw-04", "show version", noon)
	if c := strings.Join(e.Caveats, "\n"); err != nil || strings.Contains(c, "may refuse") {
		t.Fatalf("%q %v", e.Caveats, err)
	}
}

// Each finding says which moment it applies to (task 11 review I1): a
// composition that holds until a grant expires says until when, and the one
// that follows says from when, as a scheduled quarantine does.
func TestAProjectionFindingSaysWhenItHolds(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: ok, privilege: readonly, permit: ["show version"]}
  - {name: r, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
`+subjOK+`grants:
  - {subject: s, scope: all_devices, roles: [ok]}
  - {subject: s, scope: all_devices, roles: [r], expires: 2099-01-01}
`)
	var refused, projected []string
	for _, f := range p.Lint(noon) {
		switch f.Kind {
		case FindingProjectionRefused:
			refused = append(refused, f.Message)
		case FindingProjection:
			projected = append(projected, f.Message)
		}
	}
	if len(refused) != 1 || !strings.HasPrefix(refused[0], `subject "s" on juniper_junos, until `+
		`2099-01-01T00:00:00.000Z, when grant all_devices [r] expires, gets the fail-closed reply (refused_shape)`) {
		t.Fatalf("refused: %q", refused)
	}
	if len(projected) != 1 || !strings.HasPrefix(projected[0], `subject "s" on juniper_junos, from `+
		`2099-01-01T00:00:00.000Z, when grant all_devices [r] expires: narrow shape`) {
		t.Fatalf("projected: %q", projected)
	}
}

// Where one subject's composition differs by device, each projection
// finding names its devices; a refusal names them after its reason, with a
// count, so a fleet's list does not bury why (task 11 review M4, M5).
func TestAProjectionFindingNamesItsDevicesWhereTheyDiffer(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+
		"  - {name: fw04, match: {os_version: 21.4R3-S4}}\n"+`roles:
  - {name: ok, privilege: readonly, permit: ["show version"]}
  - {name: more, privilege: readonly, permit: ["show route **"]}
`+subjOK+`grants:
  - {subject: s, scope: all_devices, roles: [ok]}
  - {subject: s, scope: fw04, roles: [more]}
`)
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjection {
			got = append(got, f.Message)
		}
	}
	slices.Sort(got)
	if len(got) != 2 || !strings.HasSuffix(got[0], "; on 1 device: srx-fw-04") ||
		!strings.HasSuffix(got[1], "; on 3 devices: srx-fw-05, srx-fw-22, srx-lab-01") {
		t.Fatalf("%q", got)
	}
	// A device-scoped grant that expires splits the moments by device: each
	// moment then has one reply, and still names the devices it is on, so a
	// grant to one SRX never reads as every SRX's (re-review R2).
	bindingRPCs(t)
	p = parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+
		"  - {name: few, match: {os_version: 21.4R3-S4}}\n"+`roles:
  - {name: ro, privilege: operator, permit: ["show **"], deny: ["show configuration **"]}
  - {name: op, privilege: operator, permit: ["ping **"]}
`+subjOK+`grants:
  - {subject: s, scope: all_devices, roles: [ro]}
  - {subject: s, scope: few, roles: [op], expires: 2099-01-01}
`)
	got = nil
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjection {
			got = append(got, f.Message)
		}
	}
	slices.Sort(got)
	if len(got) != 3 || !strings.HasPrefix(got[0], `subject "s" on juniper_junos, from 2099-01-01T00:00:00.000Z`) ||
		!strings.HasSuffix(got[0], "; on 1 device: srx-fw-04") ||
		!strings.HasPrefix(got[1], `subject "s" on juniper_junos, until 2099-01-01T00:00:00.000Z`) ||
		!strings.Contains(got[1], "allow-commands: ping **") || !strings.HasSuffix(got[1], "; on 1 device: srx-fw-04") ||
		!strings.HasSuffix(got[2], "; on 3 devices: srx-fw-05, srx-fw-22, srx-lab-01") {
		t.Fatalf("%q", got)
	}
}

// No projection finding and no explain caveat prints a value redaction
// hides (spec §5.8; task 11 review I2): a composition with such a rule is
// refused as secret_rule, naming only the role, and the messages redact
// every rule they list.
func TestProjectionFindingsNeverPrintASecret(t *testing.T) {
	const secret = "show system radius-server 10.0.0.1 secret HUNTER2"
	for _, roles := range []string{
		`permit: ["show **", "` + secret + `"]`,
		`permit: ["show **"], deny: ["` + secret + `"]`,
		`permit: ["show interfaces **", "show version", "` + secret + `"], deny: ["show interfaces terse"]`,
	} {
		p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+"roles:\n  - {name: r, privilege: readonly, "+
			roles+"}\n"+subjOK+grantOK)
		var all []string
		secretRule := false
		for _, f := range p.Lint(noon) {
			if strings.HasPrefix(f.Kind, "projection") {
				all = append(all, f.Message)
				secretRule = secretRule || strings.Contains(f.Message, `(secret_rule): role "r" has a rule`)
			}
		}
		for _, line := range []string{"", "show version", secret} {
			e, err := p.Explain("s", "", "srx-fw-04", line, noon)
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, e.Caveats...)
		}
		if !secretRule || strings.Contains(strings.Join(all, "\n"), "HUNTER2") {
			t.Fatalf("%s:\n%s", roles, strings.Join(all, "\n"))
		}
	}
	// A value another rule hides, in a rule that is no secret, in any letter
	// case and with a `"` or `\` %q would escape past any writer, is left
	// out where each finding and caveat is made (task 12b review I1).
	for _, c := range []struct{ hides, typed string }{
		{"HUNTER2", "hunter2"}, {`PA"sS9`, `pa"ss9`}, {`A\B9`, `a\b9`}, {`Mi"X\d9`, `mI"x\D9`},
	} {
		for _, roles := range []string{
			`permit: ["show interfaces **", 'show version ` + c.typed + `'], deny: ["show interfaces terse"]`,
			`permit: ["show **"], deny: ['show route ` + c.typed + `']`,
			`permit: ['show interfaces ` + c.typed + ` **', "show version"]`,
		} {
			p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+"roles:\n  - {name: r, privilege: readonly, "+
				roles+"}\n  - {name: sec, privilege: readonly, permit: ['show system radius-server 10.0.0.1 secret "+
				c.hides+"']}\n"+subjOK+grantOK)
			var all []string
			for _, f := range p.Lint(noon) {
				all = append(all, f.Message)
			}
			for _, line := range []string{"", "show version", "show interfaces " + c.typed + " terse"} {
				e, err := p.Explain("s", "", "srx-fw-04", line, noon)
				if err != nil {
					t.Fatal(err)
				}
				all = append(all, e.Caveats...)
			}
			if leaks(strings.Join(all, "\n"), c.hides) {
				t.Errorf("%s:\n%s", roles, strings.Join(all, "\n"))
			}
		}
	}

	// Each message redacts what it lists itself, whatever reached it.
	patterns := mustParse(t, readonlyCarveOut).Redactions()
	rule := engine.Rule{Verdict: engine.Permit, Rule: secret, Role: "r"}
	for _, msg := range []string{
		projectionMessage(projection.Result{Shape: projection.ShapeCapability,
			Denies: []engine.Rule{rule}, Allows: []engine.Rule{rule}, Omitted: []engine.Rule{rule},
			Beyond: []engine.Rule{rule}, Unreached: []engine.Rule{rule}}, patterns, nil),
		second(refusedMessage(projection.Result{FailClosed: projection.FailOverflow,
			Allows: []engine.Rule{rule}, Refusal: &projection.Refusal{Why: "w", Attribute: "deny-commands",
				Value: "^(" + secret + ")$", Class: "p49-readonly"}}, patterns, nil)),
		second(refusedMessage(projection.Result{FailClosed: projection.FailRefusedShape,
			Allows: []engine.Rule{rule}, Refusal: &projection.Refusal{Why: "w"}}, patterns, nil)),
		// The class line's regex writes a hidden value re-cased, which no
		// writer recognizes: it prints redacted whole.
		second(refusedMessage(projection.Result{FailClosed: projection.FailOverflow, Refusal: &projection.Refusal{
			Why: "w", Attribute: "deny-commands", Value: "^(show [hH][uU][nN][tT][eE][rR]2)$", Class: "p49-readonly"}},
			patterns, []string{"HUNTER2"})),
	} {
		if strings.Contains(msg, "HUNTER2") || !strings.Contains(msg, platform.Redacted) {
			t.Errorf("%s", msg)
		}
	}
}

func second(_, b string) string { return b }

// On the command path, a fail-closed composition's caveat names why, as the
// session path and the finding do, and a line with no command still gets it
// (task 11 review M2, M3).
func TestTheFailClosedCaveatSaysWhy(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show interfaces **", "show version"], deny: ["show interfaces terse"]}
`+subjOK+grantOK)
	e, err := p.Explain("s", "", "srx-fw-04", "show version", noon)
	if c := strings.Join(e.Caveats, "\n"); err != nil || !strings.Contains(c, "(refused_shape): on juniper_junos, "+
		`permit "show interfaces **" (role "r") needs an allow-commands`) {
		t.Fatalf("%q %v", e.Caveats, err)
	}
	res, _, err := p.Decide("s", "", p.env.Devices[slices.IndexFunc(p.env.Devices,
		func(d admission.Device) bool { return d.Name == "srx-fw-04" })], "show version", noon)
	if err != nil {
		t.Fatal(err)
	}
	if c := strings.Join(ProjectionCaveats(res, "juniper_junos", engine.Outcome{}, nil), "\n"); !strings.Contains(c,
		"gets the fail-closed reply there") || strings.Contains(c, "the device runs") {
		t.Fatalf("%q", c)
	}
}

// A probe prints each argument made from a hidden value, the value itself,
// padded, or a piece a probe split or cut short, as redacted, and every other
// argument as probed (re-review 2, R5): diff's changed commands and a
// projection's narrower examples both print through it.
func TestAProbeMadeFromAHiddenValuePrintsRedacted(t *testing.T) {
	src := map[string][]string{"Kilo": {"Kilo7"}, "7": {"Kilo7"}, " Kilo7": {"Kilo7"}, "community": {"community"},
		"username": {"username"}, "kilo7": {"Kilo7"}}
	got := probeShown([]string{"username", "community", "Kilo", "7", " Kilo7", "kilo7"}, src, []string{"KILO7"})
	want := []string{"username", "community", platform.Redacted, platform.Redacted, platform.Redacted, platform.Redacted}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

// An argument with no recorded source prints redacted: what a probe made it
// from is unknown, so it may be a secret (re-review 3, R6, fail closed).
// The stand-in for every other argument is no rule's text and prints as it
// is.
func TestAProbeArgumentOfNoKnownSourcePrintsRedacted(t *testing.T) {
	src := map[string][]string{"username": {"username"}}
	got := probeShown([]string{"username", "Mango", engine.OtherArgument}, src, nil)
	if want := []string{"username", platform.Redacted, engine.OtherArgument}; !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

// The diff reports a reply whose shape or bits moved, and the reply gate
// judges it by what the device can do: a carve-out only narrows, so it is no
// raise, and lifting it again is (plan 5b pre-flight I14).
func TestTheDiffReportsAProjectionChange(t *testing.T) {
	bindingRPCs(t)
	before := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"]}
`+subjOK+grantOK)
	after := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
	d := Compare(before, after, noon)
	if len(d.Projections) != 1 || !reflect.DeepEqual(d.Projections[0].OldBits, []string{"view", "view-configuration"}) ||
		!reflect.DeepEqual(d.Projections[0].NewBits, []string{"view"}) || len(d.Projections[0].Devices) != 4 {
		t.Fatalf("%+v", d.Projections)
	}
	if d.UnacknowledgedLevels() != 0 {
		t.Errorf("a narrowing is no raise: %+v", d.Levels)
	}
	d = Compare(after, before, noon)
	if d.UnacknowledgedLevels() == 0 || !slices.Contains(d.Levels[0].Raised, "reply") {
		t.Errorf("a widening is a raise until a reply: test asserts it: %+v", d.Levels)
	}
	// A narrow grant losing a permit is no raise either, though every regex
	// in its reply changed.
	narrow := func(permits string) *Policy {
		return parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: [`+permits+`]}
`+subjOK+grantOK)
	}
	if d := Compare(narrow(`"show version", "show route **"`), narrow(`"show version"`), noon); d.UnacknowledgedLevels() != 0 {
		t.Errorf("revoking a narrow permit: %+v", d.Levels)
	}
}

// A composition that gets the fail-closed reply fails the diff, whether or
// not the change brought it (spec §8; §13 decision 26).
func TestTheDiffRefusesAFailClosedReply(t *testing.T) {
	refused := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
`+subjOK+grantOK)
	d := Compare(refused, refused, noon)
	if len(d.ProjectionRefusals) != 1 || !strings.Contains(d.ProjectionRefusals[0].Message, "(refused_shape)") {
		t.Fatalf("%+v", d.ProjectionRefusals)
	}
}

// A fail-closed reply is no raise, whatever it replaced: it is refused
// instead, which fails the diff on its own (plan 5b pre-flight R-M8).
func TestAFailClosedReplyIsNoRaise(t *testing.T) {
	grant := func(role string) *Policy {
		return parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+"roles:\n"+role+subjOK+grantOK)
	}
	// The fail-closed reply allows show version, which the first reply did
	// not run: the device does more, and the refusal is what fails the diff.
	for _, was := range []string{
		"  - {name: r, privilege: readonly, permit: [\"show route\"]}\n",
		"  - {name: r, privilege: readonly, permit: [\"show **\"]}\n",
	} {
		d := Compare(grant(was), grant(`  - {name: r, privilege: readonly, permit: ["show version", "show interfaces **"], `+
			`deny: ["show interfaces terse"]}
`), noon)
		if len(d.ProjectionRefusals) != 1 || slices.ContainsFunc(d.Levels, func(l LevelChange) bool {
			return slices.Contains(l.Raised, "reply")
		}) {
			t.Errorf("%s: %+v %+v", was, d.ProjectionRefusals, d.Levels)
		}
	}
}

// A projection change says where the new reply is narrower than port49, as
// policy test does: the commands the device refuses, and beside them the
// allows sent under bits that do not reach them (task 8 review; Result.Unreached).
func TestAProjectionChangeSaysWhereTheDeviceIsNarrower(t *testing.T) {
	bindingRPCs(t)
	before := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: operator, permit: ["show **"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	after := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: operator, permit: ["show **", "clear counters", "ping **"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	d := Compare(before, after, noon)
	if len(d.Projections) != 1 || !slices.Equal(d.Projections[0].Unreached, []string{"clear counters", "ping **"}) {
		t.Fatalf("%+v", d.Projections)
	}
	// What it lists is redacted, whatever reached it (spec §5.8).
	const secret = "show system radius-server 10.0.0.1 secret HUNTER2"
	rule := engine.Rule{Verdict: engine.Permit, Rule: secret, Role: "r"}
	pc, ok := projectionChange(nil, &projection.Result{Shape: projection.ShapeCapability,
		Unreached: []engine.Rule{rule}}, mustParse(t, readonlyCarveOut).Redactions(), nil)
	if shown := strings.Join(slices.Concat(pc.Narrower, pc.Unreached), "\n"); !ok ||
		strings.Contains(shown, "HUNTER2") || !strings.Contains(shown, platform.Redacted) {
		t.Fatalf("%v %q", ok, shown)
	}
}

// Rules on a platform that neither asks port49 nor has them projected decide
// nothing, and CI says so (spec §9); projected, they are the reply.
func TestUnenforcedRules(t *testing.T) {
	count := func(p *Policy) int {
		n := 0
		for _, f := range p.Lint(noon) {
			if f.Kind == FindingUnenforcedRules {
				n++
			}
		}
		return n
	}
	if n := count(mustParse(t, readonlyCarveOut)); n != 1 {
		t.Errorf("1.0.0: %d", n)
	}
	if n := count(parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)); n != 0 {
		t.Errorf("projected: %d", n)
	}
}

// A baseline deny the entry deny refuses is reported beside the reply, not
// sent (decision 44 ruling 10).
func TestTheProjectionMessageNamesWhatTheEntryDenyCloses(t *testing.T) {
	pr := projection.Result{Shape: projection.ShapeCapability, Bits: []string{"view"},
		Closed: []engine.Rule{{Verdict: engine.Deny, Rule: "xml-mode **", Role: platform.BaselineBit}}}
	if msg := projectionMessage(pr, nil, nil); !strings.Contains(msg, "; refused by the entry deny, sent as nothing: xml-mode **") {
		t.Errorf("%q", msg)
	}
}

// parseEntry is parseProjected under user_permissions with set 1.2.0's entry
// deny on the test set, and view-configuration reaching `show log` too, so a
// deny of `show configuration` is sent beneath the bit, not aligned with it.
func parseEntry(t *testing.T, body string) *Policy {
	t.Helper()
	e := projectedEnv(platform.BitDeliveryUserPermissions)
	d := e.Sets[projectedSet]["juniper_junos"]
	d.RPCEntryDenies = []string{"junoscript **"}
	d.Bits["view-configuration"] = []string{"show configuration **", "show log **"}
	e.Sets[projectedSet]["juniper_junos"] = d
	p, err := Parse([]byte("platform_set: "+projectedSet+"\n"+body), e)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The entry deny closes NETCONF for that subject, and a deny of `show
// configuration` beneath view-configuration is Ryan's operator error: each a
// warning, failing nothing; policy diff prints the ones a change brings
// (decision 44 ruling 4).
func TestTheEntryDenyWarnings(t *testing.T) {
	plain := parseEntry(t, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"]}
`+subjOK+grantOK)
	denies := parseEntry(t, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	kinds := func(fs []Finding) map[string][]string {
		out := map[string][]string{}
		for _, f := range fs {
			out[f.Kind] = append(out[f.Kind], f.Message)
		}
		return out
	}
	got := kinds(denies.Projections(noon))
	if n := got[FindingProjectionNetconfClosed]; len(n) != 1 || !strings.Contains(n[0], "no NETCONF") {
		t.Errorf("netconf closed: %q", n)
	}
	if v := got[FindingProjectionDenyBeneathViewConfiguration]; len(v) != 1 ||
		!strings.Contains(v[0], "show configuration **") || !strings.Contains(v[0], "withhold view-configuration") {
		t.Errorf("view-configuration: %q", v)
	}
	if ProjectionRefusals(denies.Projections(noon)) != 0 {
		t.Error("a warning fails policy test")
	}
	if p := kinds(plain.Projections(noon)); len(p[FindingProjectionNetconfClosed])+
		len(p[FindingProjectionDenyBeneathViewConfiguration]) != 0 {
		t.Errorf("no deny beneath, no warning: %v", p)
	}
	d := Compare(plain, denies, noon)
	if len(d.ProjectionWarnings) != 2 || len(d.ProjectionRefusals) != 0 {
		t.Errorf("the change brings two warnings: %+v", d.ProjectionWarnings)
	}
	if d := Compare(denies, denies, noon); len(d.ProjectionWarnings) != 0 {
		t.Errorf("an unchanged warning is not repeated: %+v", d.ProjectionWarnings)
	}
}

// A set that carries no rpc_entry_denies (1.1.0) leaves NETCONF on whatever
// the shape: a narrow result there gets no netconf-closed warning (R8).
func TestNoNetconfClosedWarningWithoutEntryDenies(t *testing.T) {
	// Two show commands are narrower than any whole bit: the narrow shape, on
	// the test set, which carries no rpc_entry_denies.
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+narrowRole+subjOK+grantOK)
	narrow := false
	for _, f := range p.Projections(noon) {
		if f.Kind == FindingProjection && strings.Contains(f.Message, "narrow shape") {
			narrow = true
		}
		if f.Kind == FindingProjectionNetconfClosed {
			t.Errorf("a set with no entry denies warned: %s", f.Message)
		}
	}
	if !narrow {
		t.Errorf("the fixture is no longer the narrow shape: %v", p.Projections(noon))
	}
}

// netconfRemedy is the one remedy both shapes' netconf-closed warnings give
// (decision 44 ruling 3): the reply's denies come from what the bits reach
// and the grant does not permit, not from denies the grant writes.
const netconfRemedy = "an account keeps NETCONF only where its reply sends no deny: " +
	"grant everything the level's bits reach (a readonly `**` does)"

// On shipped set 1.2.0 a readonly grant of `show **` and `monitor **` has no
// deny of its own and still takes the entry deny, from the bits' reach: the
// warning carries the one remedy, which names no deny the grant wrote. A
// readonly `**` sends no deny and gets no warning.
func TestTheNetconfClosedRemedyIsTheReplysNotTheGrants(t *testing.T) {
	closed := func(role string) []string {
		p := mustParse(t, "platform_set: 1.2.0\n"+scopeOK+"roles:\n  - "+role+"\n"+subjOK+grantOK)
		var got []string
		for _, f := range p.Projections(noon) {
			if f.Kind == FindingProjectionNetconfClosed {
				got = append(got, f.Message)
			}
		}
		return got
	}
	got := closed(`{name: r, privilege: readonly, permit: ["show **", "monitor **"]}`)
	if len(got) != 1 || !strings.Contains(got[0], netconfRemedy) || !strings.Contains(got[0], "the reply adds deny") ||
		strings.Contains(got[0], "no deny beneath") || strings.Contains(got[0], "reaches whole bits") {
		t.Errorf("deny-less grant, entry deny: %q", got)
	}
	if got := closed(`{name: r, privilege: readonly, permit: ["**"]}`); len(got) != 0 {
		t.Errorf("a readonly ** keeps NETCONF: %q", got)
	}
}

const narrowRole = `roles:
  - {name: r, privilege: readonly, permit: ["show version", "show interfaces **"]}
`

// The narrow shape closes NETCONF with no deny beneath any bit, so the
// warning carries the one remedy (decision 44 ruling 3): the account keeps
// NETCONF only where its reply sends no deny. Each warning is written after its subject
// and platform with a colon, its rules quoted, and names no device where it
// is on every one.
func TestTheNarrowNetconfClosedWarningAdvises(t *testing.T) {
	p := parseEntry(t, scopeOK+narrowRole+subjOK+grantOK)
	var got []string
	for _, f := range p.Projections(noon) {
		if f.Kind == FindingProjectionNetconfClosed {
			got = append(got, f.Message)
		}
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], `subject "s" on juniper_junos: the narrow reply's `) ||
		!strings.Contains(got[0], netconfRemedy) || strings.Contains(got[0], "reaches whole bits") ||
		strings.Contains(got[0], "no deny beneath") || strings.Contains(got[0], "; on ") {
		t.Errorf("narrow netconf closed: %q", got)
	}
	denies := parseEntry(t, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **", "show configuration"]}
`+subjOK+grantOK)
	found := false
	for _, f := range denies.Projections(noon) {
		if f.Kind == FindingProjectionDenyBeneathViewConfiguration {
			found = true
			if !strings.Contains(f.Message, `: deny "show configuration", "show configuration **" is sent beneath`) {
				t.Errorf("beneath rules quoted and joined: %q", f.Message)
			}
		}
	}
	if !found {
		t.Errorf("no beneath warning: %v", denies.Projections(noon))
	}
}
