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
	p := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
	res, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
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
	if testing.Short() {
		t.Skip("load-time bound")
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
	p := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
	want, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil {
		t.Fatal(err)
	}
	wantAttrs, wantBeyond := slices.Clone(want.Projection.Attributes), slices.Clone(want.Projection.Beyond)
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
			res.Projection.Beyond = append(res.Projection.Beyond[:0], engine.Rule{Verdict: engine.Permit, Rule: "**"})
			res.Projection.Denies = slices.DeleteFunc(res.Projection.Denies, func(engine.Rule) bool { return true })
		}()
	}
	wg.Wait()
	got, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil || !reflect.DeepEqual(got.Projection.Attributes, wantAttrs) ||
		!reflect.DeepEqual(got.Projection.Beyond, wantBeyond) ||
		!reflect.DeepEqual(got.Projection.Denies, want.Projection.Denies) {
		t.Fatalf("%q %v", got.Projection.Attributes, err)
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
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **", "clear counters"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjection {
			got = append(got, f.Message)
		}
	}
	want := `subject "s" on juniper_junos: capability shape, bits view; refused by the bits, sent as nothing: ` +
		`show configuration **; beyond the level's bits, not sent: clear counters; the device refuses what port49 ` +
		`permits, e.g. clear counters`
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
	// and says it binds every subject at that template.
	body = scopeOK + "roles:\n  - {name: r, privilege: readonly, permit: [\"show **\"], deny: ["
	for i, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"} {
		if i > 0 {
			body += ", "
		}
		body += `"show ` + w + ` **"`
	}
	// A deny narrower than every command goes out only once L9 measures that
	// the device matches it against the expanded command.
	saved := projection.JunosFacts
	projection.JunosFacts.DenyMatchesExpanded = true
	defer func() { projection.JunosFacts = saved }()
	p = parseProjected(t, platform.BitDeliveryLocalUserName, body+"]}\n"+subjOK+grantOK)
	over = nil
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionOverflow {
			over = append(over, f)
		}
	}
	if len(over) != 1 || !strings.Contains(over[0].Message, "binding every subject at that template: "+
		"set system login class p49-readonly deny-commands \"^( *[sS]") {
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
  - {name: more, privilege: readonly, permit: ["show route"]}
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
	// Each message redacts what it lists itself, whatever reached it.
	patterns := mustParse(t, readonlyCarveOut).Redactions()
	rule := engine.Rule{Verdict: engine.Permit, Rule: secret, Role: "r"}
	for _, msg := range []string{
		projectionMessage(projection.Result{Shape: projection.ShapeCapability,
			Denies: []engine.Rule{rule}, Allows: []engine.Rule{rule}, Omitted: []engine.Rule{rule},
			Beyond: []engine.Rule{rule}, Unreached: []engine.Rule{rule}}, patterns, nil),
		second(refusedMessage(projection.Result{FailClosed: projection.FailOverflow,
			Allows: []engine.Rule{rule}, Refusal: &projection.Refusal{Why: "w", Attribute: "deny-commands",
				Value: "^(" + secret + ")$", Class: "p49-readonly"}}, patterns)),
		second(refusedMessage(projection.Result{FailClosed: projection.FailRefusedShape,
			Allows: []engine.Rule{rule}, Refusal: &projection.Refusal{Why: "w"}}, patterns)),
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
	if c := strings.Join(ProjectionCaveats(res, "juniper_junos", engine.Outcome{}), "\n"); !strings.Contains(c,
		"gets the fail-closed reply there") || strings.Contains(c, "the device runs") {
		t.Fatalf("%q", c)
	}
}

// A probe prints each argument made from a hidden value, the value itself,
// padded, or a piece a probe split or cut short, as redacted, and every other
// argument as probed (re-review 2, R5): diff's changed commands and a
// projection's narrower examples both print through it.
func TestAProbeMadeFromAHiddenValuePrintsRedacted(t *testing.T) {
	src := map[string][]string{"Kilo": {"Kilo7"}, "7": {"Kilo7"}, " Kilo7": {"Kilo7"}, "community": {"community"}}
	got := probeShown([]string{"username", "community", "Kilo", "7", " Kilo7", "kilo7"}, src, []string{"KILO7"})
	want := []string{"username", "community", platform.Redacted, platform.Redacted, platform.Redacted, platform.Redacted}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}
