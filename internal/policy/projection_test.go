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
