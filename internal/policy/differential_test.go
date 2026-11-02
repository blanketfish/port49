package policy

// The differential test: the memoized and indexed paths of Parse's joint
// checks, composeAll, ClassAges, MFARequirements and Compare against the
// frozen per-device oracle (oracle_test.go), over randomized fleets. The
// fleets vary every input resolve reads of a device (the inventory in the plan
// 12c Task 6b brief) and the ones it does not (addresses, key pins,
// transport), so a read added later fails here.

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
)

// fleetSpec is one random fleet's policy, as data so an edit can change it.
type fleetSpec struct {
	custom   bool // privilege_levels adds netops under operator
	defMFA   string
	scopes   []scopeSpec
	roles    []roleSpec
	subjects []subjectSpec
	grants   []grantSpec
}

type scopeSpec struct {
	name, match, onMissing, attached, mfa string
}

type roleSpec struct {
	name, privilege string
	permit, deny    []string
	pipe            string
	attrs           string
	age             string
	mfa             string
}

type subjectSpec struct{ name, line string }

type grantSpec struct {
	subject, scope string
	roles          []string
	max, expires   string
}

var fleetPlatforms = []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos", "srx_variant", "nokia_srlinux"}

func pick[T any](r *rand.Rand, xs ...T) T { return xs[r.IntN(len(xs))] }

func chance(r *rand.Rand, percent int) bool { return r.IntN(100) < percent }

// randomFleet is the policy text, the inventory and an edited copy of the
// text for one seed.
func randomFleet(r *rand.Rand) (policyText string, devs []admission.Device, after string) {
	spec := randomSpec(r)
	devs = randomDevices(r)
	edited := spec.edit(r)
	return spec.render(), devs, edited.render()
}

func randomDevices(r *rand.Rand) []admission.Device {
	sites := []string{"dc1", "dc2", "edge"}
	versions := []string{"21.4R3-S4", "21.4R3-S5", "22.2R1", "beta", ""}
	serials := []string{"SN100", "XX900", ""}
	n := 14 + r.IntN(24)
	var devs []admission.Device
	for i := range n {
		d := admission.Device{Name: fmt.Sprintf("dev-%02d", i), Platform: fleetPlatforms[r.IntN(len(fleetPlatforms))],
			Attributes: map[string]string{}}
		// A device with no platform set is a generic one.
		if v := pick(r, versions...); v != "" {
			d.Attributes["os_version"] = v
		}
		if v := pick(r, serials...); v != "" {
			d.Attributes["serial"] = v
		}
		if chance(r, 85) {
			d.Attributes["site"] = pick(r, sites...)
		}
		// None of these is read by a composition: they vary within a class.
		d.Addresses = []netip.Addr{netip.AddrFrom4([4]byte{10, 0, byte(i / 250), byte(1 + i%250)})}
		if chance(r, 30) {
			d.KeyRef = pick(r, "k1", "k2")
		}
		if chance(r, 20) {
			d.Transport = admission.TransportTLS
		}
		if chance(r, 25) {
			d.Attributes["ignored"] = strconv.Itoa(r.IntN(1000))
		}
		devs = append(devs, d)
	}
	// One device whose name alone puts a {device} attribute past 255 bytes.
	devs = append(devs, admission.Device{Name: "long-" + strings.Repeat("x", 247), Platform: "arista_eos",
		Addresses:  []netip.Addr{netip.MustParseAddr("10.9.9.9")},
		Attributes: map[string]string{"site": "dc1", "os_version": "22.2R1"}})
	r.Shuffle(len(devs), func(i, j int) { devs[i], devs[j] = devs[j], devs[i] })
	return devs
}

func randomSpec(r *rand.Rand) fleetSpec {
	s := fleetSpec{custom: chance(r, 30)}
	if chance(r, 25) {
		s.defMFA = pick(r, "{accept: [hardware_key_touch, idp_mfa]}", "{accept: [idp_mfa]}",
			"{accept: [idp_mfa], applies_to_machines: true}")
	}
	mfa := func() string {
		if !chance(r, 20) {
			return ""
		}
		return pick(r, "{accept: [hardware_key_touch], reuse_for: 5m}", "{accept: [idp_mfa]}",
			"{accept: [hardware_key_touch, idp_mfa], reuse_for: 30m}", "{accept: [hardware_key_touch], applies_to_machines: true}")
	}
	pool := []scopeSpec{
		{name: "by_platform", match: "{platform: [" + pick(r, "arista_eos", "juniper_junos", "cisco_nxos") + ", srx_variant]}", onMissing: pick(r, "include", "exclude")},
		{name: "by_site", match: "{site: [dc1, edge]}", onMissing: pick(r, "include", "exclude")},
		{name: "by_site_one", match: "{site: dc2}", onMissing: pick(r, "include", "exclude")},
		{name: "unpatched", match: `{os_version: {lt: "21.4R3-S5"}}`, onMissing: pick(r, "include", "exclude")},
		{name: "patched", match: `{os_version: {gte: "22.2R1"}}`, onMissing: pick(r, "include", "exclude")},
		{name: "by_serial", match: `{serial: {re: "^SN1"}}`, onMissing: pick(r, "include", "exclude")},
		{name: "pinned", match: "{name: [dev-03, dev-07, dev-11]}", onMissing: "exclude"},
		{name: "pinned_one", match: "{name: dev-05}", onMissing: "exclude"},
		{name: "eos_site", match: "{platform: arista_eos, site: dc1}", onMissing: "include"},
	}
	s.scopes = []scopeSpec{{name: "all_devices", match: "{}"}}
	for _, i := range r.Perm(len(pool))[:3+r.IntN(4)] {
		sc := pool[i]
		sc.mfa = mfa()
		s.scopes = append(s.scopes, sc)
	}
	roleNames := []string{"ro", "ops", "adm", "attr", "devattr", "classed", "piped", "lvl"}
	roles := map[string]roleSpec{
		"ro":  {privilege: "readonly", permit: []string{"show **"}},
		"ops": {privilege: "operator", permit: []string{"show **", "clear counters"}, deny: []string{"show running-config"}},
		"adm": {privilege: "admin", permit: []string{"**"}},
		"attr": {privilege: "readonly", permit: []string{"show **"},
			attrs: pick(r, `{all: ["idletime*30"]}`, `{arista_eos: ["priv-lvl=15"], cisco_iosxe: ["priv-lvl=15"]}`, `{arista_eos: ["priv-lvl=2"], all: ["timeout*480"]}`, `{cisco_iosxe: ["priv-lvl=99"]}`)},
		"devattr": {privilege: "readonly", permit: []string{"show **"},
			attrs: `{arista_eos: ["home-directory*/h/{device}"]}`},
		"classed": {privilege: "operator", permit: []string{"show **"}, deny: []string{"interface @uplink", "show interfaces ge-0/0/0"}},
		"piped":   {privilege: "readonly", permit: []string{"show **"}, pipe: "{permit: [grep **, count]}"},
		"lvl":     {privilege: pick(r, "netops", "operator", "readonly"), permit: []string{"show version"}},
	}
	for _, n := range roleNames {
		rs := roles[n]
		rs.name = n
		if rs.privilege == "netops" && !s.custom {
			rs.privilege = "operator"
		}
		rs.age = pick(r, "", "", "8h", "never", "2h")
		rs.mfa = mfa()
		s.roles = append(s.roles, rs)
	}
	s.roles = append(s.roles, roleSpec{name: "attach_ro", privilege: "readonly", permit: []string{"show version"}})
	// Roles attached to scopes: to humans, machines, or both.
	for i := 1; i < len(s.scopes); i++ {
		if chance(r, 25) {
			s.scopes[i].attached = pick(r, "{humans: [attach_ro]}", "{machines: [attach_ro]}", "{humans: [ro], machines: [attach_ro]}")
		}
	}
	// Subjects: humans, machines and a group subject, with each enable.
	nh, nm := 3+r.IntN(3), 2+r.IntN(2)
	for i := range nh {
		s.subjects = append(s.subjects, subjectSpec{name: fmt.Sprintf("h%d", i), line: fmt.Sprintf(
			`{name: h%d, identity: ["user:h%d@example.com"], username: h%d, enable: %s, token_ttl: 60s}`, i, i, i, pick(r, "none", "token", "auto"))})
	}
	for i := range nm {
		s.subjects = append(s.subjects, subjectSpec{name: fmt.Sprintf("m%d", i), line: fmt.Sprintf(
			`{name: m%d, identity: ["spiffe://example.com/m%d"], username: m%d, token_ttl: 60s}`, i, i, i)})
	}
	s.subjects = append(s.subjects, subjectSpec{name: "g0", line: `{name: g0, group: grp-0, enable: ` + pick(r, "none", "token") + `, token_ttl: 5m}`})
	// Grants: several per subject, never one row twice.
	seen := map[string]bool{}
	scopeNames := func() string { return s.scopes[r.IntN(len(s.scopes))].name }
	expiries := []string{"", "", "", "", "2026-01-01", "2026-12-01", "2026-12-01", "2027-03-01T08:30:00Z"}
	for _, sub := range s.subjects {
		for range 1 + r.IntN(4) {
			g := grantSpec{subject: sub.name, scope: scopeNames(), expires: pick(r, expiries...)}
			g.roles = []string{s.roles[r.IntN(len(s.roles)-1)].name}
			if chance(r, 25) {
				if second := s.roles[r.IntN(len(s.roles)-1)].name; second != g.roles[0] {
					g.roles = append(g.roles, second)
				}
			}
			if chance(r, 25) {
				g.max = pick(r, "readonly", "operator", "admin")
			}
			key := g.subject + g.scope + strings.Join(slices.Sorted(slices.Values(g.roles)), ",")
			if !seen[key] {
				seen[key] = true
				s.grants = append(s.grants, g)
			}
		}
	}
	// Two subjects holding one scope and roles: a tie for composeAll's sort.
	if chance(r, 70) {
		for _, name := range []string{"h0", "h1"} {
			key := name + "all_devices" + "ro"
			if !seen[key] {
				seen[key] = true
				s.grants = append(s.grants, grantSpec{subject: name, scope: "all_devices", roles: []string{"ro"}})
			}
		}
	}
	return s
}

func (s fleetSpec) render() string {
	var b strings.Builder
	b.WriteString("platform_set: 1.1.0\nplatforms:\n  srx_variant: {based_on: juniper_junos, redact: [{match: ['**'], after: interfaces}]}\n")
	b.WriteString("  arista_eos:\n    entity_classes:\n      uplink: ['^Ethernet(49|50)$']\n")
	if s.custom {
		b.WriteString("privilege_levels: [{name: readonly}, {name: operator}, {name: admin}, {name: netops, parent: operator}]\n")
	}
	if s.defMFA != "" {
		fmt.Fprintf(&b, "defaults:\n  per_login_mfa: %s\n", s.defMFA)
	}
	b.WriteString("scopes:\n")
	for _, sc := range s.scopes {
		fmt.Fprintf(&b, "  - {name: %s, match: %s", sc.name, sc.match)
		if sc.onMissing != "" {
			fmt.Fprintf(&b, ", on_missing: %s", sc.onMissing)
		}
		if sc.attached != "" {
			fmt.Fprintf(&b, ", attached_roles: %s", sc.attached)
		}
		if sc.mfa != "" && sc.match != "{}" {
			fmt.Fprintf(&b, ", security_log: true, per_login_mfa: %s", sc.mfa)
		}
		b.WriteString("}\n")
	}
	b.WriteString("roles:\n")
	for _, ro := range s.roles {
		fmt.Fprintf(&b, "  - {name: %s, privilege: %s, permit: [%s]", ro.name, ro.privilege, quoteAll(ro.permit))
		if len(ro.deny) > 0 {
			fmt.Fprintf(&b, ", deny: [%s]", quoteAll(ro.deny))
		}
		if ro.pipe != "" {
			fmt.Fprintf(&b, ", pipe: %s", ro.pipe)
		}
		if ro.attrs != "" {
			fmt.Fprintf(&b, ", attributes: %s", ro.attrs)
		}
		if ro.age != "" {
			fmt.Fprintf(&b, ", max_session_age: %s", ro.age)
		}
		if ro.mfa != "" {
			fmt.Fprintf(&b, ", per_login_mfa: %s", ro.mfa)
		}
		b.WriteString("}\n")
	}
	b.WriteString("subjects:\n")
	for _, sub := range s.subjects {
		fmt.Fprintf(&b, "  - %s\n", sub.line)
	}
	b.WriteString("grants:\n")
	for _, g := range s.grants {
		fmt.Fprintf(&b, "  - {subject: %s, scope: %s, roles: [%s]", g.subject, g.scope, strings.Join(g.roles, ", "))
		if g.max != "" {
			fmt.Fprintf(&b, ", max_privilege: %s", g.max)
		}
		if g.expires != "" {
			fmt.Fprintf(&b, ", expires: %s", g.expires)
		}
		b.WriteString("}\n")
	}
	b.WriteString("keys:\n  k1: {current: {version: 1, secret_ref: env:PORT49_KEY_DIFF}}\n  k2: {current: {version: 1, secret_ref: env:PORT49_KEY_DIFF}}\n")
	b.WriteString("key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: k1}\n")
	return b.String()
}

func quoteAll(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = strconv.Quote(x)
	}
	return strings.Join(q, ", ")
}

// edit is a copy of s with one to three random edits: a role's rule, a
// scope's match, a grant removed or its expiry moved, a max_session_age, a
// per_login_mfa accept list.
func (s fleetSpec) edit(r *rand.Rand) fleetSpec {
	e := s
	e.scopes, e.roles, e.grants = slices.Clone(s.scopes), slices.Clone(s.roles), slices.Clone(s.grants)
	for range 1 + r.IntN(3) {
		switch r.IntN(6) {
		case 0:
			i := r.IntN(len(e.roles))
			e.roles[i].permit = slices.Clone(e.roles[i].permit)
			e.roles[i].permit = append(e.roles[i].permit, pick(r, "clear counters", "show running-config", "ping **", "reload"))
		case 1:
			if i := 1 + r.IntN(len(e.scopes)-1); e.scopes[i].match != "{}" {
				e.scopes[i].match = pick(r, "{site: [dc2]}", "{site: [dc1, dc2, edge]}", "{name: [dev-01, dev-02]}",
					`{os_version: {lt: "22.2R1"}}`, "{platform: cisco_iosxe}")
				if strings.Contains(e.scopes[i].match, "name") {
					e.scopes[i].onMissing = "exclude"
				} else if e.scopes[i].onMissing == "" {
					e.scopes[i].onMissing = "include"
				}
			}
		case 2:
			if len(e.grants) > 1 {
				i := r.IntN(len(e.grants))
				e.grants = slices.Delete(e.grants, i, i+1)
			}
		case 3:
			i := r.IntN(len(e.grants))
			e.grants[i].expires = pick(r, "", "2026-12-01", "2027-06-01", "2026-01-01")
		case 4:
			i := r.IntN(len(e.roles))
			e.roles[i].age = pick(r, "", "1h", "never", "8h")
		case 5:
			i := r.IntN(len(e.roles))
			e.roles[i].mfa = pick(r, "", "{accept: [idp_mfa]}", "{accept: [hardware_key_touch, idp_mfa], reuse_for: 5m}")
		}
	}
	return e
}

// sentinels are the errors a resolution can be told apart by.
var sentinels = []error{ErrNoGrants, ErrDeviceQuarantined, ErrDeviceRefused, ErrMFADisjoint, errMFAMachine}

func sameError(t *testing.T, what string, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("%s: error %v, oracle %v", what, got, want)
	}
	if got == nil {
		return
	}
	if got.Error() != want.Error() {
		t.Fatalf("%s: error text\n  got    %q\n  oracle %q", what, got.Error(), want.Error())
	}
	for _, s := range sentinels {
		if errors.Is(got, s) != errors.Is(want, s) {
			t.Fatalf("%s: errors.Is(%v) differs: %v vs oracle %v", what, s, got, want)
		}
	}
}

// coverage counts what the fleets exercised, from the oracle's results.
type coverage struct {
	mu                                                        sync.Mutex
	parsed, seeds                                             int
	sharedClass, mfaClassQuarantine, plainQuarantine          int
	lapsing, noGrants, projected, longRefusal, tie, splitting int
	longRefusalElsewhere                                      int
}

func (c *coverage) add(f func(*coverage)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

func (c *coverage) String() string {
	return fmt.Sprintf("seeds=%d parsed=%d shared_class=%d mfa_class_quarantine=%d plain_quarantine=%d lapsing=%d "+
		"no_grants=%d projected=%d long_name_refusal=%d (elsewhere=%d) r18_tie=%d class_split=%d", c.seeds, c.parsed,
		c.sharedClass, c.mfaClassQuarantine, c.plainQuarantine, c.lapsing, c.noGrants, c.projected, c.longRefusal,
		c.longRefusalElsewhere, c.tie, c.splitting)
}

func (c *coverage) problems() []string {
	var out []string
	for name, n := range map[string]int{"shared_class": c.sharedClass, "mfa_class_quarantine": c.mfaClassQuarantine,
		"plain_quarantine": c.plainQuarantine, "lapsing": c.lapsing, "no_grants": c.noGrants, "projected": c.projected,
		"long_name_refusal": c.longRefusal, "r18_tie": c.tie, "class_split": c.splitting} {
		if n == 0 {
			out = append(out, name+" never happened")
		}
	}
	return out
}

func fleetEnv(devs []admission.Device) Env {
	return Env{Now: noon, Devices: devs}
}

// parseFleet is Parse of text over devs, ok false for a seed whose random
// policy the loader refuses.
func parseFleet(t testing.TB, text string, devs []admission.Device) (*Policy, bool) {
	t.Helper()
	t.Setenv("PORT49_KEY_DIFF", "not-a-real-key-0123456789")
	p, err := Parse([]byte(text), fleetEnv(devs))
	return p, err == nil
}

func instantsOf(p *Policy) []time.Time {
	return append([]time.Time{{}}, p.expiryInstants(noon)...)
}

// checkSeed runs every assertion for one seed against the oracle, counting
// coverage into cov when it is not nil.
func checkSeed(t *testing.T, seed uint64, cov *coverage) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed))
	text, devs, afterText := randomFleet(r)
	p, ok := parseFleet(t, text, devs)
	if cov != nil {
		cov.add(func(c *coverage) { c.seeds++ })
	}
	if !ok {
		return
	}
	if cov != nil {
		cov.add(func(c *coverage) { c.parsed++ })
	}
	where := func(what string, sub string, d admission.Device, at time.Time) string {
		return fmt.Sprintf("seed %d: %s, subject %s, device %s, at %s", seed, what, sub, d.Name[:min(len(d.Name), 12)], at.Format(time.RFC3339))
	}
	instants := instantsOf(p)
	names := sortedKeys(p.subs)
	subjectSets := [][]*Subject{}
	for _, n := range names {
		subjectSets = append(subjectSets, []*Subject{p.subs[n]})
	}
	rs := rand.New(rand.NewPCG(seed, seed+1))
	for range 3 {
		set := []*Subject{p.subs[names[rs.IntN(len(names))]], p.subs[names[rs.IntN(len(names))]]}
		if chance(rs, 40) {
			set = append(set, p.subs[names[rs.IntN(len(names))]])
		}
		subjectSets = append(subjectSets, set)
	}
	subjectSets = append(subjectSets, []*Subject{p.subs[names[0]], p.subs[names[0]]}) // a duplicated subject
	for _, d := range devs {
		for _, at := range instants {
			for _, set := range subjectSets {
				got, want := p.composeAll(set, d, at), oracleComposeAll(p, set, d, at)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: composeAll differs\n  got    %+v\n  oracle %+v", where("compose "+set[0].Name, set[0].Name, d, at), got, want)
				}
			}
			for _, n := range names {
				sub := p.subs[n]
				got, gerr := p.resolve(sub, d, at)
				want, werr := oracleResolve(p, sub, d, at)
				sameError(t, where("resolve", n, d, at), gerr, werr)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: resolution differs\n  got    %+v\n  oracle %+v", where("resolve", n, d, at), got, want)
				}
				got, gerr = p.ResolveSubject(n, d, at)
				want, werr = oracleResolveNow(p, sub, d, at)
				sameError(t, where("ResolveSubject", n, d, at), gerr, werr)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: ResolveSubject differs", where("ResolveSubject", n, d, at))
				}
				if cov != nil {
					cov.add(func(c *coverage) {
						switch {
						case errors.Is(werr, ErrNoGrants):
							c.noGrants++
						case want.Projection != nil:
							c.projected++
						}
					})
				}
			}
		}
	}
	// The quarantine pass, entry order included.
	oracleQ := oracleQuarantine(p)
	if !reflect.DeepEqual(p.quarantine, oracleQ) {
		t.Fatalf("seed %d: quarantine differs\n  got    %s\n  oracle %s", seed, dumpQuarantine(p.quarantine), dumpQuarantine(oracleQ))
	}
	for _, at := range instants {
		for _, plat := range fleetPlatforms {
			got, _ := p.ClassAges(plat, 12*time.Hour, at)
			want, _ := oracleClassAges(p, plat, 12*time.Hour, at)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d: ClassAges(%s) at %s: got %+v, oracle %+v", seed, plat, at, got, want)
			}
		}
		got, want := p.MFARequirements(at), oracleMFARequirements(p, at)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: MFARequirements at %s differs\n  got    %+v\n  oracle %+v", seed, at, got, want)
		}
	}
	after, afterOK := parseFleet(t, afterText, devs)
	if afterOK {
		got := Compare(p, after, noon)
		want := compareWith(p, after, noon, oracleSides{})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: Compare differs\n  got    %+v\n  oracle %+v", seed, got, want)
		}
	}
	if cov != nil {
		countCoverage(cov, p, after, afterOK, devs, oracleQ)
	}
}

func dumpQuarantine(q map[string]*Quarantine) string {
	var b strings.Builder
	for _, name := range sortedKeys(q) {
		fmt.Fprintf(&b, "\n%s:", name[:min(len(name), 12)])
		for _, e := range q[name].Entries {
			fmt.Fprintf(&b, " [from %s until %s lapsing %q mfa %v %q]", e.From.Format(time.RFC3339), e.Until.Format(time.RFC3339),
				e.Lapsing, e.MFA, e.Cause[:min(len(e.Cause), 60)])
		}
	}
	return b.String()
}

func countCoverage(cov *coverage, p, after *Policy, afterOK bool, devs []admission.Device, oracleQ map[string]*Quarantine) {
	scopes := sortedKeys(p.scopes)
	class := map[string][]admission.Device{}
	for _, d := range devs {
		k := p.signature(d, scopes)
		class[k] = append(class[k], d)
	}
	cov.add(func(c *coverage) {
		for _, members := range class {
			if len(members) < 2 {
				continue
			}
			c.sharedClass++
			for _, d := range members {
				q, ok := oracleQ[d.Name]
				if !ok {
					continue
				}
				for _, e := range q.Entries {
					if e.MFA {
						c.mfaClassQuarantine++
					}
				}
			}
		}
		for _, q := range oracleQ {
			for _, e := range q.Entries {
				if !e.MFA {
					c.plainQuarantine++
				}
				if e.Lapsing != "" {
					c.lapsing++
				}
			}
		}
		seen := map[string]string{}
		for _, g := range p.grants {
			k := g.Scope + "|" + strings.Join(g.Roles, ",")
			if other, ok := seen[k]; ok && other != g.Subject {
				c.tie++
			}
			seen[k] = g.Subject
		}
	})
	for _, d := range devs {
		for _, sub := range sortedKeys(p.subs) {
			if s := oracleSide(p, sub, d, noon); s.refused == "attribute_too_long" {
				cov.add(func(c *coverage) {
					if strings.HasPrefix(d.Name, "long-") {
						c.longRefusal++
					} else {
						c.longRefusalElsewhere++
					}
				})
			}
		}
	}
	if afterOK {
		aScopes := sortedKeys(after.scopes)
		children := map[string]map[string]bool{}
		for _, d := range devs {
			b := p.signature(d, scopes)
			if children[b] == nil {
				children[b] = map[string]bool{}
			}
			children[b][after.signature(d, aScopes)] = true
		}
		for _, kids := range children {
			if len(kids) > 1 {
				cov.add(func(c *coverage) { c.splitting++ })
				break
			}
		}
	}
}

func TestDifferentialAgainstTheOracle(t *testing.T) {
	last := uint64(300)
	if testing.Short() {
		last = 40
	}
	cov := &coverage{}
	for seed := uint64(1); seed <= last; seed++ {
		checkSeed(t, seed, cov)
	}
	t.Logf("coverage: %s", cov)
	minParsed := 200
	if testing.Short() {
		minParsed = 25
	}
	if cov.parsed < minParsed {
		t.Errorf("only %d of %d seeds parsed, want at least %d", cov.parsed, cov.seeds, minParsed)
	}
	if testing.Short() {
		return
	}
	for _, p := range cov.problems() {
		t.Errorf("coverage guard: %s", p)
	}
}

func FuzzDifferential(f *testing.F) {
	for seed := uint64(1); seed <= 20; seed++ {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed uint64) {
		checkSeed(t, seed, nil)
	})
}
