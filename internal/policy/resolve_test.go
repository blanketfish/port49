package policy

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

var noon = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

// Spec §5.1 end to end for one principal on one device: the subject, the
// grants that selected it, the roles, the ceiling as the platform's number, and
// a blob that encodes — the rules carry their roles, the pipe list is the
// default, and the session reply is the platform's rendering of the level.
func TestResolveComposesAndCompiles(t *testing.T) {
	p := mustParse(t, good)
	r, err := p.Resolve("user:alice@example.com", deviceNamed(t, "leaf-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	if r.Subject != "alice" || r.Username != "alice" || r.Enable != "token" || r.TokenTTL != time.Minute ||
		r.Level != "readonly" || r.MaxPrivilege != 0 || r.HasCeiling || strings.Join(r.Roles, ",") != "no_disruptive,read_only" {
		t.Fatalf("resolution: %+v", r)
	}
	if len(r.Grants) != 1 || r.Grants[0].Scope != "all_devices" || r.Grants[0].Expires != "2026-12-01T00:00:00.000Z" {
		t.Fatalf("the mint record's grants: %+v", r.Grants)
	}
	b := r.Blob
	if b.Platform != "arista_eos" || b.Bundle != p.Bundle || b.Privilege != "readonly" ||
		!reflect.DeepEqual(b.Attributes, []string{"priv-lvl=1"}) || !reflect.DeepEqual(b.Pipe, sortedCopy(DefaultPipe)) ||
		b.Normalize.PipeToken != "|" || b.Normalize.PipeAuthorized || !b.Normalize.ExpandsAbbreviations {
		t.Fatalf("blob: %+v", b)
	}
	if len(b.Rules) != 4 || b.Rules[0] != (engine.Rule{Verdict: engine.Deny, Rule: "reload **", Role: "no_disruptive"}) {
		t.Fatalf("rules: %+v", b.Rules)
	}
	if _, _, err := engine.Encode(b); err != nil {
		t.Fatalf("the blob must encode: %v", err)
	}
	if _, err := p.Resolve("user:mallory@example.com", deviceNamed(t, "leaf-01"), noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("a principal no subject lists: %v", err)
	}
	if _, err := p.Resolve("user:alice@example.com", deviceNamed(t, "leaf-01"), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("an expired grant: %v", err)
	}
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// A platform that renders no level sends no attributes, and still numbers the
// ceiling for the token (plan 3's table); a group subject resolves by name
// only, since matching a person to a group is the directory's (plan 7).
func TestAPlatformThatRendersNothingStillHasACeiling(t *testing.T) {
	p := mustParse(t, good)
	if _, err := p.Resolve("CN=netops-admins,OU=Groups,DC=example,DC=com", deviceNamed(t, "nx-01"), noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("a group is never a principal: %v", err)
	}
	r, err := p.ResolveSubject("netops_admins", deviceNamed(t, "nx-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	if r.MaxPrivilege != 15 || !r.HasCeiling || r.Level != "admin" || len(r.Blob.Attributes) != 0 ||
		!reflect.DeepEqual(r.Blob.Pipe, []string{"**"}) {
		t.Fatalf("netops_admins on NX-OS: %+v", r)
	}
	if _, err := p.ResolveSubject("nobody", deviceNamed(t, "nx-01"), noon); err == nil {
		t.Fatal("an undeclared subject is an error")
	}
}

// One decision, one blob: two subjects holding the same roles on the same
// platform compile to the same bytes, whatever order their grants list the
// roles in (spec §5.1.1).
func TestTheSameCompositionIsTheSameBlob(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: a, permit: ["show  version", show **]}
  - {name: b, permit: [show **], deny: [reload **]}
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}
  - {name: t, identity: "user:t@example.com", username: t, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [a, b]}
  - {subject: t, scope: all_devices, roles: [b]}
  - {subject: t, scope: all_devices, roles: [a]}
`)
	s, _ := p.Resolve("user:s@example.com", deviceNamed(t, "leaf-01"), noon)
	u, _ := p.Resolve("user:t@example.com", deviceNamed(t, "leaf-01"), noon)
	_, h1, err1 := engine.Encode(s.Blob)
	_, h2, err2 := engine.Encode(u.Blob)
	if err1 != nil || err2 != nil || h1 != h2 {
		t.Fatalf("one decision, two blobs: %s %s %v %v", h1, h2, err1, err2)
	}
	nx, _ := p.Resolve("user:s@example.com", deviceNamed(t, "nx-01"), noon)
	if _, h3, _ := engine.Encode(nx.Blob); h3 == h1 {
		t.Fatal("two platforms must not share a blob")
	}
}

// Spec §6: platform → role → grant, most specific winning by attribute name,
// every override recorded, a parent chain rendering a custom level.
func TestAttributesLayerAndRecordWhatTheyShadow(t *testing.T) {
	p := mustParse(t, `
privilege_levels: [{name: readonly}, {name: read_only_limited, parent: readonly}, {name: operator}, {name: admin}]
scopes: [{name: all_devices, match: {}}, {name: dc_fabric, match: {site: dc1}}]
roles:
  - {name: limited, privilege: read_only_limited, permit: [show version],
     attributes: {all: ["idletime*30", "timeout*480"], arista_eos: ["priv-lvl=2"]}}
  - {name: homes, attributes: {all: ["home-directory*/home/{username}", "idletime*10"]}}
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [limited, homes]}
  - {subject: s, scope: dc_fabric, roles: [limited], attributes: {arista_eos: ["timeout*60"]}}
`)
	r, err := p.Resolve("user:s@example.com", deviceNamed(t, "leaf-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	// Order is first appearance — platform, then roles by name, then grants —
	// with an override taking the place of what it shadows.
	want := []string{"priv-lvl=2", "home-directory*/home/{username}", "idletime*30", "timeout*60"}
	if !reflect.DeepEqual(r.Blob.Attributes, want) {
		t.Fatalf("attributes %q, want %q", r.Blob.Attributes, want)
	}
	byName := map[string]AttributeSource{}
	for _, a := range r.Attributes {
		byName[engine.AttributeName(a.Attribute)] = a
	}
	if a := byName["priv-lvl"]; a.Source != "role limited" || len(a.Shadows) != 1 ||
		a.Shadows[0] != "priv-lvl=1 (platform arista_eos, level readonly)" {
		t.Errorf("the role shadows the platform's rendering of the parent level: %+v", a)
	}
	if a := byName["idletime"]; a.Source != "role limited" || a.Shadows[0] != "idletime*10 (role homes)" {
		t.Errorf("within the role layer, roles are taken by name: %+v", a)
	}
	if a := byName["timeout"]; !strings.HasPrefix(a.Source, "grant dc_fabric") || len(a.Shadows) != 1 {
		t.Errorf("the grant is the most specific layer: %+v", a)
	}
}

// The joint checks (spec §10; §13 decision 20): a device on which some
// subject's composition would not compile, or would contradict itself, is
// quarantined — named with the subject and the cause, refused at Resolve — and
// every other device loads. One quarantined device never takes the fleet down.
func TestJointCheckFailuresQuarantineTheDevice(t *testing.T) {
	all := []string{"campus-sw-7", "leaf-01", "nx-01", "srx-fw-04", "srx-fw-05", "srx-fw-22", "srx-lab-01", "xe-01"}
	for _, tt := range []struct {
		name, yaml, want string
		devices          []string
	}{
		{"a class the platform does not define", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: tech, permit: [interface @physical]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [tech]}]`, `role "tech" names @physical, which`,
			[]string{"nx-01", "srx-fw-04", "srx-fw-05", "srx-fw-22", "srx-lab-01", "xe-01"}},
		{"a level the platform cannot render", unmappedLevel + `
scopes: [{name: all_devices, match: {}}]
roles: [{name: op, privilege: unmapped, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [op]}]`, "level unmapped has no rendering on arista_eos",
			[]string{"campus-sw-7", "leaf-01"}},
		{"a landing level above the ceiling", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: adm, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [adm], max_privilege: readonly}]`, "above its grants' max_privilege", all},
		// §6 layering lets a role or grant override priv-lvl, and the device
		// is told what the reply says, not what the level renders to.
		{"a role's priv-lvl above the ceiling", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {arista_eos: ["priv-lvl=15"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], max_privilege: readonly}]`,
			"its session reply sends priv-lvl=15 (role ro)", []string{"campus-sw-7", "leaf-01"}},
		{"a grant's priv-lvl above the ceiling", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], max_privilege: readonly, attributes: {arista_eos: ["priv-lvl*15"]}}]`,
			"its session reply sends priv-lvl*15 (grant all_devices", []string{"campus-sw-7", "leaf-01"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := mustParse(t, tt.yaml)
			var got []string
			for _, q := range p.Quarantines(noon) {
				got = append(got, q.Device)
				if len(causesOf(q)) != 1 || !strings.Contains(causesOf(q)[0], tt.want) ||
					!strings.Contains(causesOf(q)[0], `subject "s"`) || !strings.Contains(causesOf(q)[0], q.Platform) {
					t.Errorf("%s: causes %q, want one naming subject s, %s and %q", q.Device, causesOf(q), q.Platform, tt.want)
				}
			}
			if strings.Join(got, ",") != strings.Join(tt.devices, ",") {
				t.Fatalf("quarantined %v, want %v", got, tt.devices)
			}
			for _, d := range inventory() {
				_, err := p.Resolve("user:s@example.com", d, noon)
				if slices.Contains(tt.devices, d.Name) != errors.Is(err, ErrDeviceQuarantined) {
					t.Errorf("%s: Resolve = %v", d.Name, err)
				}
			}
		})
	}
	// A class only EOS defines is fine on a scope that selects only EOS: the
	// check is per device, not per policy.
	if p := mustParse(t, `
scopes: [{name: eos, match: {platform: arista_eos}}]
roles: [{name: tech, permit: [interface @physical]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: eos, roles: [tech]}]`); len(p.Quarantines(noon)) != 0 {
		t.Fatalf("quarantined %+v", p.Quarantines(noon))
	}
	// A ceiling no platform can number is the policy's own error: no inventory
	// could make it load, so it is refused rather than quarantining the fleet.
	if _, err := Parse([]byte(unmappedLevel+`
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], max_privilege: unmapped}]`), env()); err == nil ||
		!strings.Contains(err.Error(), "no priv-lvl number on any platform") {
		t.Fatalf("Parse = %v", err)
	}
}

// A principal with no grant on a quarantined device hears no_grants_matched,
// not the quarantine: the mint API must not tell a caller which devices exist
// (design §17). Only a principal with a grant there hears the quarantine.
func TestAPrincipalWithNoGrantThereDoesNotHearTheQuarantine(t *testing.T) {
	p := mustParse(t, unmappedLevel+`
scopes: [{name: all_devices, match: {}}, {name: nx, match: {platform: cisco_nxos}}]
roles: [{name: op, privilege: unmapped, permit: [show **]}]
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}
  - {name: other, identity: "user:o@example.com", username: o, token_ttl: 60s}
grants: [{subject: s, scope: all_devices, roles: [op]}, {subject: other, scope: nx, roles: [op]}]`)
	leaf, ok := p.Device("leaf-01")
	if !ok {
		t.Fatal("inventory has no leaf-01")
	}
	if _, q := p.Quarantined("leaf-01", noon); !q {
		t.Fatal("leaf-01 renders no unmapped, so it is quarantined")
	}
	if _, err := p.Resolve("user:s@example.com", leaf, noon); !errors.Is(err, ErrDeviceQuarantined) {
		t.Fatalf("the granted principal: %v", err)
	}
	if _, err := p.Resolve("user:o@example.com", leaf, noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("Resolve for a principal with no grant there: %v", err)
	}
	if _, err := p.ResolveSubject("other", leaf, noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("ResolveSubject for a subject with no grant there: %v", err)
	}
}

// `enable: auto` quarantines a device whose enable exchange does not carry the
// principal (spec §5.6; §14). config.Load refuses such a platform today, so
// the check is exercised with a table that says otherwise.
func TestEnableAutoQuarantinesWhereTheEnableUsernameIsNotThePrincipal(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, enable: auto, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`
	e := env()
	if p, err := Parse([]byte(body), e); err != nil || len(p.Quarantines(noon)) != 0 {
		t.Fatalf("every shipped platform carries the principal: %v", err)
	}
	e.EnableUsernames = map[string]string{"arista_eos": platform.EnableEnab}
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	q := p.Quarantines(noon)
	if len(q) != 2 || q[0].Device != "campus-sw-7" || q[1].Device != "leaf-01" ||
		!strings.Contains(causesOf(q[0])[0], "enable: auto reaches this device") {
		t.Fatalf("quarantined %+v", q)
	}
}

// quarantinedAt parses body with the joint checks' present fixed at noon.
func quarantinedAt(t *testing.T, body string, e Env) (*Policy, map[string][]string) {
	t.Helper()
	e.Now = noon
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, q := range p.Quarantines(noon) {
		for _, e := range q.Entries {
			got[q.Device] = append(got[q.Device], e.Message(noon))
		}
	}
	return p, got
}

// A blob the engine would refuse at a mint is caught at load: a dialect with
// no pipe token compiles, and Encode refuses it.
func TestABlobTheEngineRefusesQuarantinesTheDevice(t *testing.T) {
	e := env()
	eos, _ := platform.DialectFor("arista_eos")
	eos.PipeToken = ""
	e.Dialects = map[string]platform.Dialect{"arista_eos": eos}
	_, got := quarantinedAt(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`, e)
	if len(got) != 2 || len(got["leaf-01"]) != 1 || len(got["campus-sw-7"]) != 1 ||
		!strings.Contains(got["leaf-01"][0], "compiled blob for arista_eos is refused") ||
		!strings.Contains(got["leaf-01"][0], "no pipe token") {
		t.Fatalf("quarantined %q", got)
	}
}

// causesOf is a quarantine's causes, in entry order.
func causesOf(q Quarantine) []string {
	var out []string
	for _, e := range q.Entries {
		out = append(out, e.Cause)
	}
	return out
}

// A composition changes when a grant expires, so the joint checks run again at
// every later expiry. Quarantine is time-scoped: a device that will fail once
// the admin grant lapses — the operator level left has no EOS rendering, or a
// lower ceiling is left under the landing level — keeps working until then,
// is scheduled for then, and says so; a load-time failure is quarantined from
// load, whatever time is asked.
func TestAnExpiryThatBreaksTheCompositionIsQuarantinedFromTheExpiry(t *testing.T) {
	before, lapse := time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	after, lastLapse := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	p, got := quarantinedAt(t, unmappedLevel+`
scopes: [{name: all_devices, match: {}}, {name: dc, match: {site: dc1}}]
roles:
  - {name: op, privilege: unmapped, permit: [show **]}
  - {name: adm, privilege: admin, permit: ["**"]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [op], expires: 2026-11-01}
  - {subject: s, scope: dc, roles: [adm], expires: 2026-10-01}`, env())
	leaf, campus := got["leaf-01"], got["campus-sw-7"]
	if len(got) != 2 || len(leaf) != 1 || len(campus) != 1 ||
		!strings.HasPrefix(leaf[0], "will be quarantined from 2026-10-01T00:00:00.000Z, when grant dc [adm] expires: ") ||
		!strings.Contains(leaf[0], "level unmapped has no rendering on arista_eos") ||
		!strings.HasPrefix(campus[0], `quarantined: subject "s": level unmapped`) {
		t.Fatalf("quarantines at noon: %q", got)
	}
	leaf01 := deviceNamed(t, "leaf-01")
	for _, tt := range []struct {
		at          time.Time
		quarantined bool
	}{{noon, false}, {before, false}, {lapse, true}, {after, true}, {lastLapse, false}} {
		cause, ok := p.Quarantined("leaf-01", tt.at)
		_, err := p.Resolve("user:s@example.com", leaf01, tt.at)
		if ok != tt.quarantined || errors.Is(err, ErrDeviceQuarantined) != tt.quarantined {
			t.Errorf("leaf-01 at %s: Quarantined = %q %v, Resolve = %v", tt.at, cause, ok, err)
		}
	}
	if _, err := p.Resolve("user:s@example.com", leaf01, noon); err != nil {
		t.Fatalf("access that works today keeps working: %v", err)
	}
	// Quarantined from load: the campus switch fails now, and still does at a
	// time before the load's present; its span ends when the op grant does.
	e := p.Quarantines(noon)[0].Entries[0]
	if !e.From.Equal(noon) || e.Lapsing != "" || !e.Until.Equal(lastLapse) {
		t.Fatalf("campus-sw-7's entry: %+v", e)
	}
	if _, ok := p.Quarantined("campus-sw-7", noon.Add(-time.Hour)); !ok {
		t.Fatal("a load-time failure holds whatever time is asked")
	}
	if q := p.Quarantines(lastLapse); len(q) != 0 {
		t.Fatalf("once every grant has lapsed nothing is quarantined: %+v", q)
	}

	p, got = quarantinedAt(t, `
scopes: [{name: all_devices, match: {}}, {name: dc, match: {site: dc1}}]
roles:
  - {name: adm, privilege: admin, permit: ["**"]}
  - {name: adm2, privilege: admin, permit: [show **]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [adm], max_privilege: admin, expires: 2026-10-01}
  - {subject: s, scope: dc, roles: [adm2], max_privilege: readonly}`, env())
	if len(got) != 1 || len(got["leaf-01"]) != 1 ||
		!strings.HasPrefix(got["leaf-01"][0], "will be quarantined from 2026-10-01T00:00:00.000Z, when grant all_devices [adm] expires: ") ||
		!strings.Contains(got["leaf-01"][0], "above its grants' max_privilege readonly") {
		t.Fatalf("the lower ceiling left behind: %q", got)
	}
	if _, ok := p.Quarantined("leaf-01", noon); ok {
		t.Fatal("not before the expiry")
	}
	if cause, ok := p.Quarantined("leaf-01", after); !ok || !strings.Contains(cause, "above its grants' max_privilege") {
		t.Fatalf("after the expiry: %q %v", cause, ok)
	}
}

// A grant already expired when the policy loads reaches no mint, so it
// quarantines nothing.
func TestAnExpiredGrantQuarantinesNothing(t *testing.T) {
	p, got := quarantinedAt(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: op, privilege: operator, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [op], expires: 2026-09-01}]`, env())
	if len(got) != 0 {
		t.Fatalf("quarantined %q", got)
	}
	if _, err := p.Resolve("user:s@example.com", deviceNamed(t, "leaf-01"), noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("Resolve = %v", err)
	}
}

// priv-lvl 0 is a ceiling, not its absence. The token reads a zero
// max_privilege as none, so a ceiling numbered 0 cannot be minted and
// quarantines the device rather than being lifted.
func TestACeilingOfZeroIsACeiling(t *testing.T) {
	e := env()
	eos, _ := platform.DialectFor("arista_eos")
	eos.Levels = map[string][]string{"readonly": {"priv-lvl=0"}, "admin": {"priv-lvl=15"}}
	e.Dialects = map[string]platform.Dialect{"arista_eos": eos}
	p, got := quarantinedAt(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], max_privilege: readonly}]`, e)
	if len(got) != 2 || !strings.Contains(got["leaf-01"][0], "max_privilege readonly is priv-lvl 0 on arista_eos") {
		t.Fatalf("quarantined %q", got)
	}
	r, err := p.Resolve("user:s@example.com", deviceNamed(t, "nx-01"), noon)
	if err != nil || !r.HasCeiling || r.MaxPrivilege != 1 {
		t.Fatalf("elsewhere the ceiling stands: %+v %v", r, err)
	}
}

// A shuffled policy file compiles to the same blob: rules in Encode's
// canonical order, as the pipe list already is, so the blob Resolve hands
// explain and a test is the one the hash names, and moving a line mints no new
// blob and churns no refresh. The bundle names the file's bytes and so differs; it is
// held fixed to compare the rest.
func TestAShuffledFileIsTheSameBlob(t *testing.T) {
	a := mustParse(t, `
scopes: [{name: all_devices, match: {}}, {name: dc, match: {site: dc1}, on_missing: exclude}]
roles:
  - {name: ops, permit: [show **, "terminal length *", ping *], deny: [reload **, write erase **]}
  - {name: net, permit: [configure **, show running-config], deny: [show tech-support **]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [ops]}
  - {subject: s, scope: dc, roles: [net, ops]}
`)
	b := mustParse(t, `
grants:
  - {subject: s, scope: dc, roles: [ops, net]}
  - {subject: s, scope: all_devices, roles: [ops]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
roles:
  - {name: net, deny: [show tech-support **], permit: [show running-config, configure **]}
  - {name: ops, deny: [write erase **, reload **], permit: [ping *, "terminal length *", show **]}
scopes: [{name: dc, match: {site: dc1}, on_missing: exclude}, {name: all_devices, match: {}}]
`)
	ra, err := a.Resolve("user:s@example.com", deviceNamed(t, "leaf-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.Resolve("user:s@example.com", deviceNamed(t, "leaf-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ra.Blob.Rules, rb.Blob.Rules) {
		t.Fatalf("a shuffled file compiled to other rules:\n%+v\n%+v", ra.Blob.Rules, rb.Blob.Rules)
	}
	ra.Blob.Bundle, rb.Blob.Bundle = "sha256:fixed", "sha256:fixed"
	ba, ha, err1 := engine.Encode(ra.Blob)
	bb, hb, err2 := engine.Encode(rb.Blob)
	if err1 != nil || err2 != nil || ha != hb || string(ba) != string(bb) {
		t.Fatalf("a shuffled file compiled to another blob:\n%s\n%s", ba, bb)
	}
}

// A ceiling that numbers 0 wherever it numbers at all can pass no device's
// check, so it is the policy's own error, like a class no platform defines.
func TestACeilingNumberedOnlyZeroIsRefused(t *testing.T) {
	e := env()
	eos, _ := platform.DialectFor("arista_eos")
	eos.Levels = map[string][]string{"readonly": {"priv-lvl=1"}, "admin": {"priv-lvl=15"}, "floor": {"priv-lvl=0"}}
	e.Dialects = map[string]platform.Dialect{"arista_eos": eos}
	if _, err := Parse([]byte(`
privilege_levels: [{name: floor}, {name: readonly}, {name: operator}, {name: admin}]
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: floor, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], max_privilege: floor}]`), e); err == nil ||
		!strings.Contains(err.Error(), "no priv-lvl number on any platform") {
		t.Fatalf("Parse = %v", err)
	}
}

// Junos sends no per-command authorization (L18; spec §13 decision 21), so its
// blob is session-only and widens no command rule; EOS and an unknown
// platform's generic adapter, which the engine still evaluates commands for,
// are not.
func TestOnlyAMeasuredSessionOnlyPlatformIsSessionOnly(t *testing.T) {
	p := mustParse(t, good)
	generic := deviceNamed(t, "leaf-01")
	generic.Name, generic.Platform = "ntp-01", "meinberg_lantime"
	for device, want := range map[string]bool{"srx-fw-04": true, "leaf-01": false, "ntp-01": false} {
		d := generic
		if device != "ntp-01" {
			d = deviceNamed(t, device)
		}
		r, err := p.Resolve("user:alice@example.com", d, noon)
		if err != nil || r.Blob.Normalize.SessionOnly != want {
			t.Errorf("%s: session_only %v, err %v; want %v", device, r.Blob.Normalize.SessionOnly, err, want)
		}
	}
}

// A ceiling caps the level, not only its number: an admin role capped at
// operator is quarantined on arista_eos and cisco_nxos, where both number 15,
// as on every other platform (review I2; spec §7).
func TestARoleAboveItsCeilingsLevelIsQuarantinedWhereverItNumbers(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: adm, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [adm], max_privilege: operator}]`)
	for _, d := range inventory() {
		cause, q := p.Quarantined(d.Name, noon)
		if !q {
			t.Errorf("%s (%s) is not quarantined", d.Name, d.Platform)
		}
		if d.Platform == "arista_eos" && !strings.Contains(cause, "land it at admin, above its grants' max_privilege operator") {
			t.Errorf("%s: cause %q", d.Name, cause)
		}
	}
}
