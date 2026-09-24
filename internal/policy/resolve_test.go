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
		!reflect.DeepEqual(b.Attributes, []string{"priv-lvl=1", "roles=network-operator"}) || !reflect.DeepEqual(b.Pipe, sortedCopy(DefaultPipe)) ||
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
// ceiling for the token (plan 3's table), as one that renders a role and no
// priv-lvl numbers it from its own; a group subject resolves by name only,
// since matching a person to a group is the directory's (plan 7).
func TestAPlatformThatRendersNothingStillHasACeiling(t *testing.T) {
	p := mustParse(t, good)
	if _, err := p.Resolve("CN=netops-admins,OU=Groups,DC=example,DC=com", deviceNamed(t, "srx-fw-04"), noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("a group is never a principal: %v", err)
	}
	r, err := p.ResolveSubject("netops_admins", deviceNamed(t, "srx-fw-04"), noon)
	if err != nil {
		t.Fatal(err)
	}
	if r.MaxPrivilege != 15 || !r.HasCeiling || r.Level != "admin" || len(r.Blob.Attributes) != 0 ||
		!reflect.DeepEqual(r.Blob.Pipe, []string{"**"}) {
		t.Fatalf("netops_admins on Junos: %+v", r)
	}
	r, err = p.ResolveSubject("netops_admins", deviceNamed(t, "nx-01"), noon)
	if err != nil || r.MaxPrivilege != 15 || !r.HasCeiling ||
		!reflect.DeepEqual(r.Blob.Attributes, []string{"shell:roles*network-admin"}) {
		t.Fatalf("netops_admins on NX-OS: %+v %v", r, err)
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
  - {name: homes, attributes: {arista_eos: ["home-directory*/home/{username}"], all: ["idletime*10"]}}
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
	// Order is first appearance — platform, then roles by name, then grants,
	// a role's `all` list before its platform's — with an override taking the
	// place of what it shadows. home-directory is keyed to arista_eos: IOS-XE
	// holds it bearing privilege (L22-cisco_iosxe.md), so under `all` its
	// placeholder is refused.
	want := []string{"priv-lvl=2", "roles=network-operator", "idletime*30", "home-directory*/home/{username}", "timeout*60"}
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
grants: [{subject: s, scope: all_devices, roles: [op]}]`, "level unmapped has no rendering on",
			[]string{"campus-sw-7", "leaf-01", "nx-01", "xe-01"}},
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
	// Validate refuses `enab` in any adapter a file writes, so only an
	// environment's own table can stand one up.
	eos, _ := platform.DialectFor("arista_eos")
	eos.EnableUsername = platform.EnableEnab
	e.Dialects = map[string]platform.Dialect{"arista_eos": eos}
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
	if len(got) != 4 || len(leaf) != 1 || len(campus) != 1 || len(got["nx-01"]) != 1 || len(got["xe-01"]) != 1 ||
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

// IOS-XE refuses the whole session for an attribute it does not take, under
// either flag, and a run of refusals stops it answering SSH, break-glass
// included (tests/lab/results/L18-cisco_iosxe.md, variant 5's
// p49-nonsense*1). A composition whose reply
// would carry one quarantines the device, naming the attribute and where it
// came from; one keyed to other platforms leaves IOS-XE alone.
func TestAnAttributeIOSXEDoesNotTakeQuarantinesIt(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {KEY: ["p49-nonsense*1"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`
	p := mustParse(t, strings.Replace(body, "KEY", "all", 1))
	q := p.Quarantines(noon)
	if len(q) != 1 || q[0].Device != "xe-01" || !strings.Contains(causesOf(q[0])[0],
		"its session reply sends p49-nonsense*1 (role ro), and cisco_iosxe takes no attribute but priv-lvl, idletime, timeout") {
		t.Fatalf("quarantines: %+v", q)
	}
	for _, key := range []string{"arista_eos", "cisco_nxos"} {
		if q := mustParse(t, strings.Replace(body, "KEY", key, 1)).Quarantines(noon); len(q) != 0 {
			t.Errorf("%s: %+v", key, q)
		}
	}
	// priv-lvl is what it takes, from the level or from a role, and idletime
	// and timeout, which it left a session unchanged for
	// (tests/lab/results/L22-cisco_iosxe.md, "Inert candidates").
	for _, attr := range []string{"priv-lvl=1", "idletime*30", "timeout*480"} {
		ok := strings.Replace(strings.Replace(body, "KEY", "cisco_iosxe", 1), "p49-nonsense*1", attr, 1)
		if q := mustParse(t, ok).Quarantines(noon); len(q) != 0 {
			t.Fatalf("%s: %+v", attr, q)
		}
	}
}

// home-directory is no exception on IOS-XE: beside admin's reply the C8000V
// refused the session for it, `% Authorization failed.`
// (tests/lab/results/L22-cisco_iosxe.md). A policy that sends it there
// quarantines the device, so no login is locked out by it, and a placeholder
// in it is refused at load, since nothing is inert on IOS-XE.
func TestHomeDirectoryIsRefusedOnIOSXE(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {KEY: ["VALUE"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`
	parse := func(key, value string) (*Policy, error) {
		return Parse([]byte(strings.NewReplacer("KEY", key, "VALUE", value).Replace(body)), env())
	}
	p, err := parse("cisco_iosxe", "home-directory*/home/port49")
	if err != nil {
		t.Fatal(err)
	}
	q := p.Quarantines(noon)
	if len(q) != 1 || q[0].Device != "xe-01" || !strings.Contains(causesOf(q[0])[0],
		"its session reply sends home-directory*/home/port49 (role ro), and cisco_iosxe takes no attribute but priv-lvl, idletime, timeout") {
		t.Fatalf("quarantines: %+v", q)
	}
	for _, key := range []string{"cisco_iosxe", "all"} {
		if _, err := parse(key, "home-directory*/home/{username}"); err == nil || !strings.Contains(err.Error(),
			"home-directory is not listed inert on cisco_iosxe, so it takes no placeholder") {
			t.Errorf("%s: %v", key, err)
		}
	}
}

// idletime and timeout are numbers, and L22 measured exactly `idletime*30`
// and `timeout*480` (tests/lab/results/L22-*.md, "Inert candidates"). A
// placeholder in either is refused at load on every platform, inert or not:
// what a mint fills in is an identity, never a number the device takes. A
// literal that is not a plain decimal 0 to 65535 quarantines the device on
// every platform, and on IOS-XE, whose refusals lock out SSH, break-glass
// included (L18-cisco_iosxe.md), so does the unmeasured mandatory `=`.
func TestIdletimeAndTimeoutAreNumbers(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {KEY: [ATTR]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`
	parse := func(key, attr string) (*Policy, error) {
		return Parse([]byte(strings.NewReplacer("KEY", key, "ATTR", `"`+attr+`"`).Replace(body)), env())
	}
	for _, attr := range []string{"idletime*{principal}", "timeout={privilege}", "idletime*{username}"} {
		for _, key := range []string{"arista_eos", "cisco_nxos", "cisco_iosxe", "all"} {
			if _, err := parse(key, attr); err == nil || !strings.Contains(err.Error(),
				"is a number and takes no placeholder") {
				t.Errorf("%s under %s: %v", attr, key, err)
			}
		}
	}
	for _, attr := range []string{"idletime*forever", "idletime=-1", "idletime*030", "timeout*99999", "timeout*",
		"timeout*+5"} {
		p, err := parse("all", attr)
		if err != nil {
			t.Fatalf("%s: %v", attr, err)
		}
		if q := p.Quarantines(noon); len(q) != len(inventory()) {
			t.Errorf("%s: %d of %d devices quarantined: %+v", attr, len(q), len(inventory()), q)
		} else if !strings.Contains(causesOf(q[0])[0], "sends "+attr+" (role ro), which is not a plain decimal "+
			"0 to 65535") {
			t.Errorf("%s: %v", attr, causesOf(q[0]))
		}
	}
	// The mandatory form is unmeasured on IOS-XE, and quarantines it alone.
	p, err := parse("all", "idletime=30")
	if err != nil {
		t.Fatal(err)
	}
	if q := p.Quarantines(noon); len(q) != 1 || q[0].Device != "xe-01" || !strings.Contains(causesOf(q[0])[0],
		"sends idletime=30 (role ro), and cisco_iosxe was measured taking idletime only as idletime*") {
		t.Fatalf("quarantines: %+v", q)
	}
	// What L22 measured passes everywhere.
	for _, attr := range []string{"idletime*30", "timeout*480"} {
		if p, err := parse("all", attr); err != nil {
			t.Errorf("%s: %v", attr, err)
		} else if q := p.Quarantines(noon); len(q) != 0 {
			t.Errorf("%s: %+v", attr, q)
		}
	}
}

// priv-lvl's values are closed, 0 to 15, and IOS-XE refused the session for
// priv-lvl=99 rather than clamp or ignore it (L18-cisco_iosxe.md, variant 7).
// A role or grant that layers any other value fails the joint check on every
// device it reaches, whatever the platform, and on IOS-XE a level the adapter
// does not render fails it too.
func TestAPrivLvlThatIsNotALevelQuarantines(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {KEY: [ATTR]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`
	parse := func(key, attr string) []Quarantine {
		return mustParse(t, strings.NewReplacer("KEY", key, "ATTR", `"`+attr+`"`).Replace(body)).Quarantines(noon)
	}
	for _, attr := range []string{"priv-lvl=99", "priv-lvl=16", "priv-lvl=abc", "priv-lvl=", "priv-lvl*99", "priv-lvl=-1"} {
		q := parse("all", attr)
		if len(q) != len(inventory()) {
			t.Errorf("%s: %d of %d devices quarantined: %+v", attr, len(q), len(inventory()), q)
		}
		for _, d := range q {
			if !strings.Contains(causesOf(d)[0], "sends "+attr+" (role ro), which is not a privilege level") {
				t.Errorf("%s on %s: %v", attr, d.Device, causesOf(d))
			}
		}
	}
	// A level IOS-XE's adapter does not render: the device's own ladder there
	// is unmeasured, so the reply is not sent.
	q := parse("cisco_iosxe", "priv-lvl=5")
	if len(q) != 1 || q[0].Device != "xe-01" || !strings.Contains(causesOf(q[0])[0],
		"sends priv-lvl=5 (role ro), and cisco_iosxe's adapter renders priv-lvl 1, 7 and 15 only") {
		t.Fatalf("quarantines: %+v", q)
	}
	// Elsewhere 5 is a level, and the rendered ones pass on IOS-XE.
	for _, tt := range []struct{ key, attr string }{{"arista_eos", "priv-lvl=5"}, {"cisco_iosxe", "priv-lvl=7"},
		{"cisco_iosxe", "priv-lvl*15"}} {
		if q := parse(tt.key, tt.attr); len(q) != 0 {
			t.Errorf("%s %s: %+v", tt.key, tt.attr, q)
		}
	}
}

// The blob carries the merged adapter's accepted_attributes, so the daemon
// refuses what the device would; a platform that takes any name carries none.
func TestTheBlobCarriesWhatItsPlatformTakes(t *testing.T) {
	p := mustParse(t, good)
	r, err := p.ResolveSubject("netops_admins", deviceNamed(t, "xe-01"), noon)
	if err != nil || !reflect.DeepEqual(r.Blob.AcceptedAttributes, []string{"idletime", "priv-lvl", "timeout"}) {
		t.Fatalf("IOS-XE: %+v %v", r.Blob.AcceptedAttributes, err)
	}
	for _, name := range []string{"nx-01", "srx-fw-04"} {
		if r, err := p.ResolveSubject("netops_admins", deviceNamed(t, name), noon); err != nil || r.Blob.AcceptedAttributes != nil {
			t.Fatalf("%s: %+v %v", name, r.Blob.AcceptedAttributes, err)
		}
	}
}

// A grant's attribute is layered like a role's, and the check names it.
func TestAGrantsAttributeIOSXEDoesNotTakeQuarantinesIt(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], attributes: {cisco_iosxe: ["p49-nonsense*1"]}}]`)
	q := p.Quarantines(noon)
	if len(q) != 1 || q[0].Device != "xe-01" || !strings.Contains(causesOf(q[0])[0],
		"sends p49-nonsense*1 (grant all_devices [ro])") {
		t.Fatalf("quarantines: %+v", q)
	}
}

// The ceiling bounds every attribute of the reply that bears privilege, not
// only priv-lvl (spec §7): on NX-OS and Junos the role is the privilege, and
// on EOS the role is what the fallback to local reads. A role or grant that
// sends one above what the ceiling's level renders, or one no role_order
// ranks, which counts as the highest, quarantines the device, judged as the
// diff gate judges a raised reply (final review I1).
func TestARoleAttributeAboveTheCeilingQuarantines(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **], attributes: {KEY: ["ATTR"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r], max_privilege: readonly}]`
	for _, tt := range []struct {
		key, attr string
		devices   []string
	}{
		{"cisco_nxos", "shell:roles*network-admin", []string{"nx-01"}},
		{"arista_eos", "roles=network-admin", []string{"campus-sw-7", "leaf-01"}},
		{"juniper_junos", "local-user-name*super-user", []string{"srx-fw-04", "srx-fw-05", "srx-fw-22", "srx-lab-01"}},
		// Unranked, so above every role.
		{"arista_eos", "roles=p49-custom", []string{"campus-sw-7", "leaf-01"}},
	} {
		p := mustParse(t, strings.NewReplacer("KEY", tt.key, "ATTR", tt.attr).Replace(body))
		var got []string
		for _, q := range p.Quarantines(noon) {
			got = append(got, q.Device)
			if c := causesOf(q)[0]; !strings.Contains(c, "its session reply sends "+tt.attr+" (role r)") ||
				!strings.Contains(c, "max_privilege readonly") {
				t.Errorf("%s: cause %q", q.Device, c)
			}
		}
		if strings.Join(got, ",") != strings.Join(tt.devices, ",") {
			t.Errorf("%s: quarantined %v, want %v", tt.attr, got, tt.devices)
		}
	}
	// A grant's attribute is judged the same.
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r], max_privilege: readonly, attributes: {cisco_nxos: ["shell:roles*network-admin"]}}]`)
	if q := p.Quarantines(noon); len(q) != 1 || q[0].Device != "nx-01" {
		t.Errorf("a grant's role: %+v", q)
	}
	// idletime and timeout are accepted on IOS-XE and measured carrying no
	// privilege (L22-cisco_iosxe.md): gated in the diff, but no raise above a
	// ceiling (owner's ruling on the fix wave).
	for _, ceiling := range []string{"operator", "admin"} {
		p := mustParse(t, strings.NewReplacer("KEY", "cisco_iosxe", "ATTR", "idletime*30", "max_privilege: readonly",
			"max_privilege: "+ceiling).Replace(body))
		// Junos numbers no operator (plan 3's table), which quarantines it on
		// its own; IOS-XE is what is asked here.
		if cause, q := p.Quarantined("xe-01", noon); q {
			t.Errorf("IOS-XE idletime under %s: %s", ceiling, cause)
		}
	}
	// Nothing sits above the top level: under admin no attribute quarantines,
	// Junos's local-user-name and an unranked role included.
	for _, tt := range []struct{ key, attr string }{
		{"juniper_junos", "local-user-name*super-user"}, {"arista_eos", "roles=p49-custom"}, {"all", "idletime*30"},
	} {
		p := mustParse(t, strings.NewReplacer("KEY", tt.key, "ATTR", tt.attr, "max_privilege: readonly",
			"max_privilege: admin").Replace(body))
		if q := p.Quarantines(noon); len(q) != 0 {
			t.Errorf("%s under admin: %+v", tt.attr, q)
		}
	}
	// Unmeasured on Junos, idletime counts as the highest under any lower
	// ceiling.
	p = mustParse(t, strings.NewReplacer("KEY", "juniper_junos", "ATTR", "idletime*30").Replace(body))
	if q := p.Quarantines(noon); len(q) != 4 {
		t.Errorf("Junos idletime under readonly: %+v", q)
	}
	// What the ceiling's level renders, or provably less, is within it.
	for _, tt := range []struct{ key, attr, ceiling string }{
		{"arista_eos", "roles=network-operator", "readonly"},
		{"cisco_nxos", "shell:roles*network-admin", "admin"},
		{"cisco_nxos", "shell:roles*network-operator", "admin"},
	} {
		body := strings.NewReplacer("KEY", tt.key, "ATTR", tt.attr, "max_privilege: readonly",
			"max_privilege: "+tt.ceiling).Replace(body)
		if q := mustParse(t, body).Quarantines(noon); len(q) != 0 {
			t.Errorf("%s under %s: %+v", tt.attr, tt.ceiling, q)
		}
	}
}

// On a closed platform the reply's priv-lvl must be one a level's rendering
// sends: a ceiling_levels number stands for a level only in the token, and
// the device was never measured taking it (task 5 review, parked).
func TestAClosedPlatformTakesOnlyARenderedPrivLvl(t *testing.T) {
	p, err := Parse([]byte(`
platforms:
  acme_os:
    supports: [session]
    accepted_attributes: [priv-lvl, x-role]
    privilege_attributes: [priv-lvl, x-role]
    role_order: {x-role: [a]}
    privilege: {readonly: ["x-role=a"], operator: ["x-role=a"], admin: ["priv-lvl=15", "x-role=a"]}
    ceiling_levels: {readonly: 3, operator: 5}
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **], attributes: {acme_os: ["priv-lvl=5"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]`), withDevice("acme-01", "acme_os"))
	if err != nil {
		t.Fatal(err)
	}
	if cause, q := p.Quarantined("acme-01", noon); !q || !strings.Contains(cause, "acme_os's adapter renders priv-lvl 15 only") {
		t.Fatalf("%v %q", q, cause)
	}
}

// A platform whose levels render a role and no priv-lvl, NX-OS, is never sent
// one: beside a role the device ignores it, and alone it picks a role by a
// per-release table nobody named, 15 to network-admin and 6 to vdc-operator
// (tests/lab/results/L16-cisco_nxos.md, findings 1 and 6). A reply carrying
// one quarantines the device (task 4 review M4).
func TestAPrivLvlToAPlatformThatRendersARoleQuarantines(t *testing.T) {
	for _, key := range []string{"cisco_nxos", "all"} {
		p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **], attributes: {`+key+`: ["priv-lvl=1"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]`)
		var got []string
		for _, q := range p.Quarantines(noon) {
			got = append(got, q.Device)
			if !strings.Contains(causesOf(q)[0], "its session reply sends priv-lvl=1 (role r), and cisco_nxos's "+
				"levels render a role and no priv-lvl") {
				t.Errorf("%s: %q", q.Device, causesOf(q))
			}
		}
		if strings.Join(got, ",") != "nx-01" {
			t.Errorf("%s: quarantined %v", key, got)
		}
	}
}

// An attribute a level renders is the level on that platform, whatever
// accepted_attributes says: listed there it is still bounded by the ceiling,
// and the fallback exposure reads it (re-review RR-I1).
func TestARenderedAttributeIsAlwaysBoundedByTheCeiling(t *testing.T) {
	const block = `
platforms:
  f5_bigip:
    supports: [session]
    accepted_attributes: [F5-LTM-User-Role, priv-lvl]
    role_order: {F5-LTM-User-Role: ["700", "0"]}
    privilege: {readonly: ["F5-LTM-User-Role*700"], operator: ["F5-LTM-User-Role*700"], admin: ["F5-LTM-User-Role*0"]}
    ceiling_levels: {readonly: 1, operator: 7, admin: 15}
    fallback: {admin: "every partition, configuration included"}
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **], attributes: {f5_bigip: ["F5-LTM-User-Role*0"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]GRANT}]`
	parse := func(grant string) *Policy {
		t.Helper()
		p, err := Parse([]byte(strings.Replace(block, "GRANT", grant, 1)), withDevice("bigip-01", "f5_bigip"))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if cause, q := parse(", max_privilege: readonly").Quarantined("bigip-01", noon); !q ||
		!strings.Contains(cause, "its session reply sends F5-LTM-User-Role*0 (role r)") {
		t.Errorf("quarantined %v: %q", q, cause)
	}
	var got []string
	for _, f := range findings(parse(""), FindingFallbackExposure) {
		if strings.Contains(f, "on f5_bigip") {
			got = append(got, f)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "reaches admin") {
		t.Errorf("exposure: %q", got)
	}
}

// An attribute name is compared with a rendered or privilege-bearing name
// without regard to case, the way that bounds more: a role sending
// `f5-ltm-user-role*0` where a level renders `F5-LTM-User-Role` is the level,
// whatever case accepted_attributes spells it in (re-review 2, RR2-M1).
func TestARenderedNameIsMatchedInAnyCase(t *testing.T) {
	d := platform.Dialect{Levels: map[string][]string{"admin": {"F5-LTM-User-Role*0"}},
		AcceptedAttributes: []string{"F5-LTM-User-Role", "f5-ltm-user-role"}, InertAttributes: []string{"x-label"}}
	for _, name := range []string{"f5-ltm-user-role", "F5-LTM-USER-ROLE", "PRIV-LVL", "Shell:Roles"} {
		if !raisesCeiling(name, d) {
			t.Errorf("%s does not raise the ceiling", name)
		}
	}
	// The block the probe needs is refused at load: two spellings of one name.
	_, err := Parse([]byte(`
platforms:
  f5_bigip:
    supports: [session]
    accepted_attributes: [F5-LTM-User-Role, f5-ltm-user-role, priv-lvl]
    role_order: {F5-LTM-User-Role: ["700", "0"]}
    privilege: {readonly: ["F5-LTM-User-Role*700"], operator: ["F5-LTM-User-Role*700"], admin: ["F5-LTM-User-Role*0"]}
    ceiling_levels: {readonly: 1, operator: 7, admin: 15}
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **], attributes: {f5_bigip: ["f5-ltm-user-role*0"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r], max_privilege: readonly}]`), withDevice("bigip-01", "f5_bigip"))
	if err == nil || !strings.Contains(err.Error(), "platforms.f5_bigip.accepted_attributes") ||
		!strings.Contains(err.Error(), "F5-LTM-User-Role") || !strings.Contains(err.Error(), "f5-ltm-user-role") {
		t.Errorf("%v", err)
	}
}
