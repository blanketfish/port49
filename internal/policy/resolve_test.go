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
		r.Level != "readonly" || r.MaxPrivilege != 0 || strings.Join(r.Roles, ",") != "no_disruptive,read_only" {
		t.Fatalf("resolution: %+v", r)
	}
	if len(r.Grants) != 1 || r.Grants[0].Scope != "all_devices" || r.Grants[0].Expires != "2026-12-01T00:00:00.000Z" {
		t.Fatalf("the mint record's grants: %+v", r.Grants)
	}
	b := r.Blob
	if b.Platform != "arista_eos" || b.Bundle != p.Bundle || b.Privilege != "readonly" ||
		!reflect.DeepEqual(b.Attributes, []string{"priv-lvl=1"}) || !reflect.DeepEqual(b.Pipe, sortedCopy(DefaultPipe)) ||
		b.Normalize.PipeToken != "|" || b.Normalize.PipeAuthorized || b.Normalize.ExpandsAbbreviations {
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
	if r.MaxPrivilege != 15 || r.Level != "admin" || len(r.Blob.Attributes) != 0 ||
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
		{"a level the platform cannot render", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: op, privilege: operator, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [op]}]`, "level operator has no rendering on arista_eos",
			[]string{"campus-sw-7", "leaf-01"}},
		{"a landing level above the ceiling", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: adm, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [adm], max_privilege: readonly}]`, "above its grants' max_privilege", all},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := mustParse(t, tt.yaml)
			var got []string
			for _, q := range p.Quarantined() {
				got = append(got, q.Device)
				if len(q.Causes) != 1 || !strings.Contains(q.Causes[0], tt.want) ||
					!strings.Contains(q.Causes[0], `subject "s"`) || !strings.Contains(q.Causes[0], q.Platform) {
					t.Errorf("%s: causes %q, want one naming subject s, %s and %q", q.Device, q.Causes, q.Platform, tt.want)
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
grants: [{subject: s, scope: eos, roles: [tech]}]`); len(p.Quarantined()) != 0 {
		t.Fatalf("quarantined %+v", p.Quarantined())
	}
	// A ceiling no platform can number is the policy's own error: no inventory
	// could make it load, so it is refused rather than quarantining the fleet.
	if _, err := Parse([]byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], max_privilege: operator}]`), env()); err == nil ||
		!strings.Contains(err.Error(), "no priv-lvl number on any platform") {
		t.Fatalf("Parse = %v", err)
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
	if p, err := Parse([]byte(body), e); err != nil || len(p.Quarantined()) != 0 {
		t.Fatalf("every shipped platform carries the principal: %v", err)
	}
	e.EnableUsernames = map[string]string{"arista_eos": platform.EnableEnab}
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	q := p.Quarantined()
	if len(q) != 2 || q[0].Device != "campus-sw-7" || q[1].Device != "leaf-01" ||
		!strings.Contains(q[0].Causes[0], "enable: auto reaches this device") {
		t.Fatalf("quarantined %+v", q)
	}
}
