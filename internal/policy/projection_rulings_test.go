package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/platform"
)

// myJunos is plan 5b pre-flight R-I1's probe: a platform no shipped set
// projects, declaring a projection whose carve-out nobody measured, under a
// readonly role that denies what the carve-out claims.
const myJunos = `platforms:
  my_junos:
    supports: [session]
    command_projection: junos_regex
    bit_delivery: user_permissions
    privilege_attributes: [local-user-name, user-permissions, allow-commands, deny-commands, allow-configuration,
      deny-configuration, allow-commands-regexps, deny-commands-regexps, allow-configuration-regexps,
      deny-configuration-regexps]
    bits: {view: ["show **"], trace: ["monitor **", "show log **"]}
    carve_outs: {trace: ["show log **"]}
    privilege: {readonly: [view]}
` + scopeOK + `roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show log **"]}
` + subjOK + grantOK

// Only a platform the pinned set projects is projected: nothing measured sets
// a floor under a bit's reach anywhere else, so an understated reach or an
// unmeasured carve-out would send a deny as nothing (spec §8,
// command_projection; pre-flight R-I1; Task 6 review I3). A block, replace:
// true included, and a new platform are refused for any projection key.
func TestOnlyThePinnedSetProjects(t *testing.T) {
	withoutProjection := strings.Replace(myJunos, "    command_projection: junos_regex\n", "", 1)
	replaceOn100 := strings.Replace(strings.Replace(myJunos, "my_junos:\n", "juniper_junos:\n    replace: true\n", 1),
		`    carve_outs: {trace: ["show log **"]}`+"\n", "", 1)
	for _, c := range []struct {
		name, body, want string
		env              Env
	}{
		{"a new platform, on the projected set", "platform_set: " + projectedSet + "\n" + myJunos,
			"platforms.my_junos.command_projection: platform set 9.0.0 does not project my_junos",
			projectedEnv(platform.BitDeliveryUserPermissions)},
		{"a new platform, unpinned", myJunos, "platforms.my_junos.command_projection: platform set 1.0.0 does not " +
			"project my_junos", env()},
		{"a new platform with bits and no projection", "platform_set: " + projectedSet + "\n" + withoutProjection,
			"platforms.my_junos.bits: platform set 9.0.0 does not project my_junos",
			projectedEnv(platform.BitDeliveryUserPermissions)},
		{"a new platform with only an empty carve_outs", strings.Replace(myJunos, `carve_outs: {trace: ["show log **"]}`,
			"carve_outs: {}", 1), "platforms.my_junos.command_projection: platform set 1.0.0 does not project", env()},
		{"replace: true over 1.0.0's juniper_junos", replaceOn100,
			"platforms.juniper_junos.command_projection: platform set 1.0.0 does not project juniper_junos", env()},
		{"a new platform with a root template", "platform_set: " + projectedSet + "\n" +
			strings.Replace(strings.Replace(myJunos, "user_permissions", "local_user_name", 1),
				"    privilege:", "    local_user_names: {readonly: root}\n    privilege:", 1),
			"does not project my_junos", projectedEnv(platform.BitDeliveryLocalUserName)},
	} {
		_, err := Parse([]byte(c.body), c.env)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// A template user is p49-<name>, in the set and in a block alike: `root` or
// `remote` would put the session in a class the device already has, whatever
// bits the projection proved (spec §8, local_user_names; Task 6 review I2).
func TestABlockTemplateIsP49Namespaced(t *testing.T) {
	for _, c := range []struct{ block, want string }{
		{"local_user_names: {admin: root}", "local_user_names.admin: root is not a p49- template"},
		{"local_user_names: {readonly: remote}", "local_user_names.readonly: remote is the device's own fallback"},
		{"local_user_names: {readonly: ROOT}", "local_user_names.readonly is not a login name"},
	} {
		_, err := Parse([]byte("platform_set: "+projectedSet+"\nplatforms:\n  juniper_junos:\n    "+c.block+"\n"+
			readonlyCarveOut), projectedEnv(platform.BitDeliveryLocalUserName))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.block, err, c.want)
		}
	}
}

// Under `all`, idletime and timeout are left off a projected Junos device,
// whose idle limit is its class's (decision 21), and policy test says so:
// spec §6's example loads on a projected set and is still sent elsewhere.
// Under the platform's own key they are refused as any unlisted name is.
func TestClassIdleUnderAllIsNotSent(t *testing.T) {
	body := scopeOK + `roles:
  - {name: r, privilege: readonly, permit: ["show **"], attributes: {all: ["idletime*30", "timeout*480"]}}
` + subjOK + grantOK + `tests:
  - {subject: s, device: srx-fw-04, level: readonly}
  - {subject: s, device: srx-fw-04, command: "show version", expect: permit}
  - {subject: s, device: leaf-01, level: readonly}
`
	p := parseProjected(t, platform.BitDeliveryUserPermissions, body)
	results := p.RunTests(noon)
	for _, r := range results[:2] {
		if !r.Pass || strings.Contains(strings.Join(r.Reply, " "), "idletime") ||
			!slices.ContainsFunc(r.Caveats, func(c string) bool {
				return strings.Contains(c, "idletime*30 (role r) is not sent to juniper_junos") &&
					strings.Contains(c, "login class's")
			}) {
			t.Errorf("srx-fw-04 %q: reply %q, caveats %q", r.Test.Command, r.Reply, r.Caveats)
		}
	}
	if r := results[2]; !slices.Contains(r.Reply, "idletime*30") || len(r.Caveats) != 0 {
		t.Errorf("leaf-01: reply %q, caveats %q", r.Reply, r.Caveats)
	}
	for _, a := range []string{"Idletime*30", "idletime2*30", "timeout1*480"} {
		_, err := Parse([]byte("platform_set: "+projectedSet+"\n"+strings.Replace(body, "idletime*30", a, 1)),
			projectedEnv(platform.BitDeliveryUserPermissions))
		if err == nil || !strings.Contains(err.Error(), "is not listed inert on juniper_junos") {
			t.Errorf("all %s: %v", a, err)
		}
	}
	_, err := Parse([]byte("platform_set: "+projectedSet+"\n"+strings.Replace(body, "all:", "juniper_junos:", 1)),
		projectedEnv(platform.BitDeliveryUserPermissions))
	if err == nil || !strings.Contains(err.Error(), "idletime is not listed inert on juniper_junos") {
		t.Errorf("juniper_junos idletime: %v", err)
	}
}

// Under `all`, the rule is read for each projected platform of the pinned
// set, whether or not a device in the inventory has it yet: the pin is
// refused in CI, not the reload at the first inventory sync that adds an SRX
// (Task 6 re-review N1, superseding review M3). The same attribute under the
// key of a platform that is not projected loads.
func TestAllIsReadForThePinnedSet(t *testing.T) {
	e := projectedEnv(platform.BitDeliveryUserPermissions)
	e.Devices = slices.DeleteFunc(slices.Clone(e.Devices), func(d admission.Device) bool {
		return d.Platform == "juniper_junos"
	})
	body := scopeOK + `roles:
  - {name: r, privilege: readonly, permit: ["show **"], attributes: {all: ["foo-bar=1"]}}
` + subjOK + grantOK
	_, err := Parse([]byte("platform_set: "+projectedSet+"\n"+body), e)
	if err == nil || !strings.Contains(err.Error(), "foo-bar is not listed inert on juniper_junos") {
		t.Errorf("no Junos device: %v", err)
	}
	if _, err := Parse([]byte("platform_set: "+projectedSet+"\n"+strings.Replace(body, "all:", "arista_eos:", 1)),
		e); err != nil {
		t.Errorf("under arista_eos: %v", err)
	}
}

// A block that adds to a bit's reach, or drops a carve-out, claims the bits
// reach more: it loads, and the diff gates it as a widening, an edit to the
// adapter that needs an acknowledge: entry. It never makes port49 trust the
// bit less, which keepsProjection refuses.
func TestAddingReachIsAGatedWidening(t *testing.T) {
	before := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
	for key, block := range map[string]string{
		"bits":       "    bits: {view: [\"show **\", \"monitor **\"]}\n",
		"carve_outs": "    carve_outs: {view-configuration: []}\n",
	} {
		after := parseProjected(t, platform.BitDeliveryUserPermissions, "platforms:\n  juniper_junos:\n"+block+
			readonlyCarveOut)
		d := Compare(before, after, noon)
		if len(d.Adapters) != 1 || d.Adapters[0].Platform != "juniper_junos" || d.Adapters[0].Field != key ||
			!d.Adapters[0].Gated || d.UnacknowledgedAdapters() != 1 {
			t.Errorf("%s: %+v", key, d.Adapters)
		}
	}
	// A block that starts from nothing keeps every bit the set declares: one
	// left out is reach port49 would stop counting, and the device would still
	// run it.
	_, err := Parse([]byte("platform_set: "+projectedSet+`
platforms:
  juniper_junos:
    replace: true
    supports: [session]
    command_projection: junos_regex
    bit_delivery: user_permissions
    privilege_attributes: [local-user-name, user-permissions, allow-commands, deny-commands, allow-configuration,
      deny-configuration, allow-commands-regexps, deny-commands-regexps, allow-configuration-regexps,
      deny-configuration-regexps]
    bits: {view: ["show **"], view-configuration: ["show configuration **"], clear: ["clear **"], all: ["**"]}
    privilege: {readonly: [view, view-configuration], operator: [view, view-configuration, clear], admin: [all]}
`+readonlyCarveOut), projectedEnv(platform.BitDeliveryUserPermissions))
	if err == nil || !strings.Contains(err.Error(), "bits.network: a rule platform set 9.0.0 measured") {
		t.Errorf("a bit left out: %v", err)
	}
}

// On a projected platform, a role or grant attribute the adapter does not
// list inert is refused: whether Junos reads `shell:allow-commands` or a name
// it does not document is unmeasured, and one it read would stand beside what
// the projection proved (pre-flight R-M3).
func TestAProjectedPlatformTakesOnlyInertAttributes(t *testing.T) {
	role := func(key, a string) string {
		return scopeOK + `roles:
  - {name: r, privilege: readonly, permit: ["show **"], attributes: {` + key + `: ["` + a + `"]}}
` + subjOK + grantOK
	}
	grant := func(key, a string) string {
		return scopeOK + roleOK + subjOK + `grants:
  - {subject: s, scope: all_devices, roles: [r], attributes: {` + key + `: ["` + a + `"]}}
`
	}
	for _, key := range []string{"juniper_junos", "all"} {
		for _, a := range []string{"shell:allow-commands=.*", "foo-bar=1", "Home-Directory=/var/tmp"} {
			for _, body := range []string{role(key, a), grant(key, a)} {
				_, err := Parse([]byte("platform_set: "+projectedSet+"\n"+body),
					projectedEnv(platform.BitDeliveryUserPermissions))
				if err == nil || !strings.Contains(err.Error(), "is not listed inert on juniper_junos") {
					t.Errorf("%s %s: %v", key, a, err)
				}
			}
		}
	}
	// An attribute the adapter lists inert loads there, and a platform that
	// projects nothing is unchanged.
	parseProjected(t, platform.BitDeliveryUserPermissions, role("juniper_junos", "home-directory=/var/tmp"))
	mustParse(t, role("juniper_junos", "foo-bar=1"))
}
