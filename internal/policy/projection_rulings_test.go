package policy

import (
	"strings"
	"testing"

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

// Only a measured set subtracts reach: a block for a platform the pinned set
// does not project may not declare carve_outs at all, or a deny the carve-out
// claims would be sent as nothing (spec §8, carve_outs; pre-flight R-I1).
func TestACarveOutNoSetMeasuredIsRefused(t *testing.T) {
	for _, c := range []struct {
		name, body string
		env        Env
	}{
		{"a new platform, on the projected set", "platform_set: " + projectedSet + "\n" + myJunos,
			projectedEnv(platform.BitDeliveryUserPermissions)},
		{"a new platform, unpinned", myJunos, env()},
		{"a new platform with no carve-out's key but an empty one", "platform_set: " + projectedSet + "\n" +
			strings.Replace(myJunos, `carve_outs: {trace: ["show log **"]}`, "carve_outs: {}", 1),
			projectedEnv(platform.BitDeliveryUserPermissions)},
		{"a shipped platform the pinned set does not project", strings.Replace(myJunos, "my_junos", "juniper_junos",
			1), env()},
	} {
		_, err := Parse([]byte(c.body), c.env)
		if err == nil || !strings.Contains(err.Error(), "carve_outs: platform set") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// The same platform with no carve-out loads: its deny goes on the wire.
	parseProjected(t, platform.BitDeliveryUserPermissions,
		strings.Replace(myJunos, "    carve_outs: {trace: [\"show log **\"]}\n", "", 1))
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
