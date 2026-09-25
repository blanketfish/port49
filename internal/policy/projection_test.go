package policy

import (
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/platform"
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
