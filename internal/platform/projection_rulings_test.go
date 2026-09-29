package platform

import (
	"strings"
	"testing"
)

// A template user is port49's own, p49-<name>: `remote`, a system user such
// as root, or any name outside the namespace would put the session in a class
// the device already has, whatever bits the projection proved (spec §8,
// local_user_names; Task 6 review I2).
func TestATemplateIsP49Namespaced(t *testing.T) {
	for _, c := range []struct{ level, name, want string }{
		{"admin", "root", "local_user_names.admin: root is not a p49- template"},
		{"readonly", "remote", "local_user_names.readonly: remote is the device's own fallback template"},
		{"readonly", "readonly", "local_user_names.readonly: readonly is not a p49- template"},
		{"readonly", "p49-", "local_user_names.readonly: p49- is not a p49- template"},
		{"readonly", "P49-readonly", "local_user_names.readonly is not a login name"},
	} {
		d := with(junosProjected(BitDeliveryLocalUserName), func(d *Dialect) { d.LocalUserNames[c.level] = c.name })
		if err := Validate("juniper_junos", d); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// A carve-out of an undeclared bit says so, rather than naming the baseline
// (review M1); a projected adapter declares each level's ceiling bits (M2).
func TestValidateProjectionMessages(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*Dialect)
		want string
	}{
		{"a carve-out of an undeclared bit", func(d *Dialect) { d.CarveOuts["trace"] = []string{"monitor **"} },
			"carve_outs.trace: trace is not a bit under bits"},
		{"no privilege", func(d *Dialect) { d.CeilingBits = nil }, "privilege is required with command_projection"},
		{"an empty privilege", func(d *Dialect) { d.CeilingBits = map[string][]string{} },
			"privilege is required with command_projection"},
	} {
		d := with(junosProjected(BitDeliveryUserPermissions), c.edit)
		if err := Validate("juniper_junos", d); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
