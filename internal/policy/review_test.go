package policy

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/platform"
)

// Access review renders the flat grant table for one subject, with scope size
// and expiry (spec §12).
func TestReviewListsEveryGrantRow(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	rows, err := p.Review("noc_tier1", noon)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Scope != "all_devices" || rows[0].Devices != 5 || rows[0].Expired ||
		rows[1].Scope != "dc_fabric" || rows[1].Devices != 1 || strings.Join(rows[1].Roles, ",") != "interface_tech" ||
		rows[1].Expires.Format("2006-01-02") != "2026-12-01" {
		t.Fatalf("rows: %+v", rows)
	}
	later, _ := p.Review("noc_tier1", time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC))
	if !later[1].Expired || later[0].Expired {
		t.Fatalf("expiry: %+v", later)
	}
	// srx_unpatched holds srx-fw-04, and srx-fw-22 because its version could
	// not be compared; srx-fw-05 is patched.
	if rows, _ := p.Review("security_ir", noon); len(rows) != 1 || rows[0].Devices != 2 {
		t.Fatalf("%+v", rows)
	}
	if _, err := p.Review("nobody", noon); err == nil {
		t.Fatal("an undeclared subject is an error")
	}
}

// ServedUsernames is every username a grant reaches the device with, by the
// subject that claims it; a group subject's members are the directory's, so
// the group is named instead (spec §5.6; plan 7).
func TestServedUsernamesAreTheOnesAGrantReaches(t *testing.T) {
	p := mustParse(t, good)
	users, groups, err := p.ServedUsernames("leaf-01", noon)
	if err != nil || !reflect.DeepEqual(users, map[string]string{"alice": "alice", "svc-config-backup": "svc_oxidized"}) ||
		!reflect.DeepEqual(groups, []string{"netops_admins"}) {
		t.Fatalf("%v %v %v", users, groups, err)
	}
	if _, _, err := p.ServedUsernames("nowhere", noon); err == nil {
		t.Fatal("a device not in the inventory")
	}
}

// ConfigDialect is the adapter devices check-config holds a device to: the
// policy's, with the set's device_config, local_accounts and config_checks as
// its floor. A block that rewrites a set line to end in `none` and empties
// the checks takes none of them away, nor does a variant based_on the
// platform; a platform no set ships has no floor.
func TestConfigDialectKeepsTheSetsLines(t *testing.T) {
	set, _ := platform.DialectFor("arista_eos")
	unsafe := "    device_config: [\"aaa authorization commands all default group port49 none\"]\n" +
		"    config_checks: []\n    local_accounts: []\n"
	for name, block := range map[string]string{
		"arista_eos": "platforms:\n  arista_eos:\n" + unsafe,
		"eos_lab":    "platforms:\n  eos_lab:\n    based_on: arista_eos\n" + unsafe,
	} {
		p := mustParse(t, block+good)
		d := p.ConfigDialect(name)
		for _, line := range set.DeviceConfig {
			if !slices.Contains(d.DeviceConfig, line) {
				t.Errorf("%q: %q is not required", block, line)
			}
		}
		if !reflect.DeepEqual(d.ConfigChecks, set.ConfigChecks) || !reflect.DeepEqual(d.LocalAccounts, set.LocalAccounts) {
			t.Errorf("%q: %+v %q", block, d.ConfigChecks, d.LocalAccounts)
		}
	}
	p := mustParse(t, "platforms:\n  acme_os:\n    supports: [session]\n    device_config: [\"aaa new-model\"]\n"+good)
	if d := p.ConfigDialect("acme_os"); !reflect.DeepEqual(d.DeviceConfig, []string{"aaa new-model"}) ||
		d.ConfigChecks != nil {
		t.Fatalf("%+v", d)
	}
	if d := p.ConfigDialect("cisco_iosxe"); !reflect.DeepEqual(d, p.Dialect("cisco_iosxe")) {
		t.Fatal("no block: the policy's adapter is the set's")
	}
}
