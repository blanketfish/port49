package policy

import (
	"strings"
	"testing"
	"time"
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
