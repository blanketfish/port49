//go:build lab

package lab

import "testing"

// The srlinux row is opt-in and is the row l76_cells.go names.
func TestL76RowIsOptIn(t *testing.T) {
	if !optInPlatforms[l76Sel] {
		t.Errorf("%s is not opt-in: a default run would deploy SR Linux", l76Sel)
	}
	for _, p := range defaultPlatforms(platforms) {
		if p.sel == l76Sel {
			t.Errorf("defaultPlatforms selects %s", l76Sel)
		}
	}
	var got *platform
	for i := range platforms {
		if platforms[i].sel == l76Sel {
			got = &platforms[i]
		}
	}
	if got == nil {
		t.Fatalf("no %s row", l76Sel)
	}
	want := platform{l76Sel, l76PlatformName, l76Topo, l76Addr, l76Node, l76Image, l76Version, got.boot}
	if *got != want {
		t.Errorf("row %+v, want %+v", *got, want)
	}
}
