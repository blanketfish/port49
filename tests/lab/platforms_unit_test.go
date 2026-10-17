//go:build lab

package lab

import "testing"

// The L73 rows share node names and platform names with notes other
// entries closed on older images; a run that names no platform must never
// deploy them, or it would write those entries' notes from the wrong image.
func TestOptInPlatformsAreNotInTheDefaultSelection(t *testing.T) {
	got := map[string]bool{}
	for _, p := range defaultPlatforms(platforms) {
		got[p.sel] = true
	}
	for sel := range optInPlatforms {
		if got[sel] {
			t.Errorf("%s is in the default selection", sel)
		}
		found := false
		for _, p := range platforms {
			found = found || p.sel == sel
		}
		if !found {
			t.Errorf("opt-in selector %s names no platform row", sel)
		}
	}
	for sel := range helpOnlyPlatforms {
		if !optInPlatforms[sel] {
			t.Errorf("help-only %s is not opt-in", sel)
		}
	}
	for _, sel := range []string{"eos", "vjunos", "vsrx", "nxos", "iosxe"} {
		if !got[sel] {
			t.Errorf("%s left the default selection", sel)
		}
	}
}
