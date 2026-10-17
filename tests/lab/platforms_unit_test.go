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

func TestSelectPlatforms(t *testing.T) {
	sel, explicit, err := selectPlatforms("")
	if err != nil || explicit {
		t.Fatalf("empty: explicit=%v err=%v", explicit, err)
	}
	for _, p := range sel {
		if optInPlatforms[p.sel] {
			t.Errorf("empty selection holds opt-in %s", p.sel)
		}
	}
	sel, explicit, err = selectPlatforms("vjunos26")
	if err != nil || !explicit || len(sel) != 1 || sel[0].sel != "vjunos26" {
		t.Errorf("vjunos26: %v explicit=%v err=%v", sel, explicit, err)
	}
	if _, _, err = selectPlatforms("vjuno"); err == nil {
		t.Error("an unknown selector ran instead of failing")
	}
	if _, _, err = selectPlatforms("vjunos,vjunos26"); err == nil {
		t.Error("two selectors of one platform name were accepted")
	}
	if _, _, err = selectPlatforms(" , "); err == nil {
		t.Error("an empty list selected a platform")
	}
}

// The register tests must not run an opt-in row, or they rewrite a closed
// results note from the wrong image.
func TestRowsForSeparatesOptInRows(t *testing.T) {
	sel := []platform{{sel: "vjunos"}, {sel: "vjunos26"}}
	if got := rowsFor(sel, false); len(got) != 1 || got[0].sel != "vjunos" {
		t.Errorf("non-opting test got %v", got)
	}
	if got := rowsFor(sel, true); len(got) != 1 || got[0].sel != "vjunos26" {
		t.Errorf("opting test got %v", got)
	}
}
