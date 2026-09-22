package platform

import (
	"reflect"
	"testing"
)

// TestBuiltInSessionServices pins the table against the lab notes that
// produced it. A change to any row here changes which authorization requests
// port49 answers on a shipping image, so it has to be argued from a
// measurement and not from a preference.
func TestBuiltInSessionServices(t *testing.T) {
	for _, tt := range []struct {
		platform string
		want     []string
		measured string
	}{
		{"arista_eos", []string{"shell"}, "tests/lab/results/L10-arista_eos.md"},
		{"cisco_nxos", []string{"shell"}, "tests/lab/results/L10-cisco_nxos.md"},
		{"cisco_iosxe", []string{"shell"}, "tests/lab/results/L10-cisco_iosxe.md"},
		{"juniper_junos", []string{"junos-exec"}, "tests/lab/results/L10-juniper_vsrx.md"},
	} {
		if got := SessionServices(tt.platform); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: session services are %v, want %v — measured in %s", tt.platform, got, tt.want, tt.measured)
		}
		if !Known(tt.platform) {
			t.Errorf("%s is not Known, so configuration would refuse a block for it", tt.platform)
		}
	}
}

// TestUnknownPlatformFallsBackToShell: the behaviour every platform had before
// this table existed. A device whose platform port49 ships no adapter for must
// still log in (spec §8, "Unknown platforms").
func TestUnknownPlatformFallsBackToShell(t *testing.T) {
	if Known("meinberg_lantime") {
		t.Fatal("meinberg_lantime should not be in the built-in table")
	}
	if got := SessionServices("meinberg_lantime"); !reflect.DeepEqual(got, []string{"shell"}) {
		t.Fatalf("an unmodeled platform must fall back to [shell], got %v", got)
	}
	if got := SessionServices(""); !reflect.DeepEqual(got, []string{"shell"}) {
		t.Fatalf("a device with no platform set must fall back to [shell], got %v", got)
	}
}

// TestNamesIsSortedAndComplete: the load error for a mistyped platform name
// prints this list, so it has to hold every name and be in a stable order.
func TestNamesIsSortedAndComplete(t *testing.T) {
	names := Names()
	want := []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
}

// TestEnableUsernamesNamesEveryKnownPlatformAsPrincipal pins the built-in
// enable-username table: every platform this package knows, mapped to
// EnablePrincipal, because no platform in the lab has been measured sending
// anything else (tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md,
// L3-nxos-cisco_nxos.md).
func TestEnableUsernamesNamesEveryKnownPlatformAsPrincipal(t *testing.T) {
	got := EnableUsernames()
	for _, name := range Names() {
		if got[name] != EnablePrincipal {
			t.Errorf("%s: enable username is %q, want %q", name, got[name], EnablePrincipal)
		}
	}
	if len(got) != len(Names()) {
		t.Fatalf("EnableUsernames() has %d entries, want %d", len(got), len(Names()))
	}
}

// TestCallersCannotEditTheTable. SessionServices and Defaults hand out copies;
// a caller that appends to what it got — a config override building on a
// default, say — must not change what the next caller reads.
func TestCallersCannotEditTheTable(t *testing.T) {
	got := SessionServices("juniper_junos")
	got[0] = "tampered"
	if s := SessionServices("juniper_junos"); s[0] != "junos-exec" {
		t.Fatalf("SessionServices handed out the table itself: %v", s)
	}

	d := Defaults()
	d["arista_eos"][0] = "tampered"
	delete(d, "cisco_nxos")
	if s := SessionServices("arista_eos"); s[0] != "shell" {
		t.Fatalf("Defaults handed out the table's own slices: %v", s)
	}
	if !Known("cisco_nxos") {
		t.Fatal("Defaults handed out the table itself: deleting from it removed a platform")
	}
}
