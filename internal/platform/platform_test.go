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

// TestSessionDiscriminatorsAreMeasured pins the per-platform discriminator
// against the note that produced each row. Getting a row wrong does not fail
// loudly — it binds the wrong value, two concurrent sessions of one operator
// stop being distinguishable, and `foreign` either fires on every second login
// or never fires at all — so each row has to be argued from a measurement.
func TestSessionDiscriminatorsAreMeasured(t *testing.T) {
	for _, tt := range []struct {
		platform string
		want     string
		measured string
	}{
		{"juniper_junos", "session_pid", "tests/lab/results/L17-juniper_vsrx.md, L17-juniper_vjunos-router.md"},
		{"arista_eos", "task_id", "tests/lab/results/L1-arista_eos.md"},
		{"cisco_nxos", "task_id", "tests/lab/results/L1-cisco_nxos.md"},
		{"cisco_iosxe", "task_id", "tests/lab/results/L1-cisco_iosxe.md"},
	} {
		got, ok := SessionDiscriminator(tt.platform)
		if !ok || got != tt.want {
			t.Errorf("%s: discriminator is %q (ok=%v), want %q — measured in %s", tt.platform, got, ok, tt.want, tt.measured)
		}
	}
	if len(Names()) != 4 {
		t.Fatal("a platform was added without a discriminator row and a lab note to justify it")
	}
}

// TestUnknownPlatformHasNoDiscriminator: an unmodeled platform binds nothing
// and takes §5.8's username-only branch. That is the safe direction — it
// annotates less, never more — and it is why this returns ok rather than a
// fallback AV pair nobody measured.
func TestUnknownPlatformHasNoDiscriminator(t *testing.T) {
	if av, ok := SessionDiscriminator("meinberg_lantime"); ok {
		t.Fatalf("an unmodeled platform must have no discriminator, got %q", av)
	}
	if av, ok := SessionDiscriminator(""); ok {
		t.Fatalf("a device with no platform set must have no discriminator, got %q", av)
	}
}

// TestExecRecordDetectionIsPerPlatform. On EOS, NX-OS and IOS-XE the exec
// START and STOP carry no `cmd` at all; on both Junos images they carry
// `cmd=login` and `cmd=logout` (tests/lab/results/L6-juniper_vsrx.md,
// L6-juniper_vjunos-router.md). A reader that only knows the first form
// annotates nothing whatsoever on Junos.
func TestExecRecordDetectionIsPerPlatform(t *testing.T) {
	for _, tt := range []struct {
		platform, cmd string
		want          bool
	}{
		{"juniper_junos", "", true},
		{"juniper_junos", "login", true},
		{"juniper_junos", "logout", true},
		{"juniper_junos", "show version", false},
		{"arista_eos", "", true},
		{"arista_eos", "login", false}, // a command literally named login is still a command
		{"cisco_nxos", "", true},
		{"cisco_iosxe", "", true},
		{"cisco_iosxe", "logout", false},
		{"meinberg_lantime", "", true},
		{"meinberg_lantime", "login", false},
	} {
		if got := IsExecRecord(tt.platform, tt.cmd); got != tt.want {
			t.Errorf("IsExecRecord(%q, %q) = %v, want %v", tt.platform, tt.cmd, got, tt.want)
		}
	}
}

// TestSystemUsersShipEmptyForEveryPlatform is what keeps the "empty until a
// lab note fills it" promise honest. Two production observations are on record
// — a Junos RPC-driven `show` running as root, and an NX-OS admin record with
// task_id=vsh.bin.$port after a cancelled sudo — and neither has a
// tests/lab/results/ note in this tree. The Junos lab measured the opposite
// (L17-juniper_vsrx.md, L17-juniper_vjunos-router.md). A row added here
// without a note is a row that silently stops attributing a real operator's
// records as foreign.
func TestSystemUsersShipEmptyForEveryPlatform(t *testing.T) {
	got := SystemUsers()
	for _, name := range Names() {
		if users := got[name]; len(users) != 0 {
			t.Errorf("%s declares system users %v; the shipped list must be empty until a tests/lab/results/ note measures one", name, users)
		}
	}
	if len(got) != 0 {
		t.Fatalf("SystemUsers() = %v, want an empty table", got)
	}
}

// TestSystemUsersReturnsACopy: main.go hands the result to acct.New, which
// keeps it for the life of the process. A caller that could edit the table
// through it would be editing a security rule at run time.
func TestSystemUsersReturnsACopy(t *testing.T) {
	got := SystemUsers()
	got["juniper_junos"] = []string{"root"}
	if users := SystemUsers()["juniper_junos"]; len(users) != 0 {
		t.Fatalf("SystemUsers handed out the table itself: %v", users)
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
