package platform

import (
	"reflect"
	"strings"
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

// TestEveryAdapterSaysTheEnableSTARTCarriesThePrincipal pins the built-in
// adapters' enable username: every platform this package knows, and the
// generic adapter, says EnablePrincipal, because no platform in the lab has
// been measured sending anything else (tests/lab/results/L3-arista_eos.md,
// L3-cisco_iosxe.md, L3-nxos-cisco_nxos.md). `enab` is refused wherever it is
// written.
func TestEveryAdapterSaysTheEnableSTARTCarriesThePrincipal(t *testing.T) {
	for _, name := range append(Names(), "no_such_platform") {
		if d, _ := DialectFor(name); d.EnableUsername != EnablePrincipal {
			t.Errorf("%s: enable username is %q, want %q", name, d.EnableUsername, EnablePrincipal)
		}
	}
	d, _ := DialectFor("arista_eos")
	for v, want := range map[string]string{EnableEnab: "tests/lab/results", "princpal": `it must be "principal"`} {
		d.EnableUsername = v
		if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(),
			"platforms.arista_eos.enable_username") || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", v, err)
		}
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

// TestSystemUsersIsMeasuredPerPlatform pins the one row that exists and the
// emptiness of every other. Both halves are a measurement.
//
// juniper_junos: root, from tests/lab/evidence/L1-juniper_vsrx.pcap — three
// accounting records under user=root, port=non-tty, session_pid = 28771, with
// no AUTHEN and no AUTHOR for root anywhere in the file. Deleting this row
// makes a healthy vSRX report sessions port49 did not authenticate.
//
// Everything else: empty, because nothing has measured one. A row added here
// without a tests/lab/results/ or evidence citation is a row that silently
// stops attributing a real operator's records as `foreign` — the alert exists
// to catch a login port49 never saw, and a username on this list is a username
// that can never raise it.
func TestSystemUsersIsMeasuredPerPlatform(t *testing.T) {
	want := map[string][]string{"juniper_junos": {"root"}}
	got := SystemUsers()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SystemUsers() = %v, want %v — every row needs a capture or a tests/lab/results/ note", got, want)
	}
	for _, name := range Names() {
		if name == "juniper_junos" {
			continue
		}
		if users := got[name]; len(users) != 0 {
			t.Errorf("%s declares system users %v with nothing measuring them", name, users)
		}
	}
}

// TestSystemUsersReturnsACopy: main.go hands the result to acct.New, which
// keeps it for the life of the process. A caller that could edit the table
// through it would be editing a security rule at run time.
func TestSystemUsersReturnsACopy(t *testing.T) {
	got := SystemUsers()
	got["arista_eos"] = []string{"admin"}
	got["juniper_junos"][0] = "tampered"
	if users := SystemUsers()["arista_eos"]; len(users) != 0 {
		t.Fatalf("SystemUsers handed out the table itself: %v", users)
	}
	if users := SystemUsers()["juniper_junos"]; users[0] != "root" {
		t.Fatalf("SystemUsers handed out the table's own slices: %v", users)
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
