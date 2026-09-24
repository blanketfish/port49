package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// `port49 platform list` prints every platform with where its adapter comes
// from, how it was verified and what it authorizes (spec §8); with a policy,
// its blocks are named for what they are, and an adapter a block changed is
// not the one anybody verified.
func TestPlatformListSaysWhereEachAdapterComesFrom(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "list"}, &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "PLATFORM") || strings.Count(out.String(), "built-in") != 4 ||
		listRow(out.String(), "juniper_junos") != "juniper_junos built-in — session" ||
		listRow(out.String(), "arista_eos") != "arista_eos built-in containerlab session,commands" ||
		listRow(out.String(), "cisco_nxos") != "cisco_nxos built-in containerlab session,commands" ||
		listRow(out.String(), "cisco_iosxe") != "cisco_iosxe built-in containerlab session,commands" {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	blocks := "platforms:\n  arista_eos: {entity_classes: {uplink: ['^Ethernet49$']}}\n" +
		"  whitebox_nos: {based_on: arista_eos}\n  meinberg_lantime: {supports: [session]}\n"
	if err := os.WriteFile(pol, append([]byte(blocks), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	// A device on a platform nothing adapts is rendered with the pinned set's
	// generic adapter, and the tools say so rather than that it has none.
	fortinet := "devices:\n  - {name: fw-01, platform: fortinet_fortios, addresses: [10.0.0.2]}\n"
	if err := os.WriteFile(inv, []byte(strings.Replace(string(readFile(t, inv)), "devices:\n", fortinet, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"platform", "list", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	for name, want := range map[string]string{"arista_eos": "overridden — session,commands",
		"meinberg_lantime": "local — session", "whitebox_nos": "variant — session,commands",
		"fortinet_fortios": "generic — session"} {
		if got := listRow(out.String(), name); got != name+" "+want {
			t.Errorf("%s: %q in\n%s", name, got, out.String())
		}
	}
	// show prints what the daemon renders: the block merged over the set, a
	// variant's inherited keys, and the generic adapter for the rest.
	for name, wants := range map[string][]string{
		"arista_eos":       {"# arista_eos: overridden, platform set 1.0.0\n", "      uplink:\n        - ^Ethernet49$\n", "      physical:\n"},
		"whitebox_nos":     {"# whitebox_nos: variant, platform set 1.0.0\n", "      physical:\n"},
		"fortinet_fortios": {"# fortinet_fortios: generic, platform set 1.0.0\n", "    supports:\n      - session\n"},
	} {
		out.Reset()
		if code := run([]string{"platform", "show", "--policy", pol, "--inventory", inv, name}, &out, &errb); code != 0 {
			t.Fatalf("%s: code %d %s", name, code, errb.String())
		}
		for _, want := range wants {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: missing %q in\n%s", name, want, out.String())
			}
		}
	}
	generic, _ := platform.Generic(platform.DefaultSet)
	if got := parseExport(t, "fortinet_fortios", "--policy", pol, "--inventory", inv); !reflect.DeepEqual(got, generic) {
		t.Errorf("fortinet_fortios exports\n%+v\nwant the generic adapter\n%+v", got, generic)
	}
	if code := run([]string{"platform", "show", "--policy", pol, "--inventory", inv, "junos"}, &out, &errb); code != 1 {
		t.Errorf("a platform neither adapted nor in the inventory: code %d", code)
	}
	if code := run([]string{"platform", "list", "--set", "1.0.0", "--policy", pol, "--inventory", inv}, &out, &errb); code != 2 {
		t.Errorf("--set with --policy: code %d", code)
	}
	if code := run([]string{"platform", "list", "--set", "0.1.0"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "it ships 1.0.0") {
		t.Fatalf("code %d %s", code, errb.String())
	}
}

// `show` prints the adapter as a file writes it, headed by where it came from
// and followed by the built-in redaction; `export` prints the file alone, and
// what it prints is the adapter again when read back (spec §8).
func TestPlatformShowAndExportPrintTheAdapter(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "show", "cisco_iosxe"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	for _, want := range []string{"# cisco_iosxe: built-in, platform set 1.0.0\n", "      operator:\n        - priv-lvl=7\n",
		"    accepted_attributes:\n      - priv-lvl\n", "      - privilege exec level 7 clear counters\n",
		"    verified: containerlab\n",
		"#   {match: ['**'], after: secret}\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if !strings.Contains(out.String(), "a URL's password") {
		t.Errorf("the footer does not say a URL's password is removed:\n%s", out.String())
	}
	for _, name := range platform.Names() {
		// export writes a block, and a block never claims the lab's
		// verification (spec §8): the one key it leaves out.
		want, _ := platform.DialectFor(name)
		want.Verified = ""
		if got := parseExport(t, name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
		}
	}
	if code := run([]string{"platform", "show", "junos"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), `"junos" has no adapter here; the platforms are arista_eos,`) {
		t.Fatalf("code %d %s", code, errb.String())
	}
}

// A verified adapter exported is a block that pastes back into a policy: it
// leaves out `verified`, which a block may not set, and pasted back it is an
// override the list prints unverified (spec §8). The set export --all writes
// keeps it.
func TestPlatformExportOfAVerifiedAdapterPastesBack(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "export", "cisco_iosxe"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if strings.Contains(out.String(), "verified") {
		t.Fatalf("export claims the lab's verification:\n%s", out.String())
	}
	if err := os.WriteFile(pol, append(out.Bytes(), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"platform", "list", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		listRow(out.String(), "cisco_iosxe") != "cisco_iosxe overridden — session,commands" {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	dir := t.TempDir()
	if code := run([]string{"platform", "export", "--all", "--dir", dir}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if file := string(readFile(t, filepath.Join(dir, "cisco_iosxe.yaml"))); !strings.Contains(file, "    verified: containerlab\n") {
		t.Errorf("the set's file drops verified:\n%s", file)
	}
}

// `export` writes a block's fallback text under fallback, where the block
// wrote it, and never fallback_note, which a block may not set: pasted back
// as the policy's block, the export loads with the same note and exports the
// same again (spec §8, §12). `show` prints both, the set's measured text and
// the note apart.
func TestPlatformExportPastesBackWithTheFallbackNote(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	block := "platforms:\n  arista_eos: {fallback: {admin: \"read-only in practice\"}}\n"
	if err := os.WriteFile(pol, append([]byte(block), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	export := func() string {
		t.Helper()
		var out, errb bytes.Buffer
		if code := run([]string{"platform", "export", "--policy", pol, "--inventory", inv, "arista_eos"}, &out, &errb); code != 0 {
			t.Fatalf("code %d %s", code, errb.String())
		}
		return out.String()
	}
	first := export()
	if strings.Contains(first, "fallback_note") || !strings.Contains(first, "    fallback:\n      admin: read-only in practice # operator note, not measured\n") {
		t.Fatalf("export:\n%s", first)
	}
	if err := os.WriteFile(pol, append([]byte(first), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	if again := export(); again != first {
		t.Errorf("pasted back, the export changed:\n%s\nwas\n%s", again, first)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "show", "--policy", pol, "--inventory", inv, "arista_eos"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	for _, want := range []string{"    fallback:\n      admin: 'network-admin, of the commands measured: clear counters ran, clear ip bgp * passed authorization (BGP inactive on the lab node), configuration changed'\n",
		"    fallback_note:\n      admin: read-only in practice\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("show: missing %q in\n%s", want, out.String())
		}
	}
}

// `export --all` writes a platform set, which carries only what the lab
// measured: a policy block's note is not written into it, and the set's text
// is (spec §8).
func TestPlatformExportAllWritesNoOperatorNote(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	block := "platforms:\n  arista_eos: {fallback: {admin: \"read-only in practice\"}}\n"
	if err := os.WriteFile(pol, append([]byte(block), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "export", "--all", "--dir", dir, "--policy", pol, "--inventory", inv}, &out,
		&errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	file := string(readFile(t, filepath.Join(dir, "arista_eos.yaml")))
	if strings.Contains(file, "read-only in practice") || strings.Contains(file, "fallback_note") ||
		!strings.Contains(file, "      admin: 'network-admin, of the commands measured: clear counters ran, clear ip bgp * passed authorization (BGP inactive on the lab node), configuration changed'\n") {
		t.Errorf("arista_eos.yaml:\n%s", file)
	}
}

// Exporting reads the adapter and changes nothing in it: the fold writes a
// copy of the fallback map.
func TestAdapterFileLeavesTheAdapterAlone(t *testing.T) {
	d, _ := platform.DialectFor("arista_eos")
	d.FallbackNote = map[string]string{"admin": "read-only in practice"}
	want := platform.SpecOf(d).Over(platform.Dialect{})
	for _, mode := range []exportMode{exportShow, exportBlock, exportSet} {
		if _, err := adapterFile("arista_eos", d, mode); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(d, want) {
			t.Fatalf("mode %d changed the adapter: %+v", mode, d.Fallback)
		}
	}
}

// `export --all --dir` writes one file per platform, and the directory is a
// platform set LoadSets reads back as the one it was written from: a file
// fit for platforms/ in an upstream pull request.
func TestPlatformExportAllWritesASet(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "1.0.0")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "export", "--all", "--dir", dir}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	sets, err := platform.LoadSets(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := platform.Set(platform.DefaultSet)
	if !reflect.DeepEqual(sets["1.0.0"], want) {
		t.Fatalf("the exported set reads back differently:\n%+v", sets["1.0.0"])
	}
	// A directory already holding files would read back as a different set.
	if code := run([]string{"platform", "export", "--all", "--dir", dir}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "is not empty") {
		t.Errorf("a second export into %s: code %d %s", dir, code, errb.String())
	}
	for _, args := range [][]string{{"platform", "show", "--all", "--dir", dir}, {"platform", "export", "--all"},
		{"platform", "export"}, {"platform", "list", "extra"}, {"platform"}, {"platform", "upgrad"}} {
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%q: code %d", args, code)
		}
	}
}

// parseExport runs `platform export` for name and reads what it prints back
// as an adapter file, laid over nothing.
func parseExport(t *testing.T, name string, flags ...string) platform.Dialect {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"platform", "export"}, flags...), name), &out, &errb); code != 0 {
		t.Fatalf("%s: code %d %s", name, code, errb.String())
	}
	specs, err := platform.ParseSpecs(out.Bytes())
	if err != nil {
		t.Fatalf("%s: %v\n%s", name, err, out.String())
	}
	return specs[name].Over(platform.Dialect{})
}

// listRow is the `platform list` line for name, its columns joined by one
// space, so a test does not depend on how wide another row made them.
func listRow(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == name {
			return strings.Join(f, " ")
		}
	}
	return ""
}

// `port49 platform upgrade` reports what moving the pin changes and, with
// --write, rewrites the pin alone. A set this binary does not ship is not a
// pin the policy can load on, and nothing is written.
func TestPlatformUpgradeMovesThePin(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "1.0.0", "--write"},
		&out, &errb); code != 0 || out.String() != "platform_set 1.0.0 -> 1.0.0\n  no adapter changes\n" {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	pinned := readFile(t, pol)
	if string(pinned) != "platform_set: 1.0.0\n"+string(raw) {
		t.Fatalf("%s", pinned)
	}
	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "9.9.9", "--write"},
		&out, &errb); code != 1 || !strings.Contains(errb.String(), "does not load on platform set 9.9.9, so nothing was written") {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if got := readFile(t, pol); !bytes.Equal(got, pinned) {
		t.Fatalf("a refused move wrote the file: %s", got)
	}
	// A pin this binary no longer ships leaves nothing to compare against;
	// the operator is told which binary to run.
	if err := os.WriteFile(pol, append([]byte("platform_set: 0.9.0\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "1.0.0"}, &out,
		&errb); code != 1 || !strings.Contains(errb.String(), "run the upgrade with a binary that ships both sets") {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv}, &out, &errb); code != 2 {
		t.Fatalf("no --to: code %d", code)
	}
}

// The upgrade report prints, for a gated key the move changes, the generic
// adapter's included, the acknowledge: entry that clears it, bound to the new
// value's sha256; pasted into the moved file, it acknowledges the move. This
// build ships one set, so the environment stands up a second.
func TestTheUpgradeReportPrintsPasteReadyAcknowledgments(t *testing.T) {
	pol, inv := policyFixture(t)
	devices, err := admission.LoadFile(inv)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := platform.Set("1.0.0")
	second, _ := platform.Set("1.0.0")
	eos := second["arista_eos"]
	eos.DeviceConfig = append(eos.DeviceConfig, "aaa accounting exec default start-stop group port49")
	second["arista_eos"] = eos
	g1, _ := platform.Generic("1.0.0")
	g2, _ := platform.Generic("1.0.0")
	g2.StripCR = !g2.StripCR
	e := policy.Env{Devices: devices.Devices, Sets: map[string]map[string]platform.Dialect{"1.0.0": first,
		"1.1.0": second}, Generics: map[string]platform.Dialect{"1.0.0": g1, "1.1.0": g2}}
	raw := readFile(t, pol)
	before, err := policy.Parse(raw, e)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := policy.SetPlatformSet(raw, "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	after, err := policy.Parse(moved, e)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var out bytes.Buffer
	upgradeReport(&out, before, after, now)
	newValue, _ := json.Marshal(eos.DeviceConfig)
	entry := fmt.Sprintf("{platform: arista_eos, field: device_config, sha256: %x, reason: \"...\"}",
		sha256.Sum256(newValue))
	for _, want := range []string{"platform_set 1.0.0 -> 1.1.0\n  platforms.arista_eos.device_config\n",
		"    affects 1 devices, 2 subjects\n", "    gated: add " + entry + " under acknowledge:\n",
		"  generic.strip_cr\n", "    affects 0 devices, 0 subjects\n",
		"    gated: add {platform: generic, field: strip_cr, sha256: ",
		"  port49 policy diff fails on the move until"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
	acks := "acknowledge:\n"
	for _, m := range regexp.MustCompile(`add (\{.*\}) under acknowledge:`).FindAllStringSubmatch(out.String(), -1) {
		acks += "  - " + strings.Replace(m[1], "...", "set 1.1.0 adds exec accounting", 1) + "\n"
	}
	acked, err := policy.Parse(append(moved, acks...), e)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	upgradeReport(&out, before, acked, now)
	if strings.Count(out.String(), "    gated, acknowledged: set 1.1.0 adds exec accounting\n") != 2 ||
		strings.Contains(out.String(), "policy diff fails") ||
		!strings.Contains(out.String(), "  port49 policy diff on the move also shows the replies it changes\n") {
		t.Fatalf("%s", out.String())
	}
}

// A device_config line or a config check a block writes with a value
// redaction hides is printed redacted by show, export and export --all: their
// output lands in terminals, CI logs and upstream pull requests (spec §5.8;
// task 15 review I2, I3). A set's own lines and checks print as written.
func TestPlatformShowAndExportRedactABlocksSecrets(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	block := "platforms:\n  arista_eos:\n    device_config: [\"aaa authorization exec default group port49 local\", " +
		"\"snmp-server community Hunter2 ro\"]\n" +
		"    config_checks:\n      - {match: '^tacacs-server key=Hunter2', says: 'tacacs-server key Hunter2 and " +
		"\"snmp-server community Hunter2 ro\"'}\n" +
		"  cisco_nxos:\n    device_config: [\"aaa authentication login default group port49 local\"]\n"
	if err := os.WriteFile(pol, append([]byte(block), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"platform", "show", "--policy", pol, "--inventory", inv, "arista_eos"},
		{"platform", "export", "--policy", pol, "--inventory", inv, "arista_eos"},
		{"platform", "export", "--all", "--dir", dir, "--policy", pol, "--inventory", inv}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 0 {
			t.Fatalf("%q: code %d %s", args, code, errb.String())
		}
		text := out.String()
		if args[2] == "--all" {
			text = string(readFile(t, filepath.Join(dir, "arista_eos.yaml"))) +
				string(readFile(t, filepath.Join(dir, "cisco_nxos.yaml")))
		}
		if strings.Contains(text+errb.String(), "Hunter2") || !strings.Contains(text, "snmp-server community «redacted» «redacted»") ||
			!strings.Contains(text, "aaa authorization exec default group port49 local") {
			t.Errorf("%q:\n%s%s", args, text, errb.String())
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "show", "--policy", pol, "--inventory", inv, "cisco_nxos"}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "aaa authentication login default group port49 local") {
		t.Fatalf("a set's line prints as written:\n%s%s", out.String(), errb.String())
	}
}

// A block's unreachable rules, its fallback text and note and its class
// patterns are block text like its device_config, and show and export print
// them redacted (final review I2): a class a rule names where a value is
// redacted holds those values, as the blob event reads it (spec §5.8).
func TestPlatformShowAndExportRedactABlocksOtherText(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := strings.Replace(string(readFile(t, pol)), "roles:\n",
		"roles:\n  - {name: snmp, deny: [snmp-server community @bad_comm **]}\n", 1)
	block := "platforms:\n  arista_eos:\n" +
		"    unreachable: {readonly: [\"snmp-server community Hunter2a **\"]}\n" +
		"    fallback: {admin: \"local admin, enable password: Hunter2b\", readonly: \"a local user, password Hunter2c\"}\n" +
		"    entity_classes: {bad_comm: ['^Hunter2d$'], secret_pattern: ['^snmp-server community Hunter2e$']}\n"
	if err := os.WriteFile(pol, []byte(block+raw), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"platform", "show", "--policy", pol, "--inventory", inv, "arista_eos"},
		{"platform", "export", "--policy", pol, "--inventory", inv, "arista_eos"},
		{"platform", "export", "--all", "--dir", dir, "--policy", pol, "--inventory", inv}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 0 {
			t.Fatalf("%q: code %d %s", args, code, errb.String())
		}
		text := out.String()
		if args[2] == "--all" {
			text = string(readFile(t, filepath.Join(dir, "arista_eos.yaml")))
		}
		for _, probe := range []string{"Hunter2a", "Hunter2b", "Hunter2c", "Hunter2d", "Hunter2e"} {
			if strings.Contains(text+errb.String(), probe) {
				t.Errorf("%q prints %s:\n%s%s", args, probe, text, errb.String())
			}
		}
		// The set's own text prints as written; export writes the block's
		// note where the block wrote it, in place of the set's.
		if !strings.Contains(text, "clear counters **") ||
			args[1] == "show" && !strings.Contains(text, "network-admin, of the commands measured") {
			t.Errorf("%q:\n%s", args, text)
		}
	}
}

// A block's check with no secret in it exports as written, regex escapes
// included: pasted back, a mangled match would be a check that matches
// nothing (task 15 re-review 2, R1).
func TestPlatformExportKeepsARegexCheckWhole(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	block := "platforms:\n  arista_eos:\n    config_checks:\n" +
		"      - {match: '^aaa authorization exec default\\s+group \\S+ none$', says: the exec list falls back to none}\n" +
		"      - {match: '^username\\s+\\S+\\s+privilege\\s+\\d+$', says: a local account}\n"
	if err := os.WriteFile(pol, append([]byte(block), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "export", "--policy", pol, "--inventory", inv, "arista_eos"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	for _, want := range []string{`^aaa authorization exec default\s+group \S+ none$`, `^username\s+\S+\s+privilege\s+\d+$`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

// An export of a block whose check or line carries a secret holds the
// marker in the value's place; pasted back, it would run a check that
// matches nothing or hold the device to a line nobody wrote, so the load
// refuses it and says to re-enter the value (task 15 re-review 2, R1b).
func TestAPastedBackRedactedValueIsRefused(t *testing.T) {
	for key, block := range map[string]string{
		"platforms.arista_eos.config_checks[0].match": "    config_checks:\n      - {match: '^snmp-server community Hunter2', says: x}\n",
		"platforms.arista_eos.device_config[1]": "    device_config: [\"aaa authorization exec default group port49 local\", " +
			"\"snmp-server community Hunter2 ro\"]\n",
		"platforms.arista_eos.unreachable.readonly holds": "    unreachable: {readonly: [\"snmp-server community Hunter2 **\"]}\n",
		"platforms.arista_eos.fallback.readonly":          "    fallback: {readonly: \"a local user, password Hunter2\"}\n",
		"platforms.arista_eos.fallback.admin":             "    fallback: {admin: \"local admin, password Hunter2\"}\n",
		"platforms.arista_eos.entity_classes.secret_pattern[0]": "    entity_classes: {secret_pattern: " +
			"['^snmp-server community Hunter2$']}\n",
	} {
		pol, inv := policyFixture(t)
		raw := readFile(t, pol)
		if err := os.WriteFile(pol, append([]byte("platforms:\n  arista_eos:\n"+block), raw...), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"platform", "export", "--policy", pol, "--inventory", inv, "arista_eos"}, &out, &errb); code != 0 ||
			!strings.Contains(out.String(), platform.Redacted) {
			t.Fatalf("code %d %s%s", code, out.String(), errb.String())
		}
		if err := os.WriteFile(pol, append(out.Bytes(), raw...), 0o600); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		code := run([]string{"platform", "show", "--policy", pol, "--inventory", inv, "arista_eos"}, &out, &errb)
		if code != 1 || !strings.Contains(errb.String(), key) || !strings.Contains(errb.String(), "re-enter the value from your policy") {
			t.Errorf("%s: code %d\n%s", key, code, errb.String())
		}
	}
}

// A set move that changes a key a block merges into, here entity_classes,
// prints the block's part of it, and the report goes to CI logs like policy
// diff's: it prints the block's text redacted (final review I3).
func TestTheUpgradeReportNeverPrintsABlockSecret(t *testing.T) {
	pol, inv := policyFixture(t)
	devices, err := admission.LoadFile(inv)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := platform.Set("1.0.0")
	second, _ := platform.Set("1.0.0")
	eos := second["arista_eos"]
	eos.EntityClasses = map[string][]string{"management": {"^Management[0-9]+$"}, "loopback": {"^Loopback[0-9]+$"},
		"physical": {"^Ethernet[0-9/.]+$"}}
	second["arista_eos"] = eos
	g, _ := platform.Generic("1.0.0")
	e := policy.Env{Devices: devices.Devices, Sets: map[string]map[string]platform.Dialect{"1.0.0": first,
		"1.1.0": second}, Generics: map[string]platform.Dialect{"1.0.0": g, "1.1.0": g}}
	raw := append([]byte("platforms:\n  arista_eos:\n    entity_classes: {secret_pattern: ['^snmp-server community Hunter2$']}\n"),
		readFile(t, pol)...)
	before, err := policy.Parse(raw, e)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := policy.SetPlatformSet(raw, "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	after, err := policy.Parse(moved, e)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	upgradeReport(&out, before, after, time.Now())
	if strings.Contains(out.String(), "Hunter2") || !strings.Contains(out.String(), "platforms.arista_eos.entity_classes") ||
		!strings.Contains(out.String(), "snmp-server community «redacted»") {
		t.Fatalf("%s", out.String())
	}
}

// policy diff and platform upgrade name an adapter key the same way, the
// generic adapter's as generic.<key>: no block writes it, so it is not under
// platforms: (task 13 review M6).
func TestDiffAndUpgradeNameAnAdapterKeyAlike(t *testing.T) {
	for _, tt := range []struct {
		a    policy.AdapterChange
		want string
	}{
		{policy.AdapterChange{Platform: "generic", Field: "strip_cr"}, "generic.strip_cr"},
		{policy.AdapterChange{Platform: "arista_eos", Field: "device_config"}, "platforms.arista_eos.device_config"},
	} {
		if got := adapterKey(tt.a); got != tt.want {
			t.Errorf("%+v: %s, want %s", tt.a, got, tt.want)
		}
	}
}

// A block's unreachable rules the set did not measure are the operator's:
// show prints them apart, as unreachable_note, export writes them back under
// unreachable commented as the operator's, so the file pastes back, and
// export --all leaves them out of the set (task 14 review M7).
func TestAnOperatorsUnreachableRulesExportAsTheOperators(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	block := "platforms:\n  arista_eos:\n    unreachable: {readonly: [\"show tech-support **\"]}\n"
	if err := os.WriteFile(pol, append([]byte(block), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	show := func(args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 0 {
			t.Fatalf("%q: code %d %s", args, code, errb.String())
		}
		return out.String()
	}
	if out := show("platform", "show", "--policy", pol, "--inventory", inv, "arista_eos"); !strings.Contains(out,
		"    unreachable_note:\n      readonly:\n        - show tech-support **\n") {
		t.Errorf("show:\n%s", out)
	}
	exported := show("platform", "export", "--policy", pol, "--inventory", inv, "arista_eos")
	if !strings.Contains(exported, "        - show tech-support ** # operator-listed, not measured\n") ||
		strings.Contains(exported, "unreachable_note") {
		t.Errorf("export:\n%s", exported)
	}
	if err := os.WriteFile(pol, append([]byte(exported), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	if again := show("platform", "export", "--policy", pol, "--inventory", inv, "arista_eos"); again != exported {
		t.Errorf("pasted back, the export changed:\n%s\nwas\n%s", again, exported)
	}
	dir := t.TempDir()
	show("platform", "export", "--all", "--dir", dir, "--policy", pol, "--inventory", inv)
	if file := string(readFile(t, filepath.Join(dir, "arista_eos.yaml"))); strings.Contains(file, "tech-support") {
		t.Errorf("--all:\n%s", file)
	}
}
