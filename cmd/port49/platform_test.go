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
		listRow(out.String(), "juniper_junos") != "juniper_junos built-in — session" {
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
		"#   {match: ['**'], after: secret}\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if !strings.Contains(out.String(), "a URL's password") {
		t.Errorf("the footer does not say a URL's password is removed:\n%s", out.String())
	}
	for _, name := range platform.Names() {
		want, _ := platform.DialectFor(name)
		if got := parseExport(t, name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
		}
	}
	if code := run([]string{"platform", "show", "junos"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), `"junos" has no adapter here; the platforms are arista_eos,`) {
		t.Fatalf("code %d %s", code, errb.String())
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
		&out, &errb); code != 0 || out.String() != "platform_set 1.0.0 -> 1.0.0\n  no adapter the inventory uses changes\n" {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	if got := readFile(t, pol); string(got) != "platform_set: 1.0.0\n"+string(raw) {
		t.Fatalf("%s", got)
	}
	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "9.9.9", "--write"},
		&out, &errb); code != 1 || !strings.Contains(errb.String(), "does not load on platform set 9.9.9, so nothing was written") {
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
		strings.Contains(out.String(), "policy diff fails") {
		t.Fatalf("%s", out.String())
	}
}
