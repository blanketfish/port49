package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `
listen: ":4949"
inventory_file: %s
keys:
  prod_key:
    current: {version: 3, secret_env: T_PROD_V3}
    accept:  [{version: 2, secret_env: T_PROD_V2}]
    retired: [{version: 1, secret_env: T_PROD_V1}]
limits: {per_nas_connections: 4}
lab:
  session_attributes: ["priv-lvl=15"]
  seed_tokens:
    - {nas: leaf-01, username: alice, secret: p49_lab, kind: login}
`

const inv = `
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [127.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: prod_key}
`

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setSecrets(t *testing.T) {
	t.Helper()
	t.Setenv("T_PROD_V3", "three")
	t.Setenv("T_PROD_V2", "two")
	t.Setenv("T_PROD_V1", "one")
}

// TestLoadRefusesUnknownKeys covers the typo that costs the most: an ignored
// `per_nas_conections` is not a missing limit, it is the default 32 silently
// in force, and nothing in the log or the metrics ever says so.
func TestLoadRefusesUnknownKeys(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "per_nas_connections", "per_nas_conections", 1)
	p := write(t, "port49d.yaml", body)
	_, err := Load(p)
	if err == nil {
		t.Fatal("a misspelled config key must be refused at load")
	}
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "per_nas_conections") {
		t.Fatalf("the error must name the file and the key, got %v", err)
	}
}

func TestLoadAppliesDefaultsAndResolvesKeys(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "port49d.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":4949" || c.MetricsListen != ":9049" || c.Limits.PerNASConnections != 4 ||
		c.Limits.IdleTimeout == 0 || c.ReceiptIdleTTL == 0 || c.ReceiptMaxAge == 0 || c.ContextIdleTTL == 0 {
		t.Fatalf("%+v", c)
	}
	// Both reset windows default to 10m when the key is absent: a zero window
	// in the limiter means "never reset", which is unbounded growth.
	if c.Limits.MalformedWindow != 10*time.Minute || c.Limits.AuthFailureWindow != 10*time.Minute {
		t.Fatalf("windows: %v %v", c.Limits.MalformedWindow, c.Limits.AuthFailureWindow)
	}
	if c.Accounting.SpoolCapacity == 0 || c.Accounting.SpoolPath == "" {
		t.Fatalf("%+v", c.Accounting)
	}
	ks := c.Keyring()["prod_key"]
	if len(ks.Versions) != 3 || string(ks.Versions[0].Secret) != "three" || !ks.Versions[2].Retired {
		t.Fatalf("%+v", ks)
	}
	if c.Lab == nil || len(c.Lab.SeedTokens) != 1 || c.Lab.SeedTokens[0].Username != "alice" {
		t.Fatalf("%+v", c.Lab)
	}
	// The inventory is read once, at load, and the admission table comes back
	// on the Config so main never re-reads the file.
	if len(c.Inventory.Devices) != 1 || c.Admission == nil {
		t.Fatalf("inventory %+v admission %v", c.Inventory, c.Admission)
	}
	r, ok := c.Admission.Lookup(netip.MustParseAddr("127.0.0.1"))
	if !ok || r.Device.Name != "leaf-01" || r.KeyRef != "prod_key" {
		t.Fatalf("lookup: %+v %v", r, ok)
	}
}

// TestAuthFailureDelayCeilingIsUnderEveryMeasuredDeviceTimeout pins the two
// numbers that decide whether a denial is delivered as a denial.
//
// The FAIL reply is delayed on purpose, 500ms doubling per consecutive failure
// for one `(nas, username)` pair up to this ceiling. Past a device's own
// TACACS+ reply timeout the delayed FAIL is not a denial at all: the device
// cannot tell it from an unreachable server, so it falls through to the next
// method and accepts the local password (spec §15, L13; `tests/lab/results/
// L13-*.md`). The ceiling was 5s until 2026-09-21, which was above the ~3s
// measured on both Junos images and exactly on the 5.0s measured on vEOS.
//
// 2s is under the lowest timeout measured on any of the five images, so it is
// asserted here rather than left to whoever next edits the defaults. Raising it
// is a device-behavior decision, and this test failing is where that has to be
// argued.
func TestAuthFailureDelayCeilingIsUnderEveryMeasuredDeviceTimeout(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "port49d.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.AuthFailureDelayBase != 500*time.Millisecond {
		t.Errorf("auth_failure_delay_base defaults to %v, want 500ms", c.Limits.AuthFailureDelayBase)
	}
	if c.Limits.AuthFailureDelayMax != 2*time.Second {
		t.Errorf("auth_failure_delay_max defaults to %v, want 2s. The shortest device reply timeout "+
			"measured in the lab is about 3s (spec §15, L13): a ceiling at or above it turns a denial "+
			"into a fall-through to the local password", c.Limits.AuthFailureDelayMax)
	}
	// An explicit value still wins; the default is a default, not a cap.
	c, err = Load(write(t, "explicit.yaml",
		strings.Replace(fmt.Sprintf(sample, invPath), "limits: {per_nas_connections: 4}",
			"limits: {auth_failure_delay_max: 750ms}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.AuthFailureDelayMax != 750*time.Millisecond {
		t.Errorf("an explicit auth_failure_delay_max must be honoured, got %v", c.Limits.AuthFailureDelayMax)
	}
}

func TestLoadRefusesMissingSecretAndUnknownKeyRef(t *testing.T) {
	invPath := write(t, "inventory.yaml", inv)
	if _, err := Load(write(t, "a.yaml", fmt.Sprintf(sample, invPath))); err == nil {
		t.Fatal("unset secret_env must fail")
	}
	setSecrets(t)
	bad := write(t, "inv2.yaml", "devices: []\nkey_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: nope}]\n")
	if _, err := Load(write(t, "b.yaml", fmt.Sprintf(sample, bad))); err == nil {
		t.Fatal("key_ref not in keys must fail")
	}
}

func TestLoadRefusesDeviceMatchingNoKeyGroup(t *testing.T) {
	setSecrets(t)
	// orphan's address is outside every key group's CIDR, so admission.Build
	// silently omits it from the table; Load must catch that at startup rather
	// than letting the daemon run with a device every packet from it fails.
	bad := write(t, "orphan.yaml", `
devices:
  - {name: orphan, addresses: [10.99.99.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: prod_key}
`)
	_, err := Load(write(t, "e.yaml", fmt.Sprintf(sample, bad)))
	if err == nil {
		t.Fatal("a device matching no key group must fail at load, not at the first packet")
	}
	if !strings.Contains(err.Error(), `device "orphan" matches no key group`) {
		t.Fatalf("error must name the device: %v", err)
	}
}

func TestLoadParsesDurationsAndBoundsWindows(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sample, invPath) + `
receipt_idle_ttl: 45s
context_idle_ttl: 8h
metrics_listen: "127.0.0.1:19049"
`
	body = strings.Replace(body, "limits: {per_nas_connections: 4}",
		"limits:\n  per_nas_connections: 4\n  idle_timeout: 15s\n  malformed_window: 2m\n  auth_failure_window: 3m\n", 1)
	c, err := Load(write(t, "d.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	if c.ReceiptIdleTTL != 45*time.Second || c.ContextIdleTTL != 8*time.Hour ||
		c.Limits.IdleTimeout != 15*time.Second || c.Limits.MalformedWindow != 2*time.Minute ||
		c.Limits.AuthFailureWindow != 3*time.Minute || c.MetricsListen != "127.0.0.1:19049" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadRefusesZeroOrNegativeWindows(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	for _, bad := range []string{
		"  malformed_window: 0s\n",
		"  malformed_window: -1m\n",
		"  auth_failure_window: 0s\n",
		"  auth_failure_window: -1m\n",
	} {
		body := strings.Replace(fmt.Sprintf(sample, invPath), "limits: {per_nas_connections: 4}",
			"limits:\n  per_nas_connections: 4\n"+bad, 1)
		_, err := Load(write(t, "w.yaml", body))
		if err == nil {
			t.Fatalf("%q must be refused", strings.TrimSpace(bad))
		}
		if !strings.Contains(err.Error(), "window") {
			t.Fatalf("%q: unhelpful error %v", strings.TrimSpace(bad), err)
		}
	}
}

func TestLoadRequiresLabBlock(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sample, invPath)
	body = body[:strings.Index(body, "lab:")]
	_, err := Load(write(t, "nolab.yaml", body))
	if err == nil {
		t.Fatal("a config without lab: must fail; there is no authorizer until plan 4")
	}
	if !strings.Contains(err.Error(), "lab: block is required until the policy engine lands (plan 4)") {
		t.Fatalf("error must name the missing block: %v", err)
	}
}

func TestLoadRefusesUnknownSeedTokenKind(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "kind: login}", "kind: root}", 1)
	if _, err := Load(write(t, "kind.yaml", body)); err == nil {
		t.Fatal("a seed token kind outside {login, enable} must fail")
	}
}

func TestLoadSurfacesAdmissionBuildError(t *testing.T) {
	t.Setenv("T_A", "a")
	t.Setenv("T_B", "b")
	cfg := `
listen: ":4949"
inventory_file: %s
keys:
  a_key: {current: {version: 1, secret_env: T_A}}
  b_key: {current: {version: 1, secret_env: T_B}}
lab: {session_attributes: ["priv-lvl=15"]}
`
	bad := write(t, "inv3.yaml", `
devices:
  - {name: two-faced, addresses: [127.0.0.1, 10.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: a_key}
  - {match: {cidr: 10.0.0.0/8}, key_ref: b_key}
`)
	if _, err := Load(write(t, "c.yaml", fmt.Sprintf(cfg, bad))); err == nil {
		t.Fatal("a device whose addresses resolve to different keys must fail at load")
	}
}

// loadWithPlatforms loads the sample config with a `platforms:` block spliced
// in, which is how every test below varies one thing.
func loadWithPlatforms(t *testing.T, platforms string) (Config, error) {
	t.Helper()
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sample, invPath) + platforms
	return Load(write(t, "port49d.yaml", body))
}

// TestSessionServicesDefaultPerPlatform: a config with no `platforms:` block
// resolves the built-in table, which is the whole point of the table — an
// operator who has renamed nothing configures nothing. `junos-exec` for Junos
// is the row that matters: before 2026-09-21 every Junos session
// authorization was denied `service_unsupported` (spec §15, L10).
func TestSessionServicesDefaultPerPlatform(t *testing.T) {
	c, err := loadWithPlatforms(t, "")
	if err != nil {
		t.Fatal(err)
	}
	for platform, want := range map[string]string{
		"arista_eos":    "shell",
		"cisco_nxos":    "shell",
		"cisco_iosxe":   "shell",
		"juniper_junos": "junos-exec",
	} {
		got := c.SessionServices[platform]
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: session_services = %v, want [%s]", platform, got, want)
		}
	}
}

// TestSessionServicesOverrideReplacesTheDefault. The owner's production SRX
// firewalls run `set system tacplus-options service-name junos-exec-fw`, so a
// custom name is the case this key exists for. The override replaces the
// built-in rather than adding to it, so a fleet mid-rename lists both names
// and a fleet that has finished lists one.
func TestSessionServicesOverrideReplacesTheDefault(t *testing.T) {
	c, err := loadWithPlatforms(t, `
platforms:
  juniper_junos:
    session_services: ["junos-exec-fw"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.SessionServices["juniper_junos"]; len(got) != 1 || got[0] != "junos-exec-fw" {
		t.Fatalf("the operator list must replace the built-in, got %v", got)
	}
	// An untouched platform keeps its default.
	if got := c.SessionServices["arista_eos"]; len(got) != 1 || got[0] != "shell" {
		t.Fatalf("configuring one platform must not disturb another, got %v", got)
	}
}

func TestSessionServicesOverrideTakesSeveralNames(t *testing.T) {
	c, err := loadWithPlatforms(t, `
platforms:
  juniper_junos:
    session_services: ["junos-exec", "junos-exec-fw"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.SessionServices["juniper_junos"]; len(got) != 2 || got[0] != "junos-exec" || got[1] != "junos-exec-fw" {
		t.Fatalf("a fleet mid-rename must be able to list both names, got %v", got)
	}
}

// TestPlatformsRefusesAnUnknownName: `platforms: {junos: ...}` is a typo for
// `juniper_junos`, and a block that governs no device is invisible — the
// operator would see Junos sessions denied and a configuration that plainly
// permits them. The error names what they could have typed.
func TestPlatformsRefusesAnUnknownName(t *testing.T) {
	_, err := loadWithPlatforms(t, `
platforms:
  junos:
    session_services: ["junos-exec"]
`)
	if err == nil {
		t.Fatal("an unknown platform name under platforms: must be refused at load")
	}
	if !strings.Contains(err.Error(), "junos") || !strings.Contains(err.Error(), "juniper_junos") {
		t.Fatalf("the error must name the bad key and the known platforms, got %v", err)
	}
}

// TestPlatformsRefusesAnUnknownKeyInsideABlock: strict YAML has to reach into
// the platform block too. `session_service:` for `session_services:` would
// otherwise leave the default in force with a config that says otherwise.
func TestPlatformsRefusesAnUnknownKeyInsideABlock(t *testing.T) {
	_, err := loadWithPlatforms(t, `
platforms:
  juniper_junos:
    session_service: ["junos-exec-fw"]
`)
	if err == nil {
		t.Fatal("a misspelled key inside a platform block must be refused at load")
	}
	if !strings.Contains(err.Error(), "session_service") {
		t.Fatalf("the error must name the key, got %v", err)
	}
}

// TestSessionServicesRefusesAnEmptyList. An empty list authorizes nothing, so
// every session on that platform is denied `service_unsupported` — a whole
// vendor locked out by a key that looks like it is configuring something. An
// absent key is how you ask for the default; `[]` is not.
func TestSessionServicesRefusesAnEmptyList(t *testing.T) {
	_, err := loadWithPlatforms(t, `
platforms:
  juniper_junos:
    session_services: []
`)
	if err == nil {
		t.Fatal("an empty session_services list must be refused at load")
	}
	if !strings.Contains(err.Error(), "junos-exec") {
		t.Fatalf("the error must name the default the operator probably wanted, got %v", err)
	}
}

// TestSessionServicesRefusesAnEmptyName. A `""` entry would match an
// authorization request carrying no `service` AV pair at all, which is not a
// session on any platform measured and is not something a list of service
// names can mean.
func TestSessionServicesRefusesAnEmptyName(t *testing.T) {
	_, err := loadWithPlatforms(t, `
platforms:
  juniper_junos:
    session_services: ["junos-exec", ""]
`)
	if err == nil {
		t.Fatal("an empty service name must be refused at load")
	}
}

// TestPlatformBlockWithNoFieldsKeepsTheDefault: `juniper_junos: {}` names a
// platform and sets nothing, which is not the same as setting nothing to
// nothing.
func TestPlatformBlockWithNoFieldsKeepsTheDefault(t *testing.T) {
	c, err := loadWithPlatforms(t, `
platforms:
  juniper_junos: {}
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.SessionServices["juniper_junos"]; len(got) != 1 || got[0] != "junos-exec" {
		t.Fatalf("an empty platform block must leave the default in force, got %v", got)
	}
}

// TestLabCommandAttributesParse: `lab.command_attributes` is a declared key, so
// it loads, and the strict decoder is what proves it is declared -- a key the
// struct does not carry is refused outright (TestLoadRefusesUnknownKeys), so a
// test that only asserted the value could not tell "parsed" from "silently
// ignored".
//
// It is separate from `session_attributes` because register entry L18 varies
// one at a time: the same bad attribute on a session reply and on a per-command
// reply are different questions, and a single list could not ask them apart.
func TestLabCommandAttributesParse(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath),
		`  session_attributes: ["priv-lvl=15"]`,
		`  session_attributes: ["priv-lvl=15"]`+"\n"+`  command_attributes: ["p49-nonsense*1"]`, 1)
	cfg, err := Load(write(t, "port49d.yaml", body))
	if err != nil {
		t.Fatalf("a config carrying lab.command_attributes did not load: %v", err)
	}
	if got := cfg.Lab.CommandAttributes; len(got) != 1 || got[0] != "p49-nonsense*1" {
		t.Fatalf("lab.command_attributes did not reach the config: %q", got)
	}
	if got := cfg.Lab.SessionAttributes; len(got) != 1 || got[0] != "priv-lvl=15" {
		t.Fatalf("lab.command_attributes disturbed session_attributes: %q", got)
	}
}

// TestLabCommandAttributesAreOptional: every config in this repository that
// predates the key must keep loading, and must load with the list empty rather
// than with anything invented for it.
func TestLabCommandAttributesAreOptional(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	cfg, err := Load(write(t, "port49d.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Lab.CommandAttributes; len(got) != 0 {
		t.Fatalf("a config that does not mention command_attributes should carry none, got %q", got)
	}
}

func TestReceiptBoundsDefaultAndTheOldKeyIsRefusedByName(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "c.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.ReceiptIdleTTL != 15*time.Minute || c.ReceiptMaxAge != 2*time.Hour {
		t.Fatalf("%s %s", c.ReceiptIdleTTL, c.ReceiptMaxAge)
	}
	body := fmt.Sprintf(sample, invPath) + "\nreceipt_ttl: 30s\n"
	_, err = Load(write(t, "d.yaml", body))
	if err == nil || !strings.Contains(err.Error(), "receipt_idle_ttl") || !strings.Contains(err.Error(), "receipt_max_age") {
		t.Fatalf("the removed key must name its replacements: %v", err)
	}
	body = fmt.Sprintf(sample, invPath) + "\nreceipt_idle_ttl: 3h\nreceipt_max_age: 2h\n"
	if _, err := Load(write(t, "e.yaml", body)); err == nil {
		t.Fatal("an idle TTL longer than the cap is a window that can never slide; refuse it")
	}
}
