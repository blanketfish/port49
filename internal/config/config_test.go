package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/secretref"
)

// The sample config is assembled from three pieces rather than written twice,
// because exactly one test has to load a config that names no encryption key
// and every other test must load one that does. Splitting it also puts
// `encryption:` ahead of `lab:`, so TestLoadWithoutALabBlock's truncation at
// `lab:` removes the lab block and nothing else.
const sampleKeys = `keys:
  prod_key:
    current: {version: 3, secret_ref: env:T_PROD_V3}
    accept:  [{version: 2, secret_ref: env:T_PROD_V2}]
    retired: [{version: 1, secret_ref: env:T_PROD_V1}]
`

const sampleHead = `
listen: ":4949"
inventory_file: %s
` + sampleKeys + `limits: {per_nas_connections: 4}
`

// withPolicy drops the keys: block from body, as a config with a policy has
// none: the policy file's keys: block is where the key sets live.
func withPolicy(body string) string { return strings.Replace(body, sampleKeys, "", 1) }

const sampleLab = `lab:
  session_attributes: ["priv-lvl=15"]
  seed_token_file: /tmp/p49-seeds.jsonl
  seed_tokens:
    - {nas: leaf-01, username: alice}
`

// sample is the standing config: a seed names who gets a token and carries no
// secret, and encryption is named because Load now requires it.
const sample = sampleHead + `encryption:
  current: {id: v2, secret_ref: env:PORT49_ENC_V2}
` + sampleLab

// sampleNoEncryption is sample without that block, for the one test whose
// subject is a config that never names a key.
const sampleNoEncryption = sampleHead + sampleLab

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

// setSecrets sets the RFC 8907 shared secrets the `keys:` block names. It is
// plan 1's helper and is left alone: the tests that call it directly are the
// ones whose subject is a missing shared secret.
func setSecrets(t *testing.T) {
	t.Helper()
	t.Setenv("T_PROD_V3", "three")
	t.Setenv("T_PROD_V2", "two")
	t.Setenv("T_PROD_V1", "one")
}

// setKeyEnv is setSecrets plus the encryption-at-rest secret `sample` names.
// Every test that loads `sample` needs both, and wrapping rather than editing
// setSecrets keeps the call sites whose subject is one or the other honest.
// The value is 32 repeated characters, not a key: nothing in this repository
// should carry bytes that would open a real record.
func setKeyEnv(t *testing.T) {
	t.Helper()
	setSecrets(t)
	t.Setenv("PORT49_ENC_V2", "22222222222222222222222222222222")
}

// TestLoadRefusesUnknownKeys covers the typo that costs the most: an ignored
// `per_nas_conections` is not a missing limit, it is the default 32 silently
// in force, and nothing in the log or the metrics ever says so.
func TestLoadRefusesUnknownKeys(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "per_nas_connections", "per_nas_conections", 1)
	p := write(t, "port49d.yaml", body)
	_, err := Load(p)
	if err == nil {
		t.Fatal("a misspelled config key must be refused at load")
	}
	// The line, not the key: a decode error quotes nothing from the document
	// (TestADecodeErrorQuotesNothingFromTheDocument).
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "an unknown field") {
		t.Fatalf("the error must name the file and the fault, got %v", err)
	}
}

func TestLoadAppliesDefaultsAndResolvesKeys(t *testing.T) {
	setKeyEnv(t)
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
	if len(ks.Versions) != 3 || string(ks.Versions[0].Secret.Bytes()) != "three" || !ks.Versions[2].Retired {
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
	setKeyEnv(t)
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
		t.Fatal("an unset secret_ref must fail")
	}
	setKeyEnv(t)
	bad := write(t, "inv2.yaml", "devices: []\nkey_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: nope}]\n")
	if _, err := Load(write(t, "b.yaml", fmt.Sprintf(sample, bad))); err == nil {
		t.Fatal("key_ref not in keys must fail")
	}
}

func TestLoadRefusesDeviceMatchingNoKeyGroup(t *testing.T) {
	setKeyEnv(t)
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
	setKeyEnv(t)
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
	setKeyEnv(t)
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

// Since the policy engine (plan 4) the lab: block is optional: a daemon with
// none runs the engine alone, and Lab is nil so nothing builds the lab's
// instrument by accident.
func TestLoadWithoutALabBlock(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sample, invPath)
	body = body[:strings.Index(body, "lab:")]
	c, err := Load(write(t, "nolab.yaml", body))
	if err != nil {
		t.Fatalf("a config without lab: loads: %v", err)
	}
	if c.Lab != nil {
		t.Fatalf("no lab: block is a nil Lab, got %+v", c.Lab)
	}
}

func TestLoadSurfacesAdmissionBuildError(t *testing.T) {
	t.Setenv("T_A", "a")
	t.Setenv("T_B", "b")
	t.Setenv("T_ENC", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	cfg := `
listen: ":4949"
inventory_file: %s
keys:
  a_key: {current: {version: 1, secret_ref: env:T_A}}
  b_key: {current: {version: 1, secret_ref: env:T_B}}
encryption: {current: {id: v1, secret_ref: env:T_ENC}}
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
	setKeyEnv(t)
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
	// The line, not the key: a decode error quotes nothing from the document.
	if !strings.Contains(err.Error(), "line ") || !strings.Contains(err.Error(), "an unknown field") {
		t.Fatalf("the error must say where and what, got %v", err)
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

// TestEnableUsernameMovedToThePolicyFile: the enable username is an adapter
// fact, and adapters live in the policy file since plan 5, where the offline
// tools read it as port49d does (plan 4 pre-flight N5). `principal`, the only
// value config.Load ever accepted, still starts, with a notice saying where
// the key went: refusing it would turn the upgrade into an outage for no
// gain. Any other value is refused and told the same.
func TestEnableUsernameMovedToThePolicyFile(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sample, invPath) + "\nplatforms: {cisco_iosxe: {enable_username: principal}}\n"
	c, err := Load(write(t, "c.yaml", body))
	// The sample's accept version has no retire_after, which is a notice of its own.
	if err != nil || len(c.Notices) != 2 ||
		!strings.Contains(c.Notices[0], "platforms.cisco_iosxe.enable_username moved to the policy file") {
		t.Fatalf("principal: %q %v", c.Notices, err)
	}
	for i, v := range []string{"enab", "princpal"} {
		body := fmt.Sprintf(sample, invPath) + "\nplatforms: {cisco_iosxe: {enable_username: " + v + "}}\n"
		_, err := Load(write(t, fmt.Sprintf("c%d.yaml", i), body))
		if err == nil || !strings.Contains(err.Error(), "platforms.cisco_iosxe.enable_username moved to the policy file") {
			t.Fatalf("%s: %v", v, err)
		}
		// Told to move it, the operator is told too that the value is refused
		// there, rather than learning it on the second try (task 8 review
		// minor 1).
		if refused := strings.Contains(err.Error(), "enab is refused there too"); refused != (v == "enab") {
			t.Errorf("%s: %v", v, err)
		}
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
	setKeyEnv(t)
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
	setKeyEnv(t)
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
	setKeyEnv(t)
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

func TestEncryptionKeysAndSessionDefaults(t *testing.T) {
	setKeyEnv(t) // sets PORT49_ENC_V2; the previous key is this test's own
	t.Setenv("PORT49_ENC_V1", "11111111111111111111111111111111")
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sampleNoEncryption, invPath) + `
encryption:
  current:  {id: v2, secret_ref: env:PORT49_ENC_V2}
  previous: {id: v1, secret_ref: env:PORT49_ENC_V1}
session: {staleness_ceiling: 5m}
token: {candidate_cap: 4}
`
	c, err := Load(write(t, "c.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.EncryptionKeys()
	if err != nil || k.Current.ID != "v2" || k.Previous == nil || k.Previous.ID != "v1" || k.Current.Bytes()[0] != '2' {
		t.Fatalf("%+v %v", k, err)
	}
	if k.Previous.Bytes()[0] != '1' {
		t.Fatalf("the previous key must be its own bytes, not a second copy of the current one: %+v", k.Previous)
	}
	if c.Session.StalenessCeiling != 5*time.Minute || c.Session.GraceWindow != 10*time.Minute ||
		c.Session.IndexTTL != 12*time.Hour || c.Session.MaxSessionAgeDefault != 12*time.Hour || c.Token.CandidateCap != 4 {
		t.Fatalf("%+v %+v", c.Session, c.Token)
	}
}

// TestPreviousEncryptionKeyIsOptional: a deployment that has never rotated names
// one key, and `Previous == nil` is how crypt.Keys says "nothing is being
// retired". A zero-valued Previous would be an all-zero AES-256 key that every
// read tries second.
func TestPreviousEncryptionKeyIsOptional(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "c.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	if k.Previous != nil {
		t.Fatalf("a config naming no previous key must produce none, got %+v", k.Previous)
	}
	if k.Current.ID != "v2" || k.Current.Bytes() != [32]byte([]byte("22222222222222222222222222222222")) {
		t.Fatalf("%+v", k.Current)
	}
}

func TestEncryptionKeyIsRequiredAnd32Bytes(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	if _, err := Load(write(t, "a.yaml", fmt.Sprintf(sampleNoEncryption, invPath))); err == nil {
		t.Fatal("a missing encryption block must fail at load, not at the first CHAP packet")
	}
	body := fmt.Sprintf(sampleNoEncryption, invPath) + "\nencryption: {current: {id: v2, secret_ref: env:PORT49_ENC_V2}}\n"
	// Unset, not merely short. This is the hole: a missing entry yields "",
	// copy() into a zeroed [32]byte writes nothing, and the daemon starts and
	// seals every token, receipt and context under an all-zero AES-256 key that
	// an attacker also knows — with no error and no panic.
	//
	// The assertions are this specific because the length check below ALSO
	// refuses an unset variable ("" is not 32 bytes) and also names it: without
	// pinning "is not set", deleting the unset branch entirely leaves this test
	// green and only degrades the message to "must be exactly 32 bytes … got 0".
	// An operator told their key is the wrong size goes and edits the secret;
	// what actually happened is that the unit never exported it.
	_, err := Load(write(t, "b.yaml", body))
	if err == nil {
		t.Fatal("an unset encryption secret must be refused")
	}
	// Not the variable's name: a secret pasted as secret_ref can look like one
	// (TestASecretThatIsNoRefIsNotPrinted). The file names it at this block.
	for _, want := range []string{`"v2"`, "encryption.current", "is not set"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("an unset encryption secret must be refused by name: the error must contain %q, got %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("an unset variable was reported as a length problem, which sends the operator to the wrong "+
			"file: %v", err)
	}
	t.Setenv("PORT49_ENC_V2", "too-short")
	_, err = Load(write(t, "c.yaml", body))
	if err == nil {
		t.Fatal("a non-32-byte key must be refused")
	}
	for _, want := range []string{`"v2"`, "32 bytes", "got 9"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("a short key must be refused by name and length: the error must contain %q, got %v", want, err)
		}
	}
	// A previous key is optional, but one that is named and unset is the same
	// hole: every read would try an all-zero key as its second guess.
	t.Setenv("PORT49_ENC_V2", "22222222222222222222222222222222")
	body = fmt.Sprintf(sampleNoEncryption, invPath) +
		"\nencryption:\n  current:  {id: v2, secret_ref: env:PORT49_ENC_V2}\n  previous: {id: v1, secret_ref: env:PORT49_ENC_V1}\n"
	if _, err := Load(write(t, "d.yaml", body)); err == nil || !strings.Contains(err.Error(), "encryption.previous") ||
		!strings.Contains(err.Error(), "is not set") {
		t.Fatalf("a named-but-unset previous key must be refused by its block: %v", err)
	}
}

// TestEncryptionKeyIDIsRequired: the id is written into every sealed record and
// is its AAD (internal/store/crypt). An empty one seals nothing — crypt.Seal
// refuses a zero-length id — so the daemon would start and fail the first write.
func TestEncryptionKeyIDIsRequired(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "{id: v2, secret_ref: env:PORT49_ENC_V2}",
		"{secret_ref: env:PORT49_ENC_V2}", 1)
	if _, err := Load(write(t, "c.yaml", body)); err == nil || !strings.Contains(err.Error(), "encryption.current") {
		t.Fatalf("an encryption key with no id must be refused at load: %v", err)
	}
}

// TestEncryptionRotationMustChangeTheKeyID and the half-configured previous key
// are the two ways a config can read as a rotation in progress and not be one.
// Both are silent at run time and both cost every record written under the old
// secret, which is the whole store.
func TestEncryptionRotationMustChangeTheKeyID(t *testing.T) {
	setKeyEnv(t)
	t.Setenv("PORT49_ENC_V1", "11111111111111111111111111111111")
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sampleNoEncryption, invPath) +
		"\nencryption:\n  current:  {id: v2, secret_ref: env:PORT49_ENC_V2}\n  previous: {id: v2, secret_ref: env:PORT49_ENC_V1}\n"
	if _, err := Load(write(t, "c.yaml", body)); err == nil || !strings.Contains(err.Error(), "id") {
		t.Fatalf("two keys sharing one id must be refused: the previous key would never be tried: %v", err)
	}
	// A previous key named with no secret_ref reads as a rotation and loads no
	// key at all.
	body = fmt.Sprintf(sampleNoEncryption, invPath) +
		"\nencryption:\n  current:  {id: v2, secret_ref: env:PORT49_ENC_V2}\n  previous: {id: v1}\n"
	if _, err := Load(write(t, "d.yaml", body)); err == nil || !strings.Contains(err.Error(), "secret_ref") {
		t.Fatalf("a previous key with an id and no secret_ref must be refused by name: %v", err)
	}
}

// TestKey32RefusesAShortSecretRatherThanZeroPadding is the backstop behind
// Load's length check, and it is a separate test because Load makes the case
// unreachable through the config: copy() into a zeroed array is silent, so the
// only way to prove the padding cannot happen by some other route is to call
// the thing that would do it.
func TestKey32RefusesAShortSecretRatherThanZeroPadding(t *testing.T) {
	if _, err := key32("v2", "short"); err == nil {
		t.Fatal("a short secret must be an error, never a zero-padded AES-256 key")
	}
	if _, err := key32("v2", strings.Repeat("x", 33)); err == nil {
		t.Fatal("an over-long secret must be an error, never a silent truncation")
	}
	k, err := key32("v2", strings.Repeat("x", 32))
	if err != nil || k.ID != "v2" || k.Bytes()[31] != 'x' {
		t.Fatalf("%+v %v", k, err)
	}
}

// TestStalenessCeilingDefaultsTo4h: the ceiling takes its default now that the
// broker's scheduled refresh stamps `refreshed_at` (plan 7g; OR-1).
func TestStalenessCeilingDefaultsTo4h(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "c.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Session.StalenessCeiling != DefaultStalenessCeiling {
		t.Fatalf("session.staleness_ceiling must default to 4h, got %s", c.Session.StalenessCeiling)
	}
	if c.Token.CandidateCap != 8 {
		t.Fatalf("token.candidate_cap must default to 8, got %d", c.Token.CandidateCap)
	}
	// Set, it has to be long enough to outlast a refresh interval; a sub-minute
	// ceiling is a config that denies everyone as fast as the broker can retry.
	body := fmt.Sprintf(sample, invPath) + "\nsession: {staleness_ceiling: 30s}\n"
	if _, err := Load(write(t, "d.yaml", body)); err == nil || !strings.Contains(err.Error(), "staleness_ceiling") {
		t.Fatalf("a positive staleness_ceiling under a minute must be refused by name: %v", err)
	}
	body = fmt.Sprintf(sample, invPath) + "\nsession: {staleness_ceiling: -1m}\n"
	if _, err := Load(write(t, "e.yaml", body)); err == nil {
		t.Fatal("a negative staleness_ceiling must be refused")
	}
}

func TestSessionAndTokenValuesAreRefusedWhenNotPositive(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	for _, bad := range []string{
		"\nsession: {grace_window: -1m}\n",
		"\nsession: {index_ttl: -1h}\n",
		"\nsession: {max_session_age_default: -1h}\n",
		"\ntoken: {candidate_cap: -1}\n",
	} {
		if _, err := Load(write(t, "b.yaml", fmt.Sprintf(sample, invPath)+bad)); err == nil {
			t.Fatalf("%q must be refused", strings.TrimSpace(bad))
		}
	}
}

// The behaviour change this test is named for is that a seed no longer carries
// a secret. Asserting that the parsed entries have a nas and a username would
// pass whether or not that happened — and would assert nothing at all if the
// sample carried no seeds.
func TestSeedTokensAreMintedNotWritten(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	for _, stale := range []string{
		"    - {nas: leaf-01, username: alice, secret: p49_lab}\n",
		"    - {nas: leaf-01, username: alice, kind: login}\n",
	} {
		body := strings.Replace(fmt.Sprintf(sample, invPath),
			"    - {nas: leaf-01, username: alice}\n", stale, 1)
		_, err := Load(write(t, "stale.yaml", body))
		if err == nil || !strings.Contains(err.Error(), "minted") {
			t.Fatalf("a seed carrying %q must be refused and name the minter as its replacement: %v", stale, err)
		}
	}
	body := strings.Replace(fmt.Sprintf(sample, invPath),
		"    - {nas: leaf-01, username: alice}\n", "    - {nas: leaf-01, username: alice, enable: true}\n", 1)
	c, err := Load(write(t, "c.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Lab.SeedTokens) != 1 || !c.Lab.SeedTokens[0].Enable || c.Lab.SeedTokens[0].NAS != "leaf-01" {
		t.Fatalf("%+v", c.Lab.SeedTokens)
	}
	// The yaml tags are the assertion here: without them the decoder matches
	// case-insensitively on the field name, `NAS:` loads, and the snake_case
	// rule is enforced nowhere.
	body = strings.Replace(fmt.Sprintf(sample, invPath),
		"    - {nas: leaf-01, username: alice}\n", "    - {NAS: leaf-01, Username: alice}\n", 1)
	if _, err := Load(write(t, "d.yaml", body)); err == nil {
		t.Fatal("a seed key in the wrong case must be refused; keys are snake_case")
	}
}

func TestSeedTokensRequireAFileToWriteThemTo(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "  seed_token_file: /tmp/p49-seeds.jsonl\n", "", 1)
	if _, err := Load(write(t, "c.yaml", body)); err == nil || !strings.Contains(err.Error(), "seed_token_file") {
		t.Fatalf("seeding credentials with nowhere to put them must be a load error: %v", err)
	}
	// A config that seeds nothing needs no file: the key exists for the seeds,
	// not for its own sake.
	body = strings.Replace(strings.Replace(fmt.Sprintf(sample, invPath),
		"  seed_token_file: /tmp/p49-seeds.jsonl\n", "", 1),
		"  seed_tokens:\n    - {nas: leaf-01, username: alice}\n", "", 1)
	if _, err := Load(write(t, "d.yaml", body)); err != nil {
		t.Fatalf("no seeds and no file is a valid config: %v", err)
	}
}

func TestSeedTokensRequireANASAndAUsername(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	for _, bad := range []string{
		"    - {nas: leaf-01}\n",
		"    - {username: alice}\n",
	} {
		body := strings.Replace(fmt.Sprintf(sample, invPath), "    - {nas: leaf-01, username: alice}\n", bad, 1)
		if _, err := Load(write(t, "c.yaml", body)); err == nil {
			t.Fatalf("%q must be refused", strings.TrimSpace(bad))
		}
	}
}

// The lab fault switch is read only from the `lab:` block and is off unless
// named: a config that does not mention it must load with no fault file.
func TestLabFaultFileIsOptionalAndLabOnly(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "a.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Lab.FaultFile != "" {
		t.Fatalf("fault_file defaulted to %q; it must be off unless named", c.Lab.FaultFile)
	}
	c, err = Load(write(t, "b.yaml", fmt.Sprintf(sample, invPath)+"  fault_file: /tmp/p49-fault\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Lab.FaultFile != "/tmp/p49-fault" {
		t.Fatalf("fault_file = %q", c.Lab.FaultFile)
	}
	if _, err := Load(write(t, "c.yaml", fmt.Sprintf(sample, invPath)+"fault_file: /tmp/p49-fault\n")); err == nil {
		t.Fatal("a top-level fault_file loaded; the switch belongs to the lab block only")
	}
}

// MaxSessionAge reads the one key, with Load's default, and no secret.
func TestMaxSessionAge(t *testing.T) {
	for raw, want := range map[string]time.Duration{"": DefaultMaxSessionAge,
		"session: {max_session_age_default: 8h}\n": 8 * time.Hour} {
		if got, err := MaxSessionAge([]byte(raw)); err != nil || got != want {
			t.Errorf("%q: %s %v", raw, got, err)
		}
	}
	if _, err := MaxSessionAge([]byte("session: {max_session_age_default: -1h}\n")); err == nil {
		t.Error("a negative age")
	}
	// The wrong file or a misspelled key is refused, as Load refuses it:
	// the default read in its place would be a timeout the daemon does not
	// run with, and check-config would pass against it (task 13 review I2).
	for _, raw := range []string{
		"sessions: {max_session_age_default: 8h}\n",
		"session: {max_sesion_age_default: 8h}\n",
		"subjects:\n  - {name: noc, username: noc}\n",
	} {
		if _, err := MaxSessionAge([]byte(raw)); err == nil {
			t.Errorf("%q: read", raw)
		}
	}
}

// With a broker the policy assigns keys, and a device no group admits is
// refused on its own at the policy load, never the daemon (spec §10; plan 6a
// Decided 5). Without one, TestLoadRefusesDeviceMatchingNoKeyGroup holds.
func TestWithABrokerAnOrphanIsTheDevicesProblemNotTheDaemons(t *testing.T) {
	setKeyEnv(t)
	orphan := write(t, "orphan.yaml", "devices:\n  - {name: orphan, addresses: [10.99.99.1]}\n")
	body := withPolicy(fmt.Sprintf(sample, orphan)) + "broker: {listen: \"127.0.0.1:0\", tls_cert_file: c, tls_key_file: k, " +
		"client_ca_file: ca, policy_file: p, revocations_file: r, " +
		"certificate_status: {disabled: true}}\n"
	cfg, err := Load(write(t, "f.yaml", body))
	if err != nil {
		t.Fatalf("a broker config refused an orphan device: %v", err)
	}
	if cfg.Admission != nil {
		t.Fatalf("admission %v", cfg.Admission)
	}
}

// With a broker the inventory is live and read behind the policy file's
// fence (port49d's fencedInventory, plan 6a C2), so Load does not read it at
// all: a plain read first would hang on a FIFO, or read a link to a huge file
// whole, before the fence could refuse it. An inventory fault — an address
// claimed twice — is found there, naming the file.
func TestWithABrokerLoadDoesNotReadTheInventory(t *testing.T) {
	setKeyEnv(t)
	missing := filepath.Join(t.TempDir(), "never-read.yaml")
	body := withPolicy(fmt.Sprintf(sample, missing)) + "broker: {listen: \"127.0.0.1:0\", tls_cert_file: c, tls_key_file: k, " +
		"client_ca_file: ca, policy_file: p, revocations_file: r, " +
		"certificate_status: {disabled: true}}\n"
	cfg, err := Load(write(t, "f.yaml", body))
	if err != nil {
		t.Fatalf("a broker config read inventory_file: %v", err)
	}
	if cfg.InventoryFile != missing || len(cfg.Inventory.Devices) != 0 {
		t.Fatalf("inventory_file %q, inventory %+v", cfg.InventoryFile, cfg.Inventory)
	}
}

func TestInventoryMaxRemovedPercent(t *testing.T) {
	setKeyEnv(t)
	i := write(t, "inv.yaml", inv)
	cfg, err := Load(write(t, "a.yaml", fmt.Sprintf(sample, i)))
	if err != nil || cfg.MaxRemovedPercent != 10 {
		t.Fatalf("default: %d, %v", cfg.MaxRemovedPercent, err)
	}
	cfg, err = Load(write(t, "b.yaml", fmt.Sprintf(sample, i)+"inventory: {max_removed_percent: 100}\n"))
	if err != nil || cfg.MaxRemovedPercent != 100 {
		t.Fatalf("100: %d, %v", cfg.MaxRemovedPercent, err)
	}
	if _, err := Load(write(t, "c.yaml", fmt.Sprintf(sample, i)+"inventory: {max_removed_percent: 150}\n")); err == nil {
		t.Fatal("150 loaded")
	}
}

// SIGHUP re-reads the one key (plan 6a, I1): as strictly as Load, so a typo
// is an error rather than the default, and an explicit 0 is not the default.
func TestInventoryBound(t *testing.T) {
	for body, want := range map[string]int{"": 10, "inventory: {max_removed_percent: 0}\n": 0,
		"inventory: {max_removed_percent: 35}\n": 35} {
		if got, err := InventoryBound([]byte(body)); err != nil || got != want {
			t.Fatalf("%q: %d, %v", body, got, err)
		}
	}
	for _, body := range []string{"inventory: {max_removed_percnt: 35}\n", "inventory: {max_removed_percent: -1}\n"} {
		if _, err := InventoryBound([]byte(body)); err == nil {
			t.Fatalf("%q read", body)
		}
	}
}

// retire_after is a date, admitting through that day UTC (plan 6a Decided 7),
// on accept versions only; a passed one and a missing one are said at start.
func TestRetireAfter(t *testing.T) {
	setKeyEnv(t)
	i := write(t, "inv.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, i), "accept:  [{version: 2, secret_ref: env:T_PROD_V2}]",
		"accept:  [{version: 2, secret_ref: env:T_PROD_V2, retire_after: 2000-01-01}]", 1)
	cfg, err := Load(write(t, "a.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC); !cfg.Keys["prod_key"].Accept[0].RetireAt.Equal(want) {
		t.Fatalf("RetireAt %v", cfg.Keys["prod_key"].Accept[0].RetireAt)
	}
	if !strings.Contains(strings.Join(cfg.Notices, "\n"), "retire_after 2000-01-01 has passed") {
		t.Fatalf("notices: %q", cfg.Notices)
	}
	if ks := cfg.Keyring()["prod_key"]; !ks.Versions[1].RetireAt.Equal(cfg.Keys["prod_key"].Accept[0].RetireAt) {
		t.Fatal("the keyring does not carry the date")
	}
	cfg, err = Load(write(t, "b.yaml", fmt.Sprintf(sample, i)))
	if err != nil || !strings.Contains(strings.Join(cfg.Notices, "\n"), "has no retire_after") {
		t.Fatalf("a missing date: %q, %v", cfg.Notices, err)
	}
	for _, bad := range []string{
		strings.Replace(fmt.Sprintf(sample, i), "current: {version: 3, secret_ref: env:T_PROD_V3}",
			"current: {version: 3, secret_ref: env:T_PROD_V3, retire_after: 2999-01-01}", 1),
		strings.Replace(body, "retire_after: 2000-01-01", "retire_after: soon", 1),
		strings.Replace(fmt.Sprintf(sample, i), "retired: [{version: 1, secret_ref: env:T_PROD_V1}]",
			"retired: [{version: 1, secret_ref: env:T_PROD_V1, retire_after: 2999-01-01}]", 1),
	} {
		if _, err := Load(write(t, "c.yaml", bad)); err == nil {
			t.Fatalf("loaded: %s", bad)
		}
	}
}

// The secrets the leak tests paste into port49d.yaml: one with punctuation,
// one an anchor or tag can hold, and one carrying a backtick.
const (
	leakDash  = "Sx9-qT4v!Lm2@pR7zK0w#Yh5"
	leakAlnum = "Qa8ZmN3tBv6cXe1Wr4Ju"
	leakTick  = "K`p7Rw2!Hd9@Tg4#Vn6$Fj3"
)

// leakShapes are the ways an operator can paste a secret into port49d.yaml's
// keys block that yaml.v3 or the key checks could quote back.
var leakShapes = []struct{ name, body, secret string }{
	{"a value where a mapping goes", "keys:\n  prod_key:\n    current: " + leakDash + "\n", leakDash},
	{"a value where a number goes", "keys:\n  prod_key:\n    current: {version: " + leakAlnum + ", secret_ref: env:T_PROD_V3}\n", leakAlnum},
	{"the secret as a key", "keys:\n  prod_key:\n    current:\n      version: 3\n      secret_ref: env:T_PROD_V3\n      " +
		leakDash + ": x\n", leakDash},
	{"the secret as a flow key", "keys:\n  prod_key:\n    current: {version: 3, " + leakAlnum + "}\n", leakAlnum},
	{"the secret in retire_after", "keys:\n  prod_key:\n    current: {version: 3, secret_ref: env:T_PROD_V3}\n" +
		"    accept: [{version: 2, secret_ref: env:T_PROD_V2, retire_after: \"" + leakDash + "\"}]\n", leakDash},
	{"the secret as an anchor", "keys:\n  prod_key:\n    current: *" + leakAlnum + "\n", leakAlnum},
	{"the secret as a tag", "keys:\n  prod_key:\n    current: !" + leakAlnum + " x\n", leakAlnum},
	{"the secret with a backtick", "keys:\n  prod_key:\n    current: " + leakTick + "\n", leakTick},
	{"the secret in secret_ref", "keys:\n  prod_key:\n    current: {version: 3, secret_ref: \"" + leakDash + "\"}\n", leakDash},
	{"the secret in an unclosed quote", "keys:\n  prod_key:\n    current: {version: 3, secret_ref: \"" + leakDash + "\n", leakDash},
}

// leaked is the first form of secret found in out, or "": the secret in any
// case, quoted or escaped, as hex or base64, or any five characters of it (a
// yaml.v3 error quotes a value's first seven).
func leaked(out, secret string) string {
	forms := []string{fmt.Sprintf("%q", secret), hex.EncodeToString([]byte(secret)),
		base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret))}
	for i := 0; i+5 <= len(secret); i++ {
		forms = append(forms, secret[i:i+5])
	}
	low := strings.ToLower(out)
	for _, f := range forms {
		if strings.Contains(low, strings.ToLower(f)) {
			return f
		}
	}
	return ""
}

// A port49d.yaml decode error names the file, the line and a fixed category,
// never text from the document: a secret pasted where the file names only its
// environment variable would reach the log and a terminal.
func TestADecodeErrorQuotesNothingFromTheDocument(t *testing.T) {
	for _, sh := range leakShapes {
		t.Run(sh.name, func(t *testing.T) {
			p := write(t, "port49d.yaml", sh.body)
			_, loadErr := Load(p)
			_, setsErr := KeySecretRefsOf([]byte(sh.body))
			_, ageErr := MaxSessionAge([]byte(sh.body))
			_, boundErr := InventoryBound([]byte(sh.body))
			for name, err := range map[string]error{"Load": loadErr, "KeySecretRefsOf": setsErr, "MaxSessionAge": ageErr,
				"InventoryBound": boundErr} {
				if err == nil {
					continue // the shape is one only the key checks see
				}
				if f := leaked(err.Error(), sh.secret); f != "" {
					t.Errorf("%s printed %q: %v", name, f, err)
				}
			}
		})
	}
}

// The error still says where: the file, the line and what kind of fault.
func TestADecodeErrorSaysWhereAndWhat(t *testing.T) {
	cases := []struct{ body, want string }{
		{"keys:\n  prod_key:\n    current: x\n", "line 3: a value of the wrong type"},
		{"keys:\n  prod_key:\n    current: {version: 3, secret_ref: env:A}\n    bogus: 1\n", "line 4: an unknown field"},
		{"keys:\n  prod_key:\n    current: *nope\n", "an unknown anchor or alias"},
		{"keys: [\n", "a yaml syntax error"},
	}
	for _, c := range cases {
		p := write(t, "port49d.yaml", c.body)
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want the file and %q, got %v", c.want, err)
		}
	}
}

// A secret_ref is parsed before it is looked up, so a secret pasted there is
// refused by its key and never printed as a variable that is not set.
func TestASecretThatIsNoRefIsNotPrinted(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	for _, name := range []string{"PORT49_ENC_V2", "T_PROD_V3"} {
		for _, pasted := range []string{leakDash, leakAlnum} {
			body := strings.Replace(fmt.Sprintf(sample, invPath), "secret_ref: env:"+name, `secret_ref: "`+pasted+`"`, 1)
			_, err := Load(write(t, "port49d.yaml", body))
			if err == nil || !strings.Contains(err.Error(), "secret_ref") || !strings.Contains(err.Error(), "is not a secret reference") {
				t.Fatalf("%s: want the reference refused, got %v", name, err)
			}
			if f := leaked(err.Error(), pasted); f != "" {
				t.Fatalf("%s: printed %q: %v", name, f, err)
			}
		}
	}
}

// A key_ref is a name the reports print, so one that is not a name, most
// likely a secret pasted as the key, is refused at load without being printed.
func TestAKeyRefThatIsNoNameIsRefusedUnprinted(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	// A second key beside prod_key, so the load gets as far as the start
	// notices, which name every key with no retire_after.
	body := strings.Replace(fmt.Sprintf(sample, invPath), "limits:", "  "+leakAlnum+":\n"+
		"    current: {version: 5, secret_ref: env:T_PROD_V3}\n    accept: [{version: 4, secret_ref: env:T_PROD_V2}]\nlimits:", 1)
	c, err := Load(write(t, "port49d.yaml", body))
	if err == nil || !strings.Contains(err.Error(), "on line 9 is not a valid key_ref name") {
		t.Fatalf("want the key_ref refused by line, got %v (notices %q)", err, c.Notices)
	}
	if f := leaked(err.Error()+strings.Join(c.Notices, "\n"), leakAlnum); f != "" {
		t.Fatalf("printed %q: %v", f, err)
	}
}

// Without a broker every device must be admitted at start, so a pin that is
// not a key_ref name refuses the start, without printing the pin.
func TestANoBrokerPinThatIsNoNameIsRefusedUnprinted(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", strings.Replace(inv, "key_groups:", "  - {name: pasted, platform: arista_eos, "+
		"addresses: [127.0.0.9], key_ref: "+leakAlnum+"}\nkey_groups:", 1))
	_, err := Load(write(t, "port49d.yaml", fmt.Sprintf(sample, invPath)))
	if err == nil || !strings.Contains(err.Error(), "not a valid key_ref name") || leaked(err.Error(), leakAlnum) != "" {
		t.Fatalf("%v", err)
	}
}

// session.ceiling_warning defaults to 30m, an explicit 0s turns it off, and
// above 24h is refused by name (spec §5.6; decision 33).
func TestCeilingWarning(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "a.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Session.CeilingWarning != 30*time.Minute || c.Session.CeilingWarningPlatforms != nil {
		t.Fatalf("default: %s %v", c.Session.CeilingWarning, c.Session.CeilingWarningPlatforms)
	}
	body := fmt.Sprintf(sample, invPath) + "\nsession: {ceiling_warning: 0s, ceiling_warning_platforms: [arista_eos, cisco_nxos]}\n"
	if c, err = Load(write(t, "b.yaml", body)); err != nil || c.Session.CeilingWarning != 0 ||
		len(c.Session.CeilingWarningPlatforms) != 2 {
		t.Fatalf("0s: %v %s %v", err, c.Session.CeilingWarning, c.Session.CeilingWarningPlatforms)
	}
	body = fmt.Sprintf(sample, invPath) + "\nsession: {ceiling_warning: 45m, grace_window: 5m}\n"
	if c, err = Load(write(t, "c.yaml", body)); err != nil || c.Session.CeilingWarning != 45*time.Minute ||
		c.Session.GraceWindow != 5*time.Minute {
		t.Fatalf("45m: %v %s %s", err, c.Session.CeilingWarning, c.Session.GraceWindow)
	}
	for _, bad := range []string{"{ceiling_warning: 25h}", "{ceiling_warning: -1m}"} {
		body = fmt.Sprintf(sample, invPath) + "\nsession: " + bad + "\n"
		if _, err := Load(write(t, "d.yaml", body)); err == nil || !strings.Contains(err.Error(), "session.ceiling_warning") {
			t.Fatalf("%s must be refused naming the key: %v", bad, err)
		}
	}
	for _, bad := range []string{"{ceiling_warning_platforms: [\"\"]}", "{ceiling_warning_platforms: [\"Arista EOS\"]}"} {
		body = fmt.Sprintf(sample, invPath) + "\nsession: " + bad + "\n"
		if _, err := Load(write(t, "e.yaml", body)); err == nil || !strings.Contains(err.Error(), "session.ceiling_warning_platforms") {
			t.Fatalf("%s must be refused naming the key: %v", bad, err)
		}
	}
	// MaxSessionAge decodes the same file shape, so the key is known there too.
	if _, err := MaxSessionAge([]byte("session: {ceiling_warning: 10m}\n")); err != nil {
		t.Fatal(err)
	}
}

// lab.deny_message_length is 0 or 16 to 4096; lab.deny_session is read
// (spec §15, L2; plan 7b).
func TestLabDenyMessageLength(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := fmt.Sprintf(sample, invPath) + "  deny_message_length: 300\n  deny_session: true\n"
	c, err := Load(write(t, "a.yaml", body))
	if err != nil || c.Lab.DenyMessageLength != 300 || !c.Lab.DenySession {
		t.Fatalf("%v %+v", err, c.Lab)
	}
	for _, n := range []string{"8", "5000", "-1"} {
		body := fmt.Sprintf(sample, invPath) + "  deny_message_length: " + n + "\n"
		if _, err := Load(write(t, "b.yaml", body)); err == nil || !strings.Contains(err.Error(), "lab.deny_message_length") {
			t.Fatalf("%s must be refused naming the key: %v", n, err)
		}
	}
}

// RevocationsFile reads the one path init-revocations needs, as strictly as
// Load decodes, resolves no secret, and refuses a path Load would refuse as
// another file port49d uses (pre-flight M10).
func TestRevocationsFileReadsThePathAlone(t *testing.T) {
	got, err := RevocationsFile([]byte("broker:\n  revocations_file: /var/lib/port49/revocations.json\n"))
	if err != nil || got != "/var/lib/port49/revocations.json" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := RevocationsFile([]byte("broker:\n  revocation_file: x\n")); err == nil {
		t.Fatal("a misspelt key was read as no path")
	}
	if _, err := RevocationsFile([]byte("listen: 127.0.0.1:49\n")); err == nil ||
		!strings.Contains(err.Error(), "no broker.revocations_file") {
		t.Fatalf("no broker: %v", err)
	}
}

// sampleWithKeyID is sample with encryption.current's id replaced by the
// YAML scalar id, and the previous block added when prev is not empty.
func sampleWithKeyID(t *testing.T, id, prev string) string {
	t.Helper()
	body := fmt.Sprintf(sample, write(t, "inv.yaml", inv))
	if !strings.Contains(body, "id: v2,") {
		t.Fatal("sample no longer names id v2: the test would replace nothing")
	}
	body = strings.Replace(body, "id: v2,", "id: "+id+",", 1)
	if prev != "" {
		body = strings.Replace(body, "encryption:\n", "encryption:\n  previous: "+prev+"\n", 1)
	}
	return body
}

// An encryption key id is sealed into every record's header and named by
// every line about one that will not open, which prints only the key-id
// charset (crypt.LineKeyID). One outside it is refused at load, naming the
// block and never echoing the id (plan 7e, Ruling 15), whether or not the
// block names a secret_ref (pre-flight M6).
func TestAnEncryptionKeyIDOutsideTheCharsetIsRefused(t *testing.T) {
	for _, id := range []string{"has space", "semi;colon", "émoji", strings.Repeat("a", 65), "new\nline"} {
		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
			setKeyEnv(t)
			_, err := Load(write(t, "port49d.yaml", sampleWithKeyID(t, fmt.Sprintf("%q", id), "")))
			if err == nil || !strings.Contains(err.Error(), "encryption.current: id must be 1 to 64 of") {
				t.Fatalf("an id %q loaded, or the refusal does not say why: %v", id, err)
			}
			if strings.Contains(err.Error(), id) {
				t.Fatalf("the refusal echoes the id: %v", err)
			}
			// A previous block naming the id and no secret_ref took the
			// branch that echoed it with %q before the shape was checked.
			_, err = Load(write(t, "port49d.yaml", sampleWithKeyID(t, "v2", fmt.Sprintf("{id: %q}", id))))
			if err == nil || !strings.Contains(err.Error(), "encryption.previous: id must be 1 to 64 of") ||
				strings.Contains(err.Error(), id) {
				t.Fatalf("a previous id %q with no secret_ref: %v", id, err)
			}
		})
	}
	for _, id := range []string{"v2", "2026-10.key_A", strings.Repeat("a", 64)} {
		setKeyEnv(t)
		if _, err := Load(write(t, "port49d.yaml", sampleWithKeyID(t, id, ""))); err != nil {
			t.Fatalf("an id %q in the charset was refused: %v", id, err)
		}
	}
}

// With the broker in the process, on memory, Config.Policy is
// broker.policy_file and its interval: the code reads one field whichever
// block named the policy (plan 7e, Ruling 2).
func TestAnInProcessBrokerSetsThePolicy(t *testing.T) {
	c, err := loadWith(t, brokerBlock+"  policy_watch_interval: 30s\n")
	if err != nil || c.Policy == nil || c.Policy.File != "/etc/port49/policy.yaml" ||
		c.Policy.WatchInterval != 30*time.Second || c.Admission != nil {
		t.Fatalf("%+v %v", c.Policy, err)
	}
	if c, err := loadWith(t, ""); err != nil || c.Policy != nil {
		t.Fatalf("no broker and no policy: %+v %v", c.Policy, err)
	}
}

// policy: beside a broker: block is two policies: the in-process broker's
// is broker.policy_file, so policy: is refused, named.
func TestPolicyIsRefusedBesideABrokerBlock(t *testing.T) {
	if _, err := loadWith(t, brokerBlock+"policy: {file: /etc/port49/p.yaml}\n"); err == nil ||
		!strings.Contains(err.Error(), "policy:") {
		t.Fatalf("policy: beside broker: %v", err)
	}
}

// session.staleness_ceiling defaults to 4h now that the scheduled refresh
// stamps refreshed_at (plan 2's hand-off; OR-1); 0s is off and said.
func TestTheStalenessCeilingDefault(t *testing.T) {
	c, err := loadWith(t, "") // no session: block
	if err != nil || c.Session.StalenessCeiling != DefaultStalenessCeiling || c.StalenessOff {
		t.Fatalf("%v %v %v", c.Session.StalenessCeiling, c.StalenessOff, err)
	}
	c, err = loadWith(t, "session: {staleness_ceiling: 0s}")
	if err != nil || c.Session.StalenessCeiling != 0 || !c.StalenessOff {
		t.Fatalf("explicit 0s: %v %v %v", c.Session.StalenessCeiling, c.StalenessOff, err)
	}
	if _, err := loadWith(t, "session: {staleness_ceiling: 30s}"); err == nil ||
		!strings.Contains(err.Error(), "set it to 0s to disable") {
		t.Fatalf("under a minute: %v", err)
	}
}

// brokerDirectory is a broker block with refresh_interval and a directory
// whose grace are the arguments.
func brokerDirectory(t *testing.T, refresh, grace string) string {
	t.Helper()
	ca := writeTemp(t, "ca.pem", testCAPEM(t))
	t.Setenv("PORT49_LDAP_PASSWORD", "x")
	return strings.Replace(brokerBlock, "  certificate_status: {disabled: true}\n", `  certificate_status: {disabled: true}
  refresh_interval: `+refresh+`
  directory:
    servers:
      - {uri: "ldaps://dc-01.corp.example.com", priority: 100}
    ca_file: `+ca+`
    bind: {mechanism: simple, bind_dn: "CN=port49,DC=corp", password_secret_ref: env:PORT49_LDAP_PASSWORD}
    base_dn: "DC=corp,DC=example,DC=com"
    certificate_mapping: {kind: issuer_serial}
    nested_groups: in_chain
    grace: `+grace+`
`, 1)
}

// In one process, the refresh must fit the ceiling twice, and grace must
// not outlive it (Ruling 14).
func TestOneProcessChecksRefreshAndGraceAgainstTheCeiling(t *testing.T) {
	for _, c := range []struct{ session, refresh, grace, want string }{
		{"session: {staleness_ceiling: 8m}\n", "5m", "1m",
			"broker.refresh_interval 5m0s: above half session.staleness_ceiling (8m0s); a context would go stale between two passes"},
		{"session: {staleness_ceiling: 1h}\n", "5m", "2h",
			"broker.directory.grace 2h0m0s: above session.staleness_ceiling (1h0m0s), a grace mint would be stale at its first command"},
	} {
		if _, err := loadWith(t, c.session+brokerDirectory(t, c.refresh, c.grace)); err == nil ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%v, want %q", err, c.want)
		}
	}
	// The default ceiling (4h) holds the defaults, and a ceiling of 0s compares nothing.
	if _, err := loadWith(t, brokerDirectory(t, "5m", "4h")); err != nil {
		t.Errorf("defaults: %v", err)
	}
	if _, err := loadWith(t, "session: {staleness_ceiling: 0s}\n"+brokerDirectory(t, "1h", "24h")); err != nil {
		t.Errorf("an off ceiling: %v", err)
	}
}

// port49-broker's load shares the schema but never applies the ceiling, so
// the one-process checks never refuse a split deployment's broker file
// (pre-flight I-15): grace 8h loads there, with the ceiling's default 4h.
func TestTheBrokersLoadSkipsTheOneProcessChecks(t *testing.T) {
	ca := writeTemp(t, "ca.pem", testCAPEM(t))
	t.Setenv("PORT49_LDAP_PASSWORD", "x")
	raw := strings.Replace(brokerRoleYAML(t), "  certificate_status: {disabled: true}\n",
		`  certificate_status: {disabled: true}
  refresh_interval: 1h
  directory:
    servers:
      - {uri: "ldaps://dc-01.corp.example.com", priority: 100}
    ca_file: `+ca+`
    bind: {mechanism: simple, bind_dn: "CN=port49,DC=corp", password_secret_ref: env:PORT49_LDAP_PASSWORD}
    base_dn: "DC=corp,DC=example,DC=com"
    certificate_mapping: {kind: issuer_serial}
    nested_groups: in_chain
    grace: 8h
`, 1)
	c, err := loadBrokerRole(t, raw)
	if err != nil || c.Broker.Directory == nil || c.Broker.Directory.Grace != 8*time.Hour {
		t.Fatalf("port49-broker.yaml with grace 8h: %v", err)
	}
}

// A TLS device takes no key, so no key group, no pin and no held key can
// refuse the start for it (decision 50 rulings 3, 18).
func TestNoBrokerModeAdmitsATLSDeviceWithNoKeyGroup(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", strings.Replace(inv, "key_groups:",
		"  - {name: tls-1, platform: arista_eos, addresses: [10.0.0.9], transport: tls, key_ref: absent_key}\n"+
			"  - {name: tls-2, platform: arista_eos, addresses: [10.0.0.10], transport: tls, key_ref: \"not a name!\"}\n"+
			"key_groups:", 1))
	c, err := Load(write(t, "port49d.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatalf("a TLS device with no key group refused the start: %v", err)
	}
	for _, a := range []string{"10.0.0.9", "10.0.0.10"} {
		if r, ok := c.Admission.Lookup(netip.MustParseAddr(a)); !ok || r.Refused != "" || r.KeyRef != "" {
			t.Fatalf("%s: %+v %v", a, r, ok)
		}
	}
}

// A second YAML document in port49d.yaml is refused, not ignored, by Load and
// by every reader of the file's bytes (plan 6b final review Minor 7;
// decision 53 ruling 6). The refusal quotes nothing after the separator.
func TestASecondYAMLDocumentIsRefused(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	raw := fmt.Sprintf(sample, invPath) + "---\nlimits: {per_nas_connections: 9999}\n"
	p := write(t, "port49d.yaml", raw)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "more than one YAML document") ||
		strings.Contains(err.Error(), "9999") {
		t.Fatalf("Load: %v", err)
	}
	for name, read := range map[string]func([]byte) error{
		"MaxSessionAge":      func(b []byte) error { _, err := MaxSessionAge(b); return err },
		"InventoryBound":     func(b []byte) error { _, err := InventoryBound(b); return err },
		"RevocationsFile":    func(b []byte) error { _, err := RevocationsFile(b); return err },
		"KeySecretRefsOf":    func(b []byte) error { _, err := KeySecretRefsOf(b); return err },
		"InventoryServiceOf": func(b []byte) error { _, err := InventoryServiceOf(b); return err },
		"StoresBlocks":       func(b []byte) error { _, err := StoresBlocks(b); return err },
	} {
		if err := read([]byte(raw)); err == nil || !strings.Contains(err.Error(), "more than one YAML document") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every secret in port49d.yaml is named by secret_ref (decision 53 ruling 1):
// a file: key and a file: encryption key load as their variables did.
func TestSecretsLoadFromFiles(t *testing.T) {
	setKeyEnv(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // the fence refuses a directory the group can write
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "enc")
	if err := os.WriteFile(enc, []byte("22222222222222222222222222222222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k3 := filepath.Join(dir, "k3")
	if err := os.WriteFile(k3, []byte("three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(strings.Replace(fmt.Sprintf(sample, invPath), "env:PORT49_ENC_V2", "file:"+enc, 1),
		"env:T_PROD_V3", "file:"+k3, 1)
	c, err := Load(write(t, "port49d.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Keyring()["prod_key"].Versions[0].Secret.Bytes(); string(got) != "three" {
		t.Fatalf("the file: key: got %d bytes, want 5", len(got)) // never the value
	}
	if _, err := c.EncryptionKeys(); err != nil {
		t.Fatalf("the file: encryption key: %v", err)
	}
}

// secret_env and password_env are gone: refused, naming the replacement and
// the line, never loaded (no deprecation before beta: a refusal, not an
// alias). An operator upgrading four files at once is told what to write.
func TestARemovedSecretKeyIsRefusedNamingItsReplacement(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "secret_ref: env:T_PROD_V3", "secret_env: T_PROD_V3", 1)
	_, err := Load(write(t, "port49d.yaml", body))
	if err == nil || !strings.Contains(err.Error(), "secret_env was replaced by secret_ref") ||
		!strings.Contains(err.Error(), "line ") {
		t.Fatalf("%v", err)
	}
	body = strings.Replace(fmt.Sprintf(sample, invPath), "secret_ref: env:T_PROD_V3", "password_env: T_PROD_V3", 1)
	if _, err := Load(write(t, "port49d.yaml", body)); err == nil ||
		!strings.Contains(err.Error(), "password_env was replaced by password_secret_ref") {
		t.Fatalf("%v", err)
	}
	if _, err := KeySecretRefsOf([]byte("keys:\n  k: {current: {version: 1, secret_env: X}}\n")); err == nil ||
		!strings.Contains(err.Error(), "secret_env was replaced by secret_ref") {
		t.Fatalf("a reader of the file's bytes: %v", err)
	}
}

// A secret pasted where the reference goes is refused by its key, unprinted.
func TestAPastedSecretInSecretRefIsNotPrinted(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "env:PORT49_ENC_V2", "hunter2hunter2hunter2hunter2hunt", 1)
	_, err := Load(write(t, "port49d.yaml", body))
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal carries the pasted secret")
	}
	if err == nil || !strings.Contains(err.Error(), "encryption.current.secret_ref") {
		t.Fatalf("%v", err)
	}
}

// A Config that is printed or logged carries no key material: fmt prints
// unexported fields, so the resolved secrets are held as secretref.Secret,
// which prints as <redacted> under every verb.
func TestAPrintedConfigCarriesNoSecret(t *testing.T) {
	setKeyEnv(t)
	const device, enc = "fake-device-key-zzz-1", "fake-encryption-key-32-bytes!!!!"
	t.Setenv("T_PROD_V3", device)
	t.Setenv("PORT49_ENC_V2", enc)
	c, err := Load(write(t, "port49d.yaml", fmt.Sprintf(sample, write(t, "inventory.yaml", inv))))
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(verb, c)
		if strings.Contains(out, device) || strings.Contains(out, enc) {
			t.Errorf("a Config printed with %s carries a resolved secret", verb) // the verb, never the value
		}
	}
}

// ResolveSecret names the key the caller reads, not a fixed one.
func TestResolveSecretNamesTheCallersKey(t *testing.T) {
	_, err := Config{}.ResolveSecret("keys.k.current.secret_ref", "env:T_RESOLVE_SECRET_UNSET")
	if err == nil || !strings.Contains(err.Error(), "keys.k.current.secret_ref the environment variable it names is not set") ||
		strings.Contains(err.Error(), "T_RESOLVE_SECRET_UNSET") || strings.Contains(err.Error(), "bind") {
		t.Fatalf("%v", err)
	}
}

// Keyring hands out copies: a write through a returned secret changes nothing
// the next swap reads.
func TestKeyringReturnsCopies(t *testing.T) {
	setKeyEnv(t)
	c, err := Load(write(t, "port49d.yaml", fmt.Sprintf(sample, write(t, "inventory.yaml", inv))))
	if err != nil {
		t.Fatal(err)
	}
	// current, accept and retired versions alike
	for i, v := range c.Keyring()["prod_key"].Versions {
		want := string(v.Secret.Bytes())
		v.Secret.Bytes()[0] ^= 0xff
		if got := c.Keyring()["prod_key"].Versions[i].Secret.Bytes(); string(got) != want {
			t.Fatalf("a write through version %d's returned secret changed the next Keyring (%d bytes)", i, len(got))
		}
	}
}

// keys: beside a policy is refused: the policy's keys: block is the one in
// force (decision 53 ruling 3); and port49-broker.yaml's key_refs is gone.
func TestKeysBesideAPolicyIsRefused(t *testing.T) {
	base := daemonRoleYAML(t)
	for name, keys := range map[string]string{
		"a block": sampleKeys,
		"empty":   "keys: {}\n",
	} {
		raw := withPolicy(base) + keys
		_, err := loadDaemonRole(t, raw)
		if err == nil || !strings.Contains(err.Error(), "keys: is the policy file's") {
			t.Errorf("%s: %v", name, err)
		}
	}
	raw := strings.Replace(brokerRoleYAML(t), "inventory_file:", "key_refs: [k]\ninventory_file:", 1)
	if _, err := loadBrokerRole(t, raw); err == nil ||
		!strings.Contains(err.Error(), "key_refs was replaced by the policy's keys: block") {
		t.Errorf("key_refs in port49-broker.yaml: %v", err)
	}
}

// A port49d.yaml secret a policy could name is refused (decision 53 ruling
// 12): the allowance and port49d.yaml's own secrets never meet.
func TestAConfigSecretInsideTheAllowanceIsRefused(t *testing.T) {
	base := withPolicy(daemonRoleYAML(t))
	for name, c := range map[string]struct{ raw, want string }{
		"the encryption secret": {strings.Replace(base, "env:PORT49_ENC_V2", "env:PORT49_KEY_ENC", 1),
			"is inside key_secret_refs"},
		"an env_prefix that is no name": {base + "key_secret_refs: {env_prefix: P}\n", "env_prefix"},
		"the bind password": {withPolicy(fmt.Sprintf(sample, write(t, "inv.yaml", inv))) + strings.Replace(brokerBlock, "  certificate_status: {disabled: true}\n",
			"  certificate_status: {disabled: true}\n  directory:\n    servers:\n"+
				"      - {uri: \"ldaps://dc-01.corp.example.com\", priority: 100}\n    ca_file: "+
				writeTemp(t, "ca.pem", testCAPEM(t))+"\n    bind: {mechanism: simple, bind_dn: \"CN=port49,DC=corp\", "+
				"password_secret_ref: env:PORT49_KEY_BIND}\n    base_dn: \"DC=corp,DC=example,DC=com\"\n"+
				"    certificate_mapping: {kind: issuer_serial}\n    nested_groups: in_chain\n", 1),
			"is inside key_secret_refs"},
	} {
		setKeyEnv(t)
		t.Setenv("PORT49_KEY_ENC", "22222222222222222222222222222222")
		t.Setenv("PORT49_KEY_BIND", "bind-not-printed")
		_, err := Load(write(t, "port49d.yaml", c.raw))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	raw := strings.Replace(brokerRoleYAML(t), "inventory_file:", "key_secret_refs: {file_dir: /run/k}\ninventory_file:", 1)
	if _, err := loadBrokerRole(t, raw); err == nil || !strings.Contains(err.Error(), "key_secret_refs") {
		t.Errorf("key_secret_refs in port49-broker.yaml: %v", err)
	}
}

// Links and neighbours (re-review N1): the overlap is judged on resolved
// paths, and a name that merely shares a prefix is not inside.
func TestAKeyFileNeedsNoTextMatchToOverlapTheAllowance(t *testing.T) {
	setKeyEnv(t)
	real := filepath.Join(safeTemp(t), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(safeTemp(t), "keys")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(real, "enc")
	if err := os.WriteFile(enc, []byte("22222222222222222222222222222222"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(withPolicy(daemonRoleYAML(t)), "env:PORT49_ENC_V2", "file:"+enc, 1) +
		"key_secret_refs: {file_dir: " + link + "}\n"
	if _, err := Load(write(t, "port49d.yaml", raw)); err == nil || !strings.Contains(err.Error(), "is inside key_secret_refs") {
		t.Errorf("a link to the key directory: %v", err)
	}
	for name, c := range map[string]struct{ dir, want string }{
		"the key under file_dir": {"DIR", "overlaps key_secret_refs.file_dir"},
		"a neighbour":            {"DIR/srv.k", ""},
	} {
		p := tlsBase(t, "listen: 127.0.0.1:0\n",
			tlsMinimal+"policy: {file: /etc/port49/policy.yaml}\nkey_secret_refs: {file_dir: "+c.dir+"}\n")
		_, err := Load(p)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// KeySecretRefsOf reads key_secret_refs alone, defaulted and checked, with no
// secret read (Task 8): what `port49 policy test --config` holds a policy to.
func TestKeySecretRefsOfReadsTheAllowanceAlone(t *testing.T) {
	got, err := KeySecretRefsOf([]byte("listen: \":49\"\n"))
	if err != nil || got != secretref.DefaultAllowance {
		t.Fatalf("no block: %+v, %v", got, err)
	}
	got, err = KeySecretRefsOf([]byte("key_secret_refs: {env_prefix: PORT49_ENC_}\n"))
	if err != nil || got.EnvPrefix != "PORT49_ENC_" || got.FileDir != secretref.DefaultAllowance.FileDir {
		t.Fatalf("a prefix: %+v, %v", got, err)
	}
	for _, bad := range []string{"key_secret_refs: {env_prefix: PORT49_KEY}\n", "key_secret_refs: {file_dir: keys}\n",
		"key_secret_refs: {file_dirr: /k}\n"} {
		if _, err := KeySecretRefsOf([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A secret pasted where an env: name goes parses as a name, so no error from
// port49d.yaml's own references, or the broker's bind password, names the
// variable (plan 6a Task 15; Task 9 re-review I1).
func TestAPastedSecretAsAnEnvNameIsNeverPrinted(t *testing.T) {
	const pasted = "FAKEtoken0123456789abcdef0123456789abcdef"
	c := Config{Secrets: secretref.New(), secrets: map[string]secretref.Secret{}}
	for name, err := range map[string]error{
		"resolveInto": c.resolveInto("encryption.current.secret_ref", "env:"+pasted),
		"ResolveSecret": func() error {
			_, err := Config{}.ResolveSecret("broker.directory.bind.password_secret_ref", "env:"+pasted)
			return err
		}(),
	} {
		if err == nil || strings.Contains(err.Error(), "FAKEtoken") {
			t.Errorf("%s: the refusal is missing, or names the pasted variable", name)
		}
	}
}

// limits.max_connections is 0 (size it at start) or 64 to 1048576.
func TestMaxConnectionsIsBounded(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	for _, c := range []struct {
		value string
		ok    bool
	}{{"0", true}, {"64", true}, {"1048576", true}, {"10", false}, {"-1", false}, {"1048577", false}} {
		body := strings.Replace(fmt.Sprintf(sample, invPath), "limits: {per_nas_connections: 4}",
			"limits: {per_nas_connections: 4, max_connections: "+c.value+"}", 1)
		cfg, err := Load(write(t, "m.yaml", body))
		if c.ok != (err == nil) {
			t.Fatalf("max_connections %s: %v", c.value, err)
		}
		if err == nil && cfg.Limits.MaxConnections != map[string]int{"0": 0, "64": 64, "1048576": 1048576}[c.value] {
			t.Fatalf("max_connections %s resolved to %d", c.value, cfg.Limits.MaxConnections)
		}
		if err != nil && !strings.Contains(err.Error(), "limits.max_connections") {
			t.Fatalf("max_connections %s: unhelpful error %v", c.value, err)
		}
	}
}

// safeTemp is a fresh directory only its owner can write, whatever the umask:
// the fence refuses a file under any directory others can write.
func safeTemp(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}
