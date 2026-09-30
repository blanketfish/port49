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

// The sample config is assembled from three pieces rather than written twice,
// because exactly one test has to load a config that names no encryption key
// and every other test must load one that does. Splitting it also puts
// `encryption:` ahead of `lab:`, so TestLoadWithoutALabBlock's truncation at
// `lab:` removes the lab block and nothing else.
const sampleHead = `
listen: ":4949"
inventory_file: %s
keys:
  prod_key:
    current: {version: 3, secret_env: T_PROD_V3}
    accept:  [{version: 2, secret_env: T_PROD_V2}]
    retired: [{version: 1, secret_env: T_PROD_V1}]
limits: {per_nas_connections: 4}
`

const sampleLab = `lab:
  session_attributes: ["priv-lvl=15"]
  seed_token_file: /tmp/p49-seeds.jsonl
  seed_tokens:
    - {nas: leaf-01, username: alice}
`

// sample is the standing config: a seed names who gets a token and carries no
// secret, and encryption is named because Load now requires it.
const sample = sampleHead + `encryption:
  current: {id: v2, secret_env: PORT49_ENC_V2}
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
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "per_nas_conections") {
		t.Fatalf("the error must name the file and the key, got %v", err)
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
		t.Fatal("unset secret_env must fail")
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
  a_key: {current: {version: 1, secret_env: T_A}}
  b_key: {current: {version: 1, secret_env: T_B}}
encryption: {current: {id: v1, secret_env: T_ENC}}
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
  current:  {id: v2, secret_env: PORT49_ENC_V2}
  previous: {id: v1, secret_env: PORT49_ENC_V1}
session: {staleness_ceiling: 5m}
token: {candidate_cap: 4}
`
	c, err := Load(write(t, "c.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.EncryptionKeys()
	if err != nil || k.Current.ID != "v2" || k.Previous == nil || k.Previous.ID != "v1" || k.Current.Bytes[0] != '2' {
		t.Fatalf("%+v %v", k, err)
	}
	if k.Previous.Bytes[0] != '1' {
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
	if k.Current.ID != "v2" || k.Current.Bytes != [32]byte([]byte("22222222222222222222222222222222")) {
		t.Fatalf("%+v", k.Current)
	}
}

func TestEncryptionKeyIsRequiredAnd32Bytes(t *testing.T) {
	setSecrets(t)
	invPath := write(t, "inventory.yaml", inv)
	if _, err := Load(write(t, "a.yaml", fmt.Sprintf(sampleNoEncryption, invPath))); err == nil {
		t.Fatal("a missing encryption block must fail at load, not at the first CHAP packet")
	}
	body := fmt.Sprintf(sampleNoEncryption, invPath) + "\nencryption: {current: {id: v2, secret_env: PORT49_ENC_V2}}\n"
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
	for _, want := range []string{"PORT49_ENC_V2", `"v2"`, "encryption.current", "is not set"} {
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
	for _, want := range []string{"PORT49_ENC_V2", `"v2"`, "32 bytes", "got 9"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("a short key must be refused by name and length: the error must contain %q, got %v", want, err)
		}
	}
	// A previous key is optional, but one that is named and unset is the same
	// hole: every read would try an all-zero key as its second guess.
	t.Setenv("PORT49_ENC_V2", "22222222222222222222222222222222")
	body = fmt.Sprintf(sampleNoEncryption, invPath) +
		"\nencryption:\n  current:  {id: v2, secret_env: PORT49_ENC_V2}\n  previous: {id: v1, secret_env: PORT49_ENC_V1}\n"
	if _, err := Load(write(t, "d.yaml", body)); err == nil || !strings.Contains(err.Error(), "PORT49_ENC_V1") {
		t.Fatalf("a named-but-unset previous key must be refused by name: %v", err)
	}
}

// TestEncryptionKeyIDIsRequired: the id is written into every sealed record and
// is its AAD (internal/store/crypt). An empty one seals nothing — crypt.Seal
// refuses a zero-length id — so the daemon would start and fail the first write.
func TestEncryptionKeyIDIsRequired(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "{id: v2, secret_env: PORT49_ENC_V2}",
		"{secret_env: PORT49_ENC_V2}", 1)
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
		"\nencryption:\n  current:  {id: v2, secret_env: PORT49_ENC_V2}\n  previous: {id: v2, secret_env: PORT49_ENC_V1}\n"
	if _, err := Load(write(t, "c.yaml", body)); err == nil || !strings.Contains(err.Error(), "id") {
		t.Fatalf("two keys sharing one id must be refused: the previous key would never be tried: %v", err)
	}
	// A previous key named with no secret_env reads as a rotation and loads no
	// key at all.
	body = fmt.Sprintf(sampleNoEncryption, invPath) +
		"\nencryption:\n  current:  {id: v2, secret_env: PORT49_ENC_V2}\n  previous: {id: v1}\n"
	if _, err := Load(write(t, "d.yaml", body)); err == nil || !strings.Contains(err.Error(), "secret_env") {
		t.Fatalf("a previous key with an id and no secret_env must be refused by name: %v", err)
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
	if err != nil || k.ID != "v2" || k.Bytes[31] != 'x' {
		t.Fatalf("%+v %v", k, err)
	}
}

// TestStalenessCeilingDefaultsToDisabled pins the default at 0, which means no
// staleness check at all, and that is a wiring fact rather than a taste: until
// plan 3/7's broker refreshes a context, `refreshed_at` is stamped once at login
// and nothing moves it. Any finite ceiling before then denies a steadily working
// operator `context_stale` — "the broker is unreachable" — at login plus the
// ceiling, with no broker to reach. Whoever wires the broker sets this key and
// changes this test with it.
func TestStalenessCeilingDefaultsToDisabled(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "c.yaml", fmt.Sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Session.StalenessCeiling != 0 {
		t.Fatalf("session.staleness_ceiling must default to 0 (disabled), got %s", c.Session.StalenessCeiling)
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
	body := fmt.Sprintf(sample, orphan) + "broker: {listen: \"127.0.0.1:0\", tls_cert_file: c, tls_key_file: k, " +
		"client_ca_file: ca, policy_file: p}\n"
	cfg, err := Load(write(t, "f.yaml", body))
	if err != nil {
		t.Fatalf("a broker config refused an orphan device: %v", err)
	}
	if cfg.Admission != nil {
		t.Fatalf("admission %v", cfg.Admission)
	}
	if got := cfg.KeyRefs(); len(got) != 1 || got[0] != "prod_key" {
		t.Fatalf("KeyRefs: %q", got)
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
	body := fmt.Sprintf(sample, missing) + "broker: {listen: \"127.0.0.1:0\", tls_cert_file: c, tls_key_file: k, " +
		"client_ca_file: ca, policy_file: p}\n"
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
	body := strings.Replace(fmt.Sprintf(sample, i), "accept:  [{version: 2, secret_env: T_PROD_V2}]",
		"accept:  [{version: 2, secret_env: T_PROD_V2, retire_after: 2000-01-01}]", 1)
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
		strings.Replace(fmt.Sprintf(sample, i), "current: {version: 3, secret_env: T_PROD_V3}",
			"current: {version: 3, secret_env: T_PROD_V3, retire_after: 2999-01-01}", 1),
		strings.Replace(body, "retire_after: 2000-01-01", "retire_after: soon", 1),
		strings.Replace(fmt.Sprintf(sample, i), "retired: [{version: 1, secret_env: T_PROD_V1}]",
			"retired: [{version: 1, secret_env: T_PROD_V1, retire_after: 2999-01-01}]", 1),
	} {
		if _, err := Load(write(t, "c.yaml", bad)); err == nil {
			t.Fatalf("loaded: %s", bad)
		}
	}
	sets, err := KeySets([]byte(body))
	if err != nil || len(sets["prod_key"].Accept) != 1 || sets["prod_key"].Accept[0].RetireAt.IsZero() {
		t.Fatalf("KeySets: %+v, %v", sets, err)
	}
}
