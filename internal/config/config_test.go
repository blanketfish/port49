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
		c.Limits.IdleTimeout == 0 || c.ReceiptTTL == 0 || c.ContextIdleTTL == 0 {
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
receipt_ttl: 45s
context_idle_ttl: 8h
metrics_listen: "127.0.0.1:19049"
`
	body = strings.Replace(body, "limits: {per_nas_connections: 4}",
		"limits:\n  per_nas_connections: 4\n  idle_timeout: 15s\n  malformed_window: 2m\n  auth_failure_window: 3m\n", 1)
	c, err := Load(write(t, "d.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	if c.ReceiptTTL != 45*time.Second || c.ContextIdleTTL != 8*time.Hour ||
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
