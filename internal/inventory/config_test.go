package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalConfig = `
listen: 127.0.0.1:8443
tls_cert_file: /etc/i/server.pem
tls_key_file: /etc/i/server-key.pem
client_ca_file: /etc/i/ca.pem
readers: ["spiffe://example.com/port49d"]
syncers: ["user:alice@example.com"]
signing_key_file: /etc/i/signing.key
policy_file: /etc/i/policy.yaml
state_dir: /var/lib/port49-inventory
sync:
  - {name: lab_file, type: file, path: /etc/i/inventory.yaml}
`

func loadString(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "port49-inventory.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestTheMinimalConfigLoadsWithItsDefaults(t *testing.T) {
	c, err := loadString(t, minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	if c.MetricsListen != ":9050" || c.Interval != 10*time.Minute || c.MaxRemovedPercent != 10 ||
		c.Bounds()["lab_file"] != 10 || c.MirrorDir != "" || c.SyncTimeout != 5*time.Minute ||
		len(c.VerifyKeyFiles) != 0 {
		t.Fatalf("%+v", c)
	}
}

// Spec §10: each source syncs on its own interval, defaulting to the
// top-level one.
func TestAPerSourceIntervalOverridesTheDefault(t *testing.T) {
	c, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, interval: 5m}", 1))
	if err != nil || c.Sync[0].Interval != 5*time.Minute {
		t.Fatalf("%+v %v", c.Sync, err)
	}
	c, err = loadString(t, minimalConfig)
	if err != nil || c.Sync[0].Interval != 10*time.Minute {
		t.Fatalf("the default: %+v %v", c.Sync, err)
	}
	if _, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, interval: 5s}", 1)); err == nil ||
		!strings.Contains(err.Error(), "sync[0].interval must be between 1m and 24h") {
		t.Fatalf("got %v", err)
	}
}

func TestASourceBoundOverridesTheDefault(t *testing.T) {
	c, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, safety: {max_removed_percent: 30}}", 1)+"safety: {max_removed_percent: 5}\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxRemovedPercent != 5 || c.Bounds()["lab_file"] != 30 {
		t.Fatalf("%+v", c)
	}
}

// A secret pasted under a mistyped key is not echoed: the line and a
// category (yamlfault).
func TestAnUnknownKeyIsNamedByLineWithoutItsText(t *testing.T) {
	_, err := loadString(t, minimalConfig+"signing_key: \"-----BEGIN PRIVATE KEY-----SECRET\"\n")
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "an unknown field") {
		t.Fatalf("got %v", err)
	}
}

func TestWhatTheServiceCannotRunWithoutIsRefused(t *testing.T) {
	for name, c := range map[string]struct{ from, to, want string }{
		"no state_dir":      {"state_dir: /var/lib/port49-inventory\n", "", "state_dir is required"},
		"no signing key":    {"signing_key_file: /etc/i/signing.key\n", "", "signing_key_file is required"},
		"nobody may read":   {"readers: [\"spiffe://example.com/port49d\"]\nsyncers: [\"user:alice@example.com\"]\n", "", "readers or syncers"},
		"no source":         {"sync:\n  - {name: lab_file, type: file, path: /etc/i/inventory.yaml}\n", "", "at least one sync source"},
		"netbox":            {"type: file", "type: netbox", "type netbox is not built yet"},
		"bad source name":   {"name: lab_file", "name: Lab-File", "sync[0].name"},
		"file with no path": {", path: /etc/i/inventory.yaml", "", "sync[0] (lab_file): path is required"},
		"bound over 100":    {"state_dir:", "safety: {max_removed_percent: 101}\nstate_dir:", "between 0 and 100"},
		"a bad identity":    {`"user:alice@example.com"`, `"alice"`, "syncers[0]"},
		"interval too fast": {"state_dir:", "interval: 10s\nstate_dir:", "interval must be between 1m and 24h"},
		"sync_timeout":      {"state_dir:", "sync_timeout: 2h\nstate_dir:", "sync_timeout must be between 10s and 1h"},
	} {
		_, err := loadString(t, strings.Replace(minimalConfig, c.from, c.to, 1))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}
