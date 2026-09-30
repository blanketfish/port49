package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/keyfile"
)

// loadService is the standing sample (config_test.go) with block appended:
// with or without its inventory_file line, and with or without broker_test.go's
// broker block.
func loadService(t *testing.T, withFile, withBroker bool, block string) (Config, error) {
	t.Helper()
	setKeyEnv(t)
	body := fmt.Sprintf(sample, write(t, "inv.yaml", inv))
	if !withFile {
		body = regexp.MustCompile(`(?m)^inventory_file: .*\n`).ReplaceAllString(body, "")
	}
	if withBroker {
		body += brokerBlock
	}
	return Load(write(t, "port49d.yaml", body+block))
}

// serviceBlock is inventory.service with a verify key that exists.
func serviceBlock(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, pubPEM, _ := keyfile.EncodeEd25519(priv)
	// The fence refuses a directory others could write, and TempDir's mode
	// follows the umask.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "signing.pub")
	if err := os.WriteFile(pub, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`inventory:
  service:
    url: https://inv.example:8443
    ca_file: /etc/port49/inventory-ca.pem
    tls_cert_file: /etc/port49/port49d.pem
    tls_key_file: /etc/port49/port49d-key.pem
    verify_key_files: [%s]
    state_dir: /var/lib/port49/inventory
`, pub)
}

func TestTheInventoryServiceBlockLoadsInPlaceOfTheFile(t *testing.T) {
	c, err := loadService(t, false, true, serviceBlock(t))
	if err != nil {
		t.Fatal(err)
	}
	s := c.InventoryService
	if s == nil || s.PollInterval != 30*time.Second || s.StateDir != "/var/lib/port49/inventory" || c.InventoryFile != "" {
		t.Fatalf("%+v", s)
	}
	if keys, err := VerifyKeys(s.VerifyKeyFiles); err != nil || len(keys) != 1 {
		t.Fatalf("%v %v", keys, err)
	}
}

func TestTheInventoryServiceBlockIsRefusedWhereItCannotWork(t *testing.T) {
	block := serviceBlock(t)
	for name, c := range map[string]struct {
		cfg  func() (Config, error)
		want string
	}{
		"both sources": {func() (Config, error) { return loadService(t, true, true, block) },
			"name inventory_file or inventory.service, not both"},
		"neither": {func() (Config, error) { return loadService(t, false, true, "") },
			"inventory_file or inventory.service is required"},
		"no broker": {func() (Config, error) { return loadService(t, false, false, block) },
			"inventory.service needs a broker: block"},
		"plain http": {func() (Config, error) {
			return loadService(t, false, true, strings.Replace(block, "https://", "http://", 1))
		}, "inventory.service.url must be https"},
		"no verify key": {func() (Config, error) {
			return loadService(t, false, true, strings.Replace(block, "verify_key_files: [", "verify_key_files: [/nonexistent/x.pub, ", 1))
		}, "inventory.service.verify_key_files[0]"},
		"poll too fast": {func() (Config, error) {
			return loadService(t, false, true, block+"    poll_interval: 1s\n")
		}, "poll_interval must be between 5s and 10m"},
		"poll too slow": {func() (Config, error) {
			return loadService(t, false, true, block+"    poll_interval: 11m\n")
		}, "poll_interval must be between 5s and 10m"},
	} {
		if _, err := c.cfg(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// Nothing to verify against is no inventory at all: an empty or missing list,
// an empty entry or a relative one refuses the start rather than leaving a
// document that nothing checks, or a key read from wherever port49d was
// started.
func TestTheVerifyKeyListFailsClosed(t *testing.T) {
	block := serviceBlock(t)
	keys := regexp.MustCompile(`(?m)^    verify_key_files: .*\n`)
	for name, c := range map[string]struct{ block, want string }{
		"missing":        {keys.ReplaceAllString(block, ""), "verify_key_files must name"},
		"empty":          {keys.ReplaceAllString(block, "    verify_key_files: []\n"), "verify_key_files must name"},
		"empty entry":    {strings.Replace(block, "verify_key_files: [", `verify_key_files: ["", `, 1), "inventory.service.verify_key_files[0] must be an absolute path"},
		"relative entry": {strings.Replace(block, "verify_key_files: [", "verify_key_files: [signing.pub, ", 1), "inventory.service.verify_key_files[0] must be an absolute path"},
	} {
		if _, err := loadService(t, false, true, c.block); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// A missing ca_file would be a nil RootCAs, which Go reads as the host's
// roots: any public CA could then vouch for the service. Refused at load, as
// is every relative path.
func TestTheServiceFilesMustBeNamedAndAbsolute(t *testing.T) {
	block := serviceBlock(t)
	for _, key := range []string{"ca_file", "tls_cert_file", "tls_key_file", "state_dir"} {
		line := regexp.MustCompile(`(?m)^    ` + key + `: .*\n`)
		if _, err := loadService(t, false, true, line.ReplaceAllString(block, "")); err == nil ||
			!strings.Contains(err.Error(), "inventory.service."+key+" is required") {
			t.Errorf("%s missing: got %v", key, err)
		}
		if _, err := loadService(t, false, true, line.ReplaceAllString(block, "    "+key+": relative/x\n")); err == nil ||
			!strings.Contains(err.Error(), "inventory.service."+key+" must be an absolute path") {
			t.Errorf("%s relative: got %v", key, err)
		}
	}
	if _, err := loadService(t, false, true, block+"    mirror_dir: mirror\n"); err == nil ||
		!strings.Contains(err.Error(), "inventory.service.mirror_dir must be an absolute path") {
		t.Errorf("mirror_dir relative: got %v", err)
	}
	c, err := loadService(t, false, true, block+"    mirror_dir: /srv/port49/mirror\n")
	if err != nil || c.InventoryService.MirrorDir != "/srv/port49/mirror" {
		t.Fatalf("mirror_dir absolute: %v", err)
	}
}

// Pre-flight M3: a verify key others could write refuses the start.
func TestAVerifyKeyOthersCouldWriteRefusesTheStart(t *testing.T) {
	block := serviceBlock(t)
	pub := regexp.MustCompile(`verify_key_files: \[(.*)\]`).FindStringSubmatch(block)[1]
	if err := os.Chmod(pub, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := loadService(t, false, true, block); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("got %v", err)
	}
}

// SIGHUP re-reads verify_key_files (Decided 12).
func TestInventoryServiceOfReadsTheBlockAlone(t *testing.T) {
	s, err := InventoryServiceOf([]byte(serviceBlock(t)))
	if err != nil || s == nil || len(s.VerifyKeyFiles) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	if s, err := InventoryServiceOf([]byte("inventory: {max_removed_percent: 10}\n")); s != nil || err != nil {
		t.Fatalf("no block: %v %v", s, err)
	}
}

// A decode error names a line and a category (yamlfault), never the text:
// what an operator typed into url could be a credential.
func TestInventoryServiceDecodeErrorsEchoNothing(t *testing.T) {
	const secret = "hunter2-do-not-echo"
	raw := "inventory:\n  service:\n    url: [" + secret + "\n"
	if _, err := InventoryServiceOf([]byte(raw)); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("got %v", err)
	}
	if _, err := InventoryServiceOf([]byte("inventory:\n  service:\n    poll_interval: " + secret + "\n")); err == nil ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("got %v", err)
	}
	if _, err := InventoryServiceOf([]byte("inventory:\n  service:\n    url: https://" + secret + "@inv.example\n")); err == nil ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("got %v", err)
	}
}

// The url is https://host[:port] and nothing else, as the client takes it.
func TestTheServiceURLIsHostAndPortOnly(t *testing.T) {
	block := serviceBlock(t)
	for _, u := range []string{"https://inv.example:8443/v1", "https://inv.example:8443?token=x",
		"https://inv.example:8443/?", "https://inv.example:8443#frag", "https://user@inv.example:8443",
		"https://", "https:inv.example"} {
		if _, err := loadService(t, false, true, strings.Replace(block, "https://inv.example:8443", u, 1)); err == nil ||
			!strings.Contains(err.Error(), "inventory.service.url must be https://host[:port]") {
			t.Errorf("%s: got %v", u, err)
		}
	}
	for _, u := range []string{"https://inv.example", "https://inv.example:8443/"} {
		if _, err := loadService(t, false, true, strings.Replace(block, "https://inv.example:8443", u, 1)); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// mirror_dir and state_dir are apart, as the service requires of its own:
// neither is, or is under, the other; a sibling that shares a prefix is apart.
func TestTheMirrorAndTheStateAreApart(t *testing.T) {
	block := serviceBlock(t)
	for mirror, want := range map[string]string{
		"/var/lib/port49/inventory":         "mirror_dir must be outside state_dir",
		"/var/lib/port49/inventory/":        "mirror_dir must be outside state_dir",
		"/var/lib/port49/inventory/mirror":  "mirror_dir must be outside state_dir",
		"/var/lib/port49":                   "state_dir must be outside mirror_dir",
		"/var/lib/port49/../port49":         "state_dir must be outside mirror_dir",
		"/var/lib/port49/inventory-mirror":  "",
		"/var/lib/port49/inventory.mirror/": "",
	} {
		_, err := loadService(t, false, true, block+"    mirror_dir: "+mirror+"\n")
		if want == "" && err != nil {
			t.Errorf("%s: %v", mirror, err)
		}
		if want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: got %v, want %q", mirror, err, want)
		}
	}
}
