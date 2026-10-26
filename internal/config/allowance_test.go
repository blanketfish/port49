package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/secretref"
)

// ownedPaths is one Config per key path or secret_ref port49d.yaml names
// (ownKeyPaths and ownSecretRefs), each naming only that one, at the given
// path. A new entry in either function needs a row here.
func ownedPaths(path string) map[string]Config {
	etcd := func(f func(*EtcdConfig)) StoresConfig {
		e := &EtcdConfig{}
		f(e)
		return StoresConfig{Directory: StoreConfig{Etcd: e}}
	}
	broker := func(f func(*BrokerConfig)) Config {
		b := &BrokerConfig{Directory: &directory.Config{}}
		f(b)
		return Config{Broker: b}
	}
	return map[string]Config{
		"tls_listener.key_file":              {TLSListener: &TLSListenerConfig{KeyFile: path}},
		"inventory_service.tls_key_file":     {InventoryService: &InventoryServiceConfig{TLSKeyFile: path}},
		"broker.tls_key_file":                broker(func(b *BrokerConfig) { b.TLSKeyFile = path }),
		"broker.directory.bind.tls_key_file": broker(func(b *BrokerConfig) { b.Directory.Bind.TLSKeyFile = path }),
		"broker.directory.bind.keytab_file":  broker(func(b *BrokerConfig) { b.Directory.Bind.KeytabFile = path }),
		"broker state directory":             broker(func(b *BrokerConfig) { b.StateDir = path }),
		"broker revocations directory":       broker(func(b *BrokerConfig) { b.RevocationsFile = filepath.Join(path, "revocations") }),
		"stores.directory.etcd.daemon.key_file": {Stores: etcd(func(e *EtcdConfig) {
			e.Daemon.KeyFile = path
		})},
		"stores.directory.etcd.broker.key_file": {Stores: etcd(func(e *EtcdConfig) {
			e.Broker = &EtcdIdentity{KeyFile: path}
		})},
		"stores.session.etcd.daemon.key_file": {Stores: StoresConfig{Session: StoreConfig{Etcd: &EtcdConfig{
			Daemon: EtcdIdentity{KeyFile: path}}}}},
		"encryption.current.secret_ref":  {encCurrent: encKeyYAML{SecretRef: "file:" + path}},
		"encryption.previous.secret_ref": {encPrevious: encKeyYAML{SecretRef: "file:" + path}},
		"bind password": broker(func(b *BrokerConfig) {
			b.Directory.Bind.PasswordRef = "file:" + path
		}),
	}
}

// Every key file, key directory and secret_ref port49d.yaml names is refused
// when key_secret_refs.file_dir covers it (decision 53 ruling 12; review 6,
// I1): a policy could otherwise name it as a device key. The key directory's
// own entry is also refused the other way, file_dir below it.
func TestEveryKeyPort49dNamesIsKeptApartFromTheAllowance(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "keys")
	inside := filepath.Join(dir, "secret")
	for at, c := range ownedPaths(inside) {
		c.KeySecretRefs = secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir}
		if err := secretsApart(c); err == nil {
			t.Errorf("%s under file_dir: not refused", at)
		}
	}
	outside := filepath.Join(root, "elsewhere", "secret")
	for at, c := range ownedPaths(outside) {
		c.KeySecretRefs = secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir}
		if err := secretsApart(c); err != nil {
			t.Errorf("%s outside file_dir: %v", at, err)
		}
	}
	// file_dir equal to, and below, the broker's state directory (the issuing
	// CA key lives there), and a revocations file's directory.
	state := filepath.Join(root, "state")
	for name, fileDir := range map[string]string{"equal": state, "below": filepath.Join(state, "keys")} {
		c := ownedPaths(state)["broker state directory"]
		c.KeySecretRefs = secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: fileDir}
		if err := secretsApart(c); err == nil || !strings.Contains(err.Error(), "overlaps key_secret_refs.file_dir") {
			t.Errorf("file_dir %s the state directory: %v", name, err)
		}
	}
	c := ownedPaths(state)["broker revocations directory"]
	c.KeySecretRefs = secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: state}
	if err := secretsApart(c); err == nil {
		t.Error("file_dir equal to the revocations file's directory: not refused")
	}
}

// A keytab named through a link inside file_dir, and a keytab inside a
// directory file_dir reaches through a link, are each refused (re-review N1).
func TestAKeytabLinkedFromTheAllowanceIsRefused(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keytab := filepath.Join(root, "port49.keytab")
	if err := os.WriteFile(keytab, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(dir, "tab")
	if err := os.Symlink(keytab, inner); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "keylink")
	if err := os.Symlink(root, dirLink); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ keytab, fileDir string }{
		"a link inside file_dir":                    {inner, dir},
		"file_dir a link to the keytab's directory": {keytab, dirLink},
	} {
		cfg := ownedPaths(c.keytab)["broker.directory.bind.keytab_file"]
		cfg.KeySecretRefs = secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: c.fileDir}
		if err := secretsApart(cfg); err == nil || !strings.Contains(err.Error(), "overlaps key_secret_refs.file_dir") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// env_prefix must end at a word boundary (review 6, M4): PORT49_KEY would admit
// PORT49_KEYTAB_PASS and HTTPS would admit HTTPS_PROXY.
func TestAnEnvPrefixMustEndAtAWordBoundary(t *testing.T) {
	for _, prefix := range []string{"PORT49_KEY", "HTTPS", "PORT49_KEYS", "PORT"} {
		a := secretref.Allowance{EnvPrefix: prefix, FileDir: "/run/port49/keys"}
		err := a.Check()
		if err == nil || !strings.Contains(err.Error(), "env_prefix") || !strings.Contains(err.Error(), "_") {
			t.Errorf("env_prefix %q: %v", prefix, err)
		}
	}
	if err := (secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: "/run/port49/keys"}).Check(); err != nil {
		t.Errorf("the default prefix: %v", err)
	}
	if err := secretref.DefaultAllowance.Check(); err != nil {
		t.Errorf("DefaultAllowance: %v", err)
	}
}
