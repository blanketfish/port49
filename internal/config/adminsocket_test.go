package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adminSocketRefusal is spec §12's line for the removed key.
const adminSocketRefusal = "admin_socket was removed: admin operations go over the broker API with a security " +
	"key press (spec §5.1.6); delete the key"

// admin_socket is refused by name in both files, with one line and no
// alias: before beta a removed key is an error, never a warning.
func TestAdminSocketIsRefusedByName(t *testing.T) {
	setKeyEnv(t)
	daemon := "admin_socket: /run/port49/port49d.sock\n" + daemonRoleYAML(t)
	if _, err := loadDaemonRole(t, daemon); err == nil || !strings.Contains(err.Error(), adminSocketRefusal) {
		t.Errorf("port49d.yaml with admin_socket: %v", err)
	}
	broker := "admin_socket: /run/port49/broker.sock\n" + brokerRoleYAML(t)
	if _, err := loadBrokerRole(t, broker); err == nil || !strings.Contains(err.Error(), adminSocketRefusal) {
		t.Errorf("port49-broker.yaml with admin_socket: %v", err)
	}
	// A value of any kind, even an empty one, is the key.
	if _, err := loadBrokerRole(t, "admin_socket: \"\"\n"+brokerRoleYAML(t)); err == nil ||
		!strings.Contains(err.Error(), adminSocketRefusal) {
		t.Errorf("an empty admin_socket: %v", err)
	}
	// The path is not echoed: the refusal names the key and its line.
	if _, err := loadBrokerRole(t, "admin_socket: /secret/path-xyz\n"+brokerRoleYAML(t)); err == nil ||
		strings.Contains(err.Error(), "path-xyz") {
		t.Errorf("the value was echoed: %v", err)
	}
	// RevocationsFile reads the same bytes and refuses the same key.
	if _, err := RevocationsFile([]byte("admin_socket: /x\nbroker:\n  revocations_file: /var/lib/port49/r.json\n")); err == nil ||
		!strings.Contains(err.Error(), adminSocketRefusal) {
		t.Errorf("RevocationsFile: %v", err)
	}
}

// The etcd rule that required admin_socket is gone: a split daemon and a
// broker load without it.
func TestEtcdNoLongerRequiresAnAdminSocket(t *testing.T) {
	if _, err := loadBrokerRole(t, brokerRoleYAML(t)); err != nil {
		t.Errorf("port49-broker.yaml on etcd with no admin_socket: %v", err)
	}
	if _, err := loadDaemonRole(t, daemonRoleYAML(t)); err != nil {
		t.Errorf("port49d.yaml on etcd with no admin_socket: %v", err)
	}
}

// The admin sockets are gone from the tree (spec §5.1.6, §12): no Go file
// under internal/ or cmd/ imports the package that served them, the package is
// not there, and no config, script or Go fixture under deploy/ or tests/ sets
// admin_socket. Historical notes (results, evidence, markdown) are not config.
func TestNoAdminSocketRemains(t *testing.T) {
	root := "../.."
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the repository root is not two levels up: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "internal", "daemon", "admin")); err == nil {
		t.Error("internal/daemon/admin is still there")
	}
	importLine := `"github.com/rhwendt/port49/internal/` + `daemon/admin"`
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
				return err
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.Contains(string(raw), importLine) {
				t.Errorf("%s imports internal/daemon/admin", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	configExt := map[string]bool{".yaml": true, ".yml": true, ".json": true, ".sh": true, ".go": true, ".tmpl": true, ".conf": true}
	for _, top := range []string{"deploy", "tests"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if n := d.Name(); n == "results" || n == "evidence" || n == "logs" || n == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !configExt[filepath.Ext(p)] {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for i, l := range strings.Split(string(raw), "\n") {
				if strings.Contains(l, "admin_socket:") {
					t.Errorf("%s:%d sets admin_socket", p, i+1)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
