//go:build !linux

package fence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Off Linux nothing is read, even a file only its owner could write: the
// check of who could have written it cannot be made, so it fails closed. The
// refusal names what was asked for; the caller adds the configuration key.
func TestReadRefusesOffLinux(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte("scopes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := Read(p, 1<<20, "policy file")
	if err == nil || raw != nil || !strings.Contains(err.Error(), "policy file on Linux only") {
		t.Fatalf("%q %v", raw, err)
	}
	if keys, err := ReadVerifyKeys("verify_key_files", []string{p}); err == nil || keys != nil ||
		!strings.Contains(err.Error(), "verify_key_files[0]") {
		t.Fatalf("%v %v", keys, err)
	}
}
