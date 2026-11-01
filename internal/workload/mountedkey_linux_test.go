//go:build linux

package workload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// A workload's key is mounted by its operator (a Kubernetes Secret volume: name -> ..data/name behind
// links, group-readable under fsGroup), so it is read under the secret-file rule within its own
// directory, not the CLI user's owner-only rule (spec §13 decision 54 ruling 16).
func mountedPair(t *testing.T) (dir string) {
	t.Helper()
	src := t.TempDir()
	if err := testpki.WriteLab(src, "svc@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cert, _ := os.ReadFile(filepath.Join(src, testpki.LabClientCert))
	key, _ := os.ReadFile(filepath.Join(src, testpki.LabClientKey))
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "..data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "..data", "tls.key"), key, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "tls.key"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAWorkloadKeyMountedAsASecretVolumeIsAccepted(t *testing.T) {
	dir := mountedPair(t)
	if _, err := LoadCertificate(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), time.Now(), nil); err != nil {
		t.Fatalf("a key behind the volume's ..data link, 0440: %v", err)
	}
}

func TestAWorkloadKeyLinkedFromOutsideItsDirectoryIsRefused(t *testing.T) {
	dir := mountedPair(t)
	other := t.TempDir()
	if err := os.Chmod(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data", "tls.key"), filepath.Join(other, "elsewhere.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "elsewhere.key"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCertificate(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), time.Now(), nil)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("a key link that leaves its directory: %v", err)
	}
}
