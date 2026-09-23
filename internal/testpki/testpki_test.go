package testpki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WriteLab's files are what the lab broker and the agent load: the server
// certificate must verify for 127.0.0.1, the client for clientAuth, both
// under the one CA, and the keys must not be readable by anyone else.
func TestWriteLabWritesAUsableSet(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if err := WriteLab(dir, "alice@slice.port49.test", now); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(dir, LabCA))
	if err != nil || !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("ca: %v", err)
	}
	srv, err := tls.LoadX509KeyPair(filepath.Join(dir, LabServerCert), filepath.Join(dir, LabServerKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(srv.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now}); err != nil || leaf.VerifyHostname("127.0.0.1") != nil {
		t.Fatalf("server certificate: %v", err)
	}
	cli, err := tls.LoadX509KeyPair(filepath.Join(dir, LabClientCert), filepath.Join(dir, LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := x509.ParseCertificate(cli.Certificate[0])
	if _, err := cl.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || cl.EmailAddresses[0] != "alice@slice.port49.test" {
		t.Fatalf("client certificate: %v %v", err, cl.EmailAddresses)
	}
	for _, k := range []string{LabServerKey, LabClientKey} {
		if fi, err := os.Stat(filepath.Join(dir, k)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s must be 0600: %v", k, err)
		}
	}
}

// os.WriteFile keeps an existing file's mode, so a key left world-readable by
// an earlier run would stay that way; WriteLab puts the modes back.
func TestWriteLabTightensAnExistingSet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, LabClientKey), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{filepath.Join(dir, LabClientKey): 0o600, dir: 0o700} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s is %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
}
