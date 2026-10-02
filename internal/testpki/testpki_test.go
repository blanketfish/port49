package testpki

import (
	"crypto/tls"
	"crypto/x509"
	"io"
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

// The new key never lands in the old file: a reader that opened a loose key
// left by an earlier run, before WriteLab tightened anything, must not read
// the new key through that open file (T8 review, parked).
func TestWriteLabNeverWritesTheNewKeyIntoAnOldLooseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LabClientKey)
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(held)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("a file opened while loose now reads %d bytes of the new key", len(got))
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the new key: %v %v", fi, err)
	}
}

// WriteInventoryLab's files are what the lab inventory service and its
// callers load: the server certificate verifies for 127.0.0.1, both clients
// for clientAuth under the one CA, each naming its one identity, and every
// key is 0600.
func TestWriteInventoryLabWritesAUsableSet(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if err := WriteInventoryLab(dir, now); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(dir, InvCA))
	if err != nil || !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("ca: %v", err)
	}
	load := func(cert, key string) *x509.Certificate {
		t.Helper()
		c, err := tls.LoadX509KeyPair(filepath.Join(dir, cert), filepath.Join(dir, key))
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		return leaf
	}
	srv := load(InvServerCert, InvServerKey)
	if _, err := srv.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now}); err != nil || srv.VerifyHostname("127.0.0.1") != nil {
		t.Fatalf("server certificate: %v", err)
	}
	client := x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	d := load(InvDaemonCert, InvDaemonKey)
	if _, err := d.Verify(client); err != nil || len(d.URIs) != 1 || d.URIs[0].String() != InvDaemonID || len(d.EmailAddresses) != 0 {
		t.Fatalf("port49d certificate: %v %v", err, d.URIs)
	}
	o := load(InvOperatorCert, InvOperatorKey)
	if _, err := o.Verify(client); err != nil || len(o.URIs) != 0 || len(o.EmailAddresses) != 1 ||
		o.EmailAddresses[0] != "alice@slice.port49.test" {
		t.Fatalf("operator certificate: %v %v", err, o.EmailAddresses)
	}
	for _, k := range []string{InvServerKey, InvDaemonKey, InvOperatorKey} {
		if fi, err := os.Stat(filepath.Join(dir, k)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s must be 0600: %v", k, err)
		}
	}
}

// WriteLabWith writes one client certificate per extra email beside the
// first's, under LabClientFiles' names, from the same CA.
func TestWriteLabWithWritesEachPerson(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLabWith(dir, "alice@lab.test", []string{"bob@lab.test"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, key := LabClientFiles("bob@lab.test")
	if cert != "client-bob.pem" || key != "client-bob-key.pem" {
		t.Fatalf("%s %s", cert, key)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, cert), filepath.Join(dir, key))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "bob@lab.test" {
		t.Fatalf("%v %v", leaf.EmailAddresses, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, key)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %v %v", fi, err)
	}
}
