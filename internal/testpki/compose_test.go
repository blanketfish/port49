package testpki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// WriteCompose writes every file deploy/compose reads from local/: etcd's
// CA and members (any-purpose, for peer and client), a client per etcd
// user, the broker's lab PKI with a client certificate each for the admin
// operator and bob, the device key as a file under keys/, and one sealing
// key file per component under secrets/ (plan 7f, Ruling 8; plan 12b, Task
// 6: no env file, nothing secret in a container's environment).
func TestWriteComposeWritesTheStacksFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteCompose(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"etcd/ca.pem", "etcd/etcd-1.pem", "etcd/etcd-1-key.pem", "etcd/etcd-3.pem",
		"etcd/root.pem", "etcd/root-key.pem", "etcd/port49d.pem", "etcd/port49d-key.pem",
		"etcd/port49-broker.pem", "etcd/port49-broker-key.pem", "broker/" + LabCA, "broker/" + LabServerCert,
		"broker/" + LabServerKey, "broker/" + LabClientCert, "broker/" + LabClientKey, "broker/" + operatorKey(), "broker/" + operatorCert(),
		"broker/" + bobCert(), "keys/tacacs_v1", "secrets/port49d-encryption.key", "secrets/broker-encryption.key"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if strings.HasSuffix(f, "-key.pem") || strings.HasPrefix(f, "keys/") || strings.HasPrefix(f, "secrets/") {
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s is %v, want 0600", f, fi.Mode().Perm())
			}
		}
	}
	cn := func(f string) string {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(raw)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c.Subject.CommonName
	}
	// etcd's user is the CN: the two components' differ, and neither is root.
	if cn("etcd/port49d.pem") != "port49d" || cn("etcd/port49-broker.pem") != "port49-broker" || cn("etcd/root.pem") != "root" {
		t.Fatalf("CNs %q %q %q", cn("etcd/port49d.pem"), cn("etcd/port49-broker.pem"), cn("etcd/root.pem"))
	}
	for _, gone := range []string{"port49d.env", "port49-broker.env"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); err == nil {
			t.Errorf("%s is written: the stack keeps no env file", gone)
		}
	}
	// One sealing key, in both components' files, 32 bytes; the device key is not it.
	d, _ := os.ReadFile(filepath.Join(dir, "secrets/port49d-encryption.key"))
	b, _ := os.ReadFile(filepath.Join(dir, "secrets/broker-encryption.key"))
	k, _ := os.ReadFile(filepath.Join(dir, "keys/tacacs_v1"))
	if len(d) != 32 || string(d) != string(b) || string(k) == string(d) || len(k) != 32 {
		t.Errorf("key files: sealing %d and %d bytes (equal %v), device key %d bytes", len(d), len(b), string(d) == string(b), len(k))
	}
}

func operatorCert() string { c, _ := LabClientFiles(ComposeOperator); return c }
func operatorKey() string  { _, k := LabClientFiles(ComposeOperator); return k }
func bobCert() string      { c, _ := LabClientFiles(ComposeBob); return c }
