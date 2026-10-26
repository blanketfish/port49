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
// user, the broker's lab PKI, and an env file per component, the device
// key in port49d's alone (plan 7f, Ruling 8).
func TestWriteComposeWritesTheStacksFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteCompose(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"etcd/ca.pem", "etcd/etcd-1.pem", "etcd/etcd-1-key.pem", "etcd/etcd-3.pem",
		"etcd/root.pem", "etcd/root-key.pem", "etcd/port49d.pem", "etcd/port49d-key.pem",
		"etcd/port49-broker.pem", "etcd/port49-broker-key.pem", "broker/" + LabCA, "broker/" + LabServerCert,
		"broker/" + LabServerKey, "broker/" + LabClientCert, "broker/" + LabClientKey, "port49d.env",
		"port49-broker.env"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if strings.HasSuffix(f, "-key.pem") || strings.HasSuffix(f, ".env") {
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
	broker, err := os.ReadFile(filepath.Join(dir, "port49-broker.env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(broker), "PORT49_KEY_TACACS") {
		t.Fatal("the broker's env file holds the device key")
	}
	daemon, _ := os.ReadFile(filepath.Join(dir, "port49d.env"))
	if !strings.Contains(string(daemon), "PORT49_KEY_TACACS=") || !strings.Contains(string(daemon), "PORT49_ENC_KEY=") {
		t.Fatalf("port49d.env: %d bytes, missing a key", len(daemon))
	}
}
