package testpki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// WriteKind writes WriteCompose's layout with member certificates for a StatefulSet's pods: the
// SANs are etcd-<i>.etcd.<namespace>.svc and .svc.cluster.local, for i in 0..members-1, and the
// files are named etcd-<i>.
func TestWriteKindNamesEachMemberByItsPodDNS(t *testing.T) {
	dir := t.TempDir()
	if err := WriteKind(dir, "port49", 3, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"etcd-0", "etcd-1", "etcd-2"} {
		c := parseCert(t, filepath.Join(dir, "etcd", name+".pem"))
		want := []string{name + ".etcd.port49.svc", name + ".etcd.port49.svc.cluster.local"}
		for _, w := range want {
			if !slices.Contains(c.DNSNames, w) {
				t.Errorf("member %d: SANs %v lack %s", i, c.DNSNames, w)
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "etcd", name+"-key.pem")); err != nil {
			t.Errorf("%s has no key file: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "etcd", "etcd-3.pem")); err == nil {
		t.Error("a fourth member was written for members = 3")
	}
	// The rest is WriteCompose's layout: the three etcd users, the device key, the sealing keys.
	for _, f := range []string{"etcd/ca.pem", "etcd/root.pem", "etcd/port49d.pem", "etcd/port49-broker.pem",
		"keys/tacacs_v1", "secrets/port49d-encryption.key", "secrets/broker-encryption.key", "broker/" + LabCA} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if cn := parseCert(t, filepath.Join(dir, "etcd", "port49d.pem")).Subject.CommonName; cn != "port49d" {
		t.Errorf("port49d's etcd user is %q", cn)
	}
}

func TestWriteKindMembersAndNamespaceAreChecked(t *testing.T) {
	for name, tc := range map[string]struct {
		ns      string
		members int
	}{"no members": {"port49", 0}, "an empty namespace": {"", 3}, "a dotted namespace": {"a.b", 3}} {
		if err := WriteKind(t.TempDir(), tc.ns, tc.members, "a@example.com", time.Now()); err == nil {
			t.Errorf("%s: WriteKind succeeded", name)
		}
	}
}

func TestWriteKindBrokerCertificateAnswersToItsServiceNames(t *testing.T) {
	dir := t.TempDir()
	if err := WriteKind(dir, "port49", 3, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "broker", LabServerCert))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"t-broker.port49.svc", "t-broker.port49.svc.cluster.local", "port49-broker"} {
		if err := c.VerifyHostname(name); err != nil {
			t.Errorf("the broker's certificate does not answer to %s: %v", name, err)
		}
	}
	if err := c.VerifyHostname("t-broker.other.svc"); err == nil {
		t.Error("the broker's certificate answers to another namespace")
	}
}
