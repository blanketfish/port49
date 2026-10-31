//go:build lab

package lab

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/testpki"
)

// assertBrokerFilesAreRight loads the rendered broker config as port49-broker
// does and reads each file it names as what its key says: tls_cert_file and
// tls_key_file are a pair the broker can serve, the x509 anchor is a CA. A
// template whose %[N] indices have drifted puts the key where the certificate
// belongs, and the broker then refuses its start; the lab learns that an hour
// into a run unless this fails first.
func assertBrokerFilesAreRight(t *testing.T, name, yaml string, load func(string) (config.Config, error)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "port49-broker.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(path)
	if err != nil {
		t.Fatalf("%s: the config does not load: %v\n%s", name, err, yaml)
	}
	b := cfg.Broker
	if b == nil {
		t.Fatalf("%s: no broker block\n%s", name, yaml)
	}
	if _, err := keyfile.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile); err != nil {
		t.Errorf("%s: tls_cert_file %s and tls_key_file %s are not a certificate and its key: %v",
			name, filepath.Base(b.TLSCertFile), filepath.Base(b.TLSKeyFile), err)
	}
	if b.ClientCAFile == "" {
		t.Errorf("%s: no x509 trust anchor\n%s", name, yaml)
		return
	}
	raw, err := os.ReadFile(b.ClientCAFile)
	if err != nil {
		t.Errorf("%s: the x509 anchor: %v", name, err)
		return
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("%s: the x509 anchor %s is not a CERTIFICATE", name, filepath.Base(b.ClientCAFile))
		return
	}
	if c, err := x509.ParseCertificate(block.Bytes); err != nil || !c.IsCA {
		t.Errorf("%s: the x509 anchor %s is not a CA (%v)", name, filepath.Base(b.ClientCAFile), err)
	}
}

func TestL74BrokerConfigNamesItsFiles(t *testing.T) {
	t.Setenv("L74_ENC_KEY", labEncKeyDefault)
	w := &regionWorld{t: t, dir: t.TempDir(), pki: newRegionPKI(t)}
	for i := 1; i <= 3; i++ {
		assertBrokerFilesAreRight(t, "l74 region "+string(rune('0'+i)), w.brokerYAML(i), config.LoadBroker)
	}
}

func TestL75BrokerConfigNamesItsFiles(t *testing.T) {
	t.Setenv("L74_ENC_KEY", labEncKeyDefault)
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	t.Setenv("LAB_DIRECTORY_BIND_PASSWORD", "unit-test-bind-password")
	pki := newRegionPKI(t)
	o := l75Opts{i: 1, dir: t.TempDir(), x: l67TestDir(t, platOpenLDAP), pki: pki, session: regionSessionClient,
		usersCA: filepath.Join(pki.lab, testpki.LabCA)}
	assertBrokerFilesAreRight(t, "l75", l75BrokerYAML(o), config.LoadBroker)
}

func TestL67BrokerConfigNamesItsFiles(t *testing.T) {
	t.Setenv("PORT49_LAB_KEY", labKeyDefault)
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	t.Setenv("LAB_DIRECTORY_BIND_PASSWORD", "unit-test-bind-password")
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteLab(pki, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	files := l67BrokerFiles(dir, pki, l67TestDir(t, platOpenLDAP), l67BrokerOpts{})
	assertBrokerFilesAreRight(t, "l67", files["port49d.yaml"], config.Load)
}
