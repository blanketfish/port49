//go:build lab

package lab

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/policy"
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

// labTree copies the files the derived daemon configs read into a temp root, as the lab's repository
// root, and makes it the process's working directory (the configs' paths are relative to it).
func labTree(t *testing.T) string {
	t.Helper()
	src, err := os.Getwd() // tests/lab
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	lab := filepath.Join(dst, "tests", "lab")
	if err := os.MkdirAll(filepath.Join(lab, "slice"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"port49d-lab.yaml", "inventory-lab.yaml", "slice/broker.yaml", "slice/policy.yaml",
		"slice/api-policy.yaml", "slice/session-policy.yaml"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lab, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := testpki.WriteLabWith(filepath.Join(lab, "logs", "slice-pki"), sliceEmail, []string{oncallEmail}, time.Now()); err != nil {
		t.Fatal(err)
	}
	old := root
	root = dst
	t.Cleanup(func() { root = old })
	t.Chdir(dst)
	return dst
}

// assertDaemonConfigLoads is the load port49d runs at start, without listening: the config, then the
// policy file it names, then the files of its broker block. A config the daemon refuses is a lab run
// that fails an hour in.
func assertDaemonConfigLoads(t *testing.T, name, path string) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Errorf("%s: port49d refuses the config: %v", name, err)
		return
	}
	if cfg.Policy != nil {
		if _, err := policy.Load(cfg.Policy.File, policy.Env{}); err != nil {
			t.Errorf("%s: the policy file %s does not load: %v", name, cfg.Policy.File, err)
		}
	}
	if b := cfg.Broker; b != nil {
		if _, err := keyfile.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile); err != nil {
			t.Errorf("%s: the broker's tls pair: %v", name, err)
		}
	}
}

// Every daemon config the lab derives for a run that adds a broker block loads as port49d loads it: the
// slice's, and the revoke and API-revoke cells' with the on-call's admin roots (their shapes are
// slice/broker.yaml, api-policy.yaml and withAdminTouch, as those cells build them).
func TestDerivedDaemonConfigsLoad(t *testing.T) {
	t.Setenv("PORT49_LAB_KEY", labKeyDefault)
	t.Setenv("PORT49_KEY_LAB", labKeyDefault)
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	r := labTree(t)
	l := &lab{p: platform{name: "arista_eos"}}
	attrs := platformSessionAttributes[l.p.name]
	raw, err := os.ReadFile(filepath.Join(r, "tests", "lab", "slice", "broker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	slice := string(raw)
	apiPolicy := strings.Replace(slice, "tests/lab/slice/policy.yaml", "tests/lab/slice/api-policy.yaml", 1)
	sessionPolicy := strings.Replace(slice, "tests/lab/slice/policy.yaml", "tests/lab/slice/session-policy.yaml", 1)
	touch, err := withAdminTouch(apiPolicy, filepath.Join(r, adminRolesFile))
	if err != nil {
		t.Fatal(err)
	}
	for name, extra := range map[string]string{"standing": "", "slice": slice, "api policy": apiPolicy,
		"session policy": sessionPolicy, "revoke with admin roots": touch} {
		path, err := l.derivedConfig("unit", attrs, extra)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertDaemonConfigLoads(t, name, path)
	}
}

// L74's port49d replicas load as port49d loads them, with the policy they name.
func TestL74DaemonConfigLoads(t *testing.T) {
	t.Setenv("L74_ENC_KEY", labEncKeyDefault)
	t.Setenv("PORT49_KEY_LAB", labKeyDefault)
	w := &regionWorld{t: t, dir: t.TempDir(), pki: newRegionPKI(t)}
	pol, err := os.ReadFile("slice/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.dir, "policy.yaml"), pol, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		path := filepath.Join(w.dir, "port49d.yaml")
		if err := os.WriteFile(path, []byte(w.daemonYAML(i)), 0o600); err != nil {
			t.Fatal(err)
		}
		assertDaemonConfigLoads(t, "l74 daemon "+string(rune('0'+i)), path)
	}
}
