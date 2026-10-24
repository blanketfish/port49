//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/testpki"
)

// The restart_etcd cell's two configs, derived from the conformance config, load
// under the real loader in their own roles, with the daemon's TLS listener on:
// a run that fails here would fail minutes into a device boot.
func TestL80EtcdConfigsLoadInTheirRoles(t *testing.T) {
	read := func(parts ...string) string {
		b, err := os.ReadFile(filepath.Join(parts...))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORT49_LAB_KEY", "labsecret")
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pol := write("policy.yaml", read("slice", "policy.yaml"))
	inv := write("inventory.yaml", read("inventory-lab.yaml"))
	qual, err := qualConfigYAML(read("port49d-lab.yaml"), read("slice", "broker.yaml"), read("..", "qual", "qual-daemon.yaml"), pol)
	if err != nil {
		t.Fatal(err)
	}
	ca, cert, key := write("ca.pem", "x\n"), write("c.pem", "x\n"), write("c-key.pem", "x\n")
	daemonStore := "\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://127.0.0.1:2379]\n      ca_file: " + ca +
		"\n      daemon: {cert_file: " + cert + ", key_file: " + key + "}\n      hold_ttl: 20s\n"
	brokerStore := "\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://127.0.0.1:2379]\n      ca_file: " + ca +
		"\n      broker: {cert_file: " + cert + ", key_file: " + key + "}\n      hold_ttl: 20s\n"
	admin := filepath.Join(dir, "a.sock")
	daemon, policy, err := l80EtcdDaemonYAML(qual, admin, daemonStore)
	if err != nil {
		t.Fatal(err)
	}
	if policy != pol {
		t.Errorf("the broker's policy file is %q, want %q", policy, pol)
	}
	// The cell then puts the TLS listener and the TLS inventory on it, as tlsDaemon does.
	daemon, err = l73DaemonYAML(daemon, l73Daemon{Inventory: inv, TLSListen: "127.0.0.1:300",
		Cert: filepath.Join(pki, testpki.LabServerCert), Key: filepath.Join(pki, testpki.LabServerKey),
		ClientCA: filepath.Join(pki, "broker-ca.pem"), StateDir: dir, Status: "{disabled: true}", DefaultIdle: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(write("port49d-etcd.yaml", daemon))
	if err != nil {
		t.Fatalf("the daemon's config does not load: %v\n%s", err, daemon)
	}
	if cfg.Broker != nil || cfg.Policy == nil || cfg.Policy.File != pol || cfg.AdminSocket != admin || cfg.TLSListener == nil {
		t.Errorf("daemon: broker %v, policy %v, admin %q, tls %v", cfg.Broker, cfg.Policy, cfg.AdminSocket, cfg.TLSListener)
	}
	if cfg.Lab == nil || len(cfg.Lab.SeedTokens) != 0 {
		t.Errorf("the daemon's lab block holds seeds or none: %+v", cfg.Lab)
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	broker, err := splitBrokerYAML(read("port49d-lab.yaml"), read("slice", "broker.yaml"), splitBrokerOpts{Policy: policy, Inventory: inv,
		State: state, Metrics: splitMetricsBroker, Admin: filepath.Join(dir, "broker.sock"), Store: brokerStore, PKI: pki})
	if err != nil {
		t.Fatal(err)
	}
	bc, err := config.LoadBroker(write("port49-broker.yaml", broker))
	if err != nil {
		t.Fatalf("the broker's config does not load: %v\n%s", err, broker)
	}
	if bc.Broker == nil || bc.Broker.PolicyFile != pol {
		t.Errorf("broker block: %+v", bc.Broker)
	}
	if strings.Contains(daemon, "\nbroker:") {
		t.Error("the daemon's config still has a broker: block")
	}
}

func TestL80EtcdDaemonYAMLRefusesWhatItCannotDerive(t *testing.T) {
	for name, in := range map[string]string{
		"no broker block":    "listen: x\n",
		"no policy_file":     "broker:\n  listen: x\n",
		"already has policy": "broker:\n  policy_file: p\npolicy: {file: q}\n",
		"already has stores": "broker:\n  policy_file: p\nstores: {}\n",
		"two brokers":        "broker:\n  policy_file: p\nbroker:\n  policy_file: q\n",
	} {
		if _, _, err := l80EtcdDaemonYAML(in, "/a", "\nstores: {}\n"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
