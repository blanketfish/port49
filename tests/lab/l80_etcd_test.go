//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// l80EtcdStack is what the restart_etcd cell runs port49d on: one real etcd
// member, port49-broker as its own process, and the daemon's config text for
// tlsDaemon. The daemon is started and restarted by the cell, as in the
// memory cell; the broker and etcd stay up across the restart.
type l80EtcdStack struct {
	re         *realEtcd
	broker     *proc
	daemonText string
	version    string
}

// l80EtcdUp starts etcd and port49-broker for the restart_etcd cell. port49d is
// stopped when it is called (e.cli stopped it for the break-glass session), so
// :8449 is free for the broker. Any failure is INVALID.
func l80EtcdUp(t *testing.T, l *lab, q *qualEnv, e *l73Env) *l80EtcdStack {
	t.Helper()
	etcdBin := os.Getenv("PORT49_LAB_ETCD_BIN")
	if etcdBin == "" {
		t.Fatal("INVALID: PORT49_LAB_ETCD_BIN names no directory holding etcd, etcdctl and etcdutl v3.6.15")
	}
	// port49-broker is built from the tree (clean, checked at the start of the run).
	build := exec.Command("go", "build", "-o", filepath.Join(root, "bin", "port49-broker"), "./cmd/port49-broker")
	build.Dir, build.Env = root, append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("INVALID: go build port49-broker: %v %s", err, out)
	}
	re := newRealEtcd(t, etcdBin)
	re.start(t, re.data)
	s := &l80EtcdStack{re: re, version: "etcd v3.6.15"}

	dir := filepath.Join(root, "tests", "lab", "logs", "l80-etcd-"+l.p.name)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "broker-state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	socks := t.TempDir() // a short path, in a directory only this user can write
	daemonStore := fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
		"      daemon: {cert_file: %s, key_file: %s}\n      hold_ttl: 20s\n", re.client, re.ca, re.daemC, re.daemK)
	brokerStore := fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
		"      broker: {cert_file: %s, key_file: %s}\n      hold_ttl: 20s\n", re.client, re.ca, re.brokC, re.brokK)
	text, policy, err := l80EtcdDaemonYAML(q.cfgText, filepath.Join(socks, "d.sock"), daemonStore)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	s.daemonText = text
	sliceBroker, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	labRaw, err := os.ReadFile(labConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := splitBrokerYAML(string(labRaw), string(sliceBroker), splitBrokerOpts{Policy: policy, Inventory: e.invTLS,
		State: state, Metrics: splitMetricsBroker, Admin: filepath.Join(socks, "b.sock"), Store: brokerStore,
		PKI: filepath.Join(root, slicePKIDir)})
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	daemonCfg, brokerCfg := write("port49d-roles.yaml", text), write("port49-broker.yaml", broker)
	// The roles the two processes start under, provisioned as an operator does.
	re.storeRoles(t, daemonCfg, brokerCfg)
	s.broker = l.newProc("port49-broker", "port49-broker", brokerCfg)
	if err := s.broker.start(); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := waitProc(s.broker, 90*time.Second, func() bool { return httpOK("http://" + splitMetricsBroker + "/readyz") }); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	return s
}

// stop ends port49-broker; etcd is the test's cleanup. A nil stack is nothing to stop.
func (s *l80EtcdStack) stop() {
	if s != nil && s.broker != nil {
		s.broker.stop()
	}
}

// keyCount is how many keys etcd holds under /port49/, or why not: a count only.
func (s *l80EtcdStack) keyCount() string {
	n, err := s.re.keys("/port49/")
	if err != nil {
		return "unread (" + err.Error() + ")"
	}
	return strconv.FormatInt(n, 10)
}
