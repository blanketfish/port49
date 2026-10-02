package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// storeFiles writes a CA and two identities' files, mode 0600, and
// returns the dir.
func storeFiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"ca.pem", "d.pem", "d-key.pem", "b.pem", "b-key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func etcdYAML(dir string) storeYAML {
	return storeYAML{Backend: "etcd", Etcd: &EtcdConfig{
		Endpoints: []string{"https://etcd-0:2379"}, CAFile: filepath.Join(dir, "ca.pem"),
		Daemon: EtcdIdentity{CertFile: filepath.Join(dir, "d.pem"), KeyFile: filepath.Join(dir, "d-key.pem")},
		Broker: &EtcdIdentity{CertFile: filepath.Join(dir, "b.pem"), KeyFile: filepath.Join(dir, "b-key.pem")}}}
}

func TestTheStoreDefaultsToMemoryWithAPacketDeadline(t *testing.T) {
	s, err := checkStore(storeYAML{}, true, false)
	if err != nil || s.Backend != BackendMemory || s.PacketDeadline != 2*time.Second || s.Etcd != nil {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestEtcdTakesItsDefaults(t *testing.T) {
	s, err := checkStore(etcdYAML(storeFiles(t)), true, true)
	if err != nil {
		t.Fatal(err)
	}
	e := s.Etcd
	if e.Prefix != "/port49/" || e.Roles != "enforced" || e.CallTimeout != 500*time.Millisecond ||
		e.BulkTimeout != 30*time.Second || e.Breaker.Failures != 5 || e.Breaker.OpenFor != 5*time.Second ||
		e.MaxInFlight.Token != 64 || e.MaxInFlight.Context != 128 || e.MaxInFlight.Bulk != 4 ||
		e.LeaseGrace != 5*time.Minute || e.StartTimeout != 30*time.Second || e.HoldTTL != 15*time.Second ||
		e.SweepInterval != 10*time.Minute {
		t.Fatalf("%+v", e)
	}
}

// A start_timeout of 0 is "wait forever", not "take the default"
// (pre-flight I19): the YAML field is a pointer, so an absent key and a
// 0 are told apart.
func TestAStartTimeoutOfZeroWaitsForever(t *testing.T) {
	y := etcdYAML(storeFiles(t))
	zero := time.Duration(0)
	y.Etcd.StartTimeoutSet = &zero
	s, err := checkStore(y, true, true)
	if err != nil || s.Etcd.StartTimeout != 0 {
		t.Fatalf("%+v %v", s.Etcd, err)
	}
}

func TestTheStoreRefusesWhatWouldRunUnsafely(t *testing.T) {
	dir := storeFiles(t)
	for _, c := range []struct {
		name          string
		edit          func(*storeYAML)
		broker, admin bool
		want          string
	}{
		{"unknown backend", func(s *storeYAML) { s.Backend = "redis" }, true, true, `store.backend "redis": must be memory or etcd`},
		{"etcd with no block", func(s *storeYAML) { s.Etcd = nil }, true, true, "store.etcd is missing"},
		{"a block on memory", func(s *storeYAML) { s.Backend = "memory" }, true, true, "store.etcd is set but store.backend is memory"},
		{"plain http", func(s *storeYAML) { s.Etcd.Endpoints = []string{"http://etcd-0:2379"} }, true, true, "must be https://"},
		{"no endpoints", func(s *storeYAML) { s.Etcd.Endpoints = nil }, true, true, "store.etcd.endpoints is empty"},
		{"a key file missing", func(s *storeYAML) { s.Etcd.Daemon.KeyFile = filepath.Join(dir, "nope.pem") }, true, true,
			"store.etcd.daemon.key_file"},
		{"no broker identity", func(s *storeYAML) { s.Etcd.Broker = nil }, true, true, "store.etcd.broker is missing"},
		{"etcd with no broker", func(s *storeYAML) {}, false, true, "store.backend etcd needs a broker: block"},
		{"etcd with no admin socket", func(s *storeYAML) {}, true, false, "store.backend etcd needs admin_socket"},
		{"roles misspelt", func(s *storeYAML) { s.Etcd.Roles = "off" }, true, true, `store.etcd.roles "off"`},
		{"a deadline past 2s", func(s *storeYAML) { s.PacketDeadline = 2500 * time.Millisecond }, true, true,
			"store.packet_deadline"},
		{"a deadline under the call's", func(s *storeYAML) {
			s.PacketDeadline, s.Etcd.CallTimeout = 200*time.Millisecond, time.Second
		}, true, true, "at least store.etcd.call_timeout"},
		{"a prefix not absolute", func(s *storeYAML) { s.Etcd.Prefix = "port49/" }, true, true, "store.etcd.prefix"},
		{"a hold too short", func(s *storeYAML) { s.Etcd.HoldTTL = time.Second }, true, true, "store.etcd.hold_ttl"},
		// The floor (8b re-review 2 R2-I1, round 3b): clientv3's keepalive
		// loop checks every 500ms, so a healthy lease can report as little as
		// floor(2*ttl/3 - 0.5s - RTT); at 10s that stays at half of ttl or
		// more for a round trip up to about 1.17s, and below 10s the bound
		// shrinks to 0.5s or less.
		{"a hold under 10s", func(s *storeYAML) { s.Etcd.HoldTTL = 9 * time.Second }, true, true,
			"store.etcd.hold_ttl 9s: must be 10s to 1m0s"},
		{"a start timeout too short", func(s *storeYAML) { d := time.Second; s.Etcd.StartTimeoutSet = &d }, true, true,
			"store.etcd.start_timeout"},
	} {
		y := etcdYAML(dir)
		c.edit(&y)
		if _, err := checkStore(y, c.broker, c.admin); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
