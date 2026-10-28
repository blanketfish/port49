package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
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
	s, err := checkStore("stores.directory", storeYAML{}, true, RoleDaemon, false, false)
	if err != nil || s.Backend != BackendMemory || s.PacketDeadline != 2*time.Second || s.Etcd != nil {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestEtcdTakesItsDefaults(t *testing.T) {
	s, err := checkStoreShape("stores.directory", etcdYAML(storeFiles(t)), true)
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
	zero := zeroDuration(0)
	y.Etcd.StartTimeoutSet = &zero
	s, err := checkStoreShape("stores.directory", y, true)
	if err != nil || s.Etcd.StartTimeout != 0 {
		t.Fatalf("%+v %v", s.Etcd, err)
	}
}

func TestTheStoreRefusesWhatWouldRunUnsafely(t *testing.T) {
	dir := storeFiles(t)
	for _, c := range []struct {
		name string
		edit func(*storeYAML)
		want string
	}{
		{"unknown backend", func(s *storeYAML) { s.Backend = "redis" }, `stores.directory.backend "redis": must be memory or etcd`},
		{"etcd with no block", func(s *storeYAML) { s.Etcd = nil }, "stores.directory.etcd is missing"},
		{"a block on memory", func(s *storeYAML) { s.Backend = "memory" }, "stores.directory.etcd is set but stores.directory.backend is memory"},
		{"plain http", func(s *storeYAML) { s.Etcd.Endpoints = []string{"http://etcd-0:2379"} }, "must be https://"},
		{"no endpoints", func(s *storeYAML) { s.Etcd.Endpoints = nil }, "stores.directory.etcd.endpoints is empty"},
		{"a key file missing", func(s *storeYAML) { s.Etcd.Daemon.KeyFile = filepath.Join(dir, "nope.pem") },
			"stores.directory.etcd.daemon.key_file"},
		{"roles misspelt", func(s *storeYAML) { s.Etcd.Roles = "off" }, `stores.directory.etcd.roles "off"`},
		{"a deadline past 2s", func(s *storeYAML) { s.PacketDeadline = 2500 * time.Millisecond },
			"stores.directory.packet_deadline"},
		{"a deadline under the call's", func(s *storeYAML) {
			s.PacketDeadline, s.Etcd.CallTimeout = 200*time.Millisecond, time.Second
		}, "at least stores.directory.etcd.call_timeout"},
		{"a prefix not absolute", func(s *storeYAML) { s.Etcd.Prefix = "port49/" }, "stores.directory.etcd.prefix"},
		{"an endpoint with a path", func(s *storeYAML) { s.Etcd.Endpoints = []string{"https://etcd-0:2379/v3"} },
			"stores.directory.etcd.endpoints[0] must be https://host:port, with no user information, path, query or fragment"},
		{"an endpoint with a query", func(s *storeYAML) { s.Etcd.Endpoints = []string{"https://etcd-0:2379?x=1"} },
			"stores.directory.etcd.endpoints[0] must be https://host:port"},
		// port49d's working directory is not a place its trust roots should
		// depend on, as inventory.service's files (checkService).
		{"a relative ca_file", func(s *storeYAML) { s.Etcd.CAFile = "ca.pem" },
			"stores.directory.etcd.ca_file must be an absolute path"},
		{"a relative key_file", func(s *storeYAML) { s.Etcd.Broker.KeyFile = "b-key.pem" },
			"stores.directory.etcd.broker.key_file must be an absolute path"},
		{"a hold too short", func(s *storeYAML) { s.Etcd.HoldTTL = time.Second }, "stores.directory.etcd.hold_ttl"},
		// The floor (8b re-review 2 R2-I1, round 3b): clientv3's keepalive
		// loop checks every 500ms, so a healthy lease can report as little as
		// floor(2*ttl/3 - 0.5s - RTT); at 10s that stays at half of ttl or
		// more for a round trip up to about 1.17s, and below 10s the bound
		// shrinks to 0.5s or less.
		{"a hold under 10s", func(s *storeYAML) { s.Etcd.HoldTTL = 9 * time.Second },
			"stores.directory.etcd.hold_ttl 9s: must be 10s to 1m0s"},
		{"a start timeout too short", func(s *storeYAML) { d := zeroDuration(time.Second); s.Etcd.StartTimeoutSet = &d },
			"stores.directory.etcd.start_timeout"},
	} {
		y := etcdYAML(dir)
		c.edit(&y)
		if _, err := checkStoreShape("stores.directory", y, true); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// Each role on etcd holds its own identity alone (plan 7e, Rulings 1, 2):
// port49d.yaml names the daemon's, its policy, and no broker;
// port49-broker.yaml names the broker's, and never runs on memory. Each refusal names the key.
func TestEachRoleHoldsItsOwnIdentityAlone(t *testing.T) {
	dir := storeFiles(t)
	daemon := func(s *storeYAML) { s.Etcd.Broker = nil }
	brk := func(s *storeYAML) { s.Etcd.Daemon = EtcdIdentity{} }
	for _, c := range []struct {
		name           string
		role           Role
		edit           func(*storeYAML)
		broker, policy bool
		want           string
	}{
		{"the daemon with a broker block", RoleDaemon, daemon, true, false, "move the broker: block"},
		{"the daemon with no policy", RoleDaemon, daemon, false, false, "under policy: (file, watch_interval)"},
		{"the daemon naming the broker's identity", RoleDaemon, func(*storeYAML) {}, false, true,
			"stores.directory.etcd.broker: the broker's identity is port49-broker's alone"},
		{"the daemon with no identity", RoleDaemon, func(s *storeYAML) { daemon(s); s.Etcd.Daemon = EtcdIdentity{} },
			false, true, "stores.directory.etcd.daemon is missing"},
		{"the broker with no identity", RoleBroker, func(s *storeYAML) { brk(s); s.Etcd.Broker = nil }, true, false,
			"stores.directory.etcd.broker is missing"},
		{"the broker naming the daemon's identity", RoleBroker, func(*storeYAML) {}, true, false,
			"stores.directory.etcd.daemon: the daemon's identity is port49d's alone"},
		{"the broker on memory", RoleBroker, func(s *storeYAML) { *s = storeYAML{} }, true, false,
			"port49-broker runs on etcd"},
	} {
		y := etcdYAML(dir)
		c.edit(&y)
		if _, err := checkStore("stores.directory", y, true, c.role, c.broker, c.policy); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	y := etcdYAML(dir)
	daemon(&y)
	if s, err := checkStore("stores.directory", y, true, RoleDaemon, false, true); err != nil || s.Etcd.Broker != nil {
		t.Errorf("the split daemon: %+v %v", s, err)
	}
	y = etcdYAML(dir)
	brk(&y)
	if s, err := checkStore("stores.directory", y, true, RoleBroker, true, false); err != nil || s.Etcd.Broker == nil {
		t.Errorf("the broker: %+v %v", s, err)
	}
	if s, err := checkStore("stores.directory", storeYAML{}, true, RoleDaemon, true, false); err != nil || s.Backend != BackendMemory {
		t.Errorf("the in-process broker on memory: %+v %v", s, err)
	}
}

// An endpoint is never echoed: user information there is a password, and
// the error goes to stderr and the journal. It is refused, named by its
// index alone (review I1).
func TestAnEndpointsCredentialIsNeverPrinted(t *testing.T) {
	for _, ep := range []string{"https://alice:hunter2@etcd-0:2379", "http://alice:hunter2@etcd-0:2379"} {
		y := etcdYAML(storeFiles(t))
		y.Etcd.Endpoints = []string{"https://etcd-1:2379", ep}
		_, err := checkStoreShape("stores.directory", y, true)
		if err == nil || !strings.Contains(err.Error(), "stores.directory.etcd.endpoints[1]") ||
			strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("%s: %v", ep, err)
		}
	}
}

// storeDoc is a port49d.yaml whose store is etcd, with startTimeout as
// the start_timeout line ("" for none).
func storeDoc(dir, startTimeout string) string {
	doc := "broker: {listen: \":8443\"}\nstores:\n  directory:\n    backend: etcd\n    etcd:\n" +
		"      endpoints: [https://etcd-0:2379]\n      ca_file: " + filepath.Join(dir, "ca.pem") + "\n" +
		"      daemon: {cert_file: " + filepath.Join(dir, "d.pem") + ", key_file: " + filepath.Join(dir, "d-key.pem") + "}\n" +
		"      broker: {cert_file: " + filepath.Join(dir, "b.pem") + ", key_file: " + filepath.Join(dir, "b-key.pem") + "}\n"
	if startTimeout != "" {
		doc += "      start_timeout: " + startTimeout + "\n"
	}
	return doc
}

// start_timeout: 0, as the spec writes it, decodes and waits forever
// (pre-flight I19): yaml.v3 alone refuses a bare 0 for a duration.
func TestABareZeroStartTimeoutWaitsForever(t *testing.T) {
	dir := storeFiles(t)
	for _, c := range []struct {
		line string
		want time.Duration
	}{{"0", 0}, {"0s", 0}, {"45s", 45 * time.Second}, {"", 30 * time.Second}} {
		s, err := StoresBlocks([]byte(storeDoc(dir, c.line)))
		if err != nil || s.Directory.Etcd.StartTimeout != c.want {
			t.Fatalf("start_timeout %q: %+v %v, want %v", c.line, s.Directory.Etcd, err, c.want)
		}
	}
	if _, err := StoresBlocks([]byte(storeDoc(dir, "5"))); err == nil {
		t.Fatal("start_timeout: 5 loaded: a bare number other than 0 has no unit")
	}
	// The unmarshaler is the scalar's alone, so stores.directory.etcd is still decoded
	// strictly: a misspelt key beside it is refused, never ignored.
	if _, err := StoresBlocks([]byte(storeDoc(dir, "0") + "      start_timout: 0\n")); err == nil ||
		!strings.Contains(err.Error(), "an unknown field") {
		t.Fatalf("a misspelt key beside start_timeout: %v", err)
	}
}

// A store refusal reads as every other load refusal does (review M1).
func TestAStoreRefusalIsAConfigError(t *testing.T) {
	_, err := StoresBlocks([]byte("stores: {directory: {backend: redis}}\n"))
	if err == nil || !strings.HasPrefix(err.Error(), `config: stores.directory.backend "redis"`) {
		t.Fatalf("%v", err)
	}
}

// A store identity whose certificate's CN is root is refused at load,
// for either component: etcd would take it as its administrator, past
// every role (Ruling T11-a). A file that is not a certificate is left
// to port49d's start, which names it.
func TestAStoreIdentityNamedRootIsRefused(t *testing.T) {
	dir := storeFiles(t)
	now := time.Now()
	ca, err := testpki.NewCA("ca", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, cn := range []string{"root", "port49-x"} {
		c, err := ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		cp, _, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, cn+".pem"), cp, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name string
		edit func(*storeYAML)
		want string
	}{
		{"the daemon's", func(s *storeYAML) { s.Etcd.Daemon.CertFile = filepath.Join(dir, "root.pem") },
			`stores.directory.etcd.daemon.cert_file: its CN is "root"`},
		{"the broker's", func(s *storeYAML) { s.Etcd.Broker.CertFile = filepath.Join(dir, "root.pem") },
			`stores.directory.etcd.broker.cert_file: its CN is "root"`},
	} {
		y := etcdYAML(dir)
		c.edit(&y)
		if _, err := checkStoreShape("stores.directory", y, true); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	y := etcdYAML(dir)
	y.Etcd.Daemon.CertFile = filepath.Join(dir, "port49-x.pem")
	if _, err := checkStoreShape("stores.directory", y, true); err != nil {
		t.Errorf("another CN: %v", err)
	}
	// checkStoreShape holds the check, so StoreBlocks refuses it as Load
	// and LoadBroker do (pre-flight I8).
	root := filepath.Join(dir, "root.pem")
	if _, err := StoresBlocks([]byte(strings.Replace(storeDoc(dir, ""), filepath.Join(dir, "d.pem"), root, 1))); err == nil ||
		!strings.Contains(err.Error(), `stores.directory.etcd.daemon.cert_file: its CN is "root"`) {
		t.Errorf("StoreBlocks, the daemon's: %v", err)
	}
	if _, err := StoresBlocks([]byte(strings.Replace(storeDoc(dir, ""), filepath.Join(dir, "b.pem"), root, 1))); err == nil ||
		!strings.Contains(err.Error(), `stores.directory.etcd.broker.cert_file: its CN is "root"`) {
		t.Errorf("StoreBlocks, the broker's: %v", err)
	}
	certAt := regexp.MustCompile(`cert_file: \S+,`)
	if _, err := loadDaemonRole(t, certAt.ReplaceAllString(daemonRoleYAML(t), "cert_file: "+root+",")); err == nil ||
		!strings.Contains(err.Error(), `stores.directory.etcd.daemon.cert_file: its CN is "root"`) {
		t.Errorf("Load, the daemon's: %v", err)
	}
	if _, err := loadBrokerRole(t, certAt.ReplaceAllString(brokerRoleYAML(t), "cert_file: "+root+",")); err == nil ||
		!strings.Contains(err.Error(), `stores.directory.etcd.broker.cert_file: its CN is "root"`) {
		t.Errorf("LoadBroker, the broker's: %v", err)
	}
}

// stores.directory.etcd.health takes its defaults, and the cache is off until its
// ttl is set (plan 7f, Rulings 3, 5): the design asks for the TTL as
// explicit configuration, so port49 never picks one.
func TestHealthDefaultsAndTheCacheIsOffUntilSet(t *testing.T) {
	s, err := checkStoreShape("stores.directory", etcdYAML(storeFiles(t)), true)
	if err != nil {
		t.Fatal(err)
	}
	if h := s.Etcd.Health; h.Interval != time.Second || h.CloseAfter != 5 || h.OpenAfter != 3 {
		t.Fatalf("health %+v", h)
	}
	if c := s.Etcd.ContextCache; c.TTL != 0 || c.MaxEntries != 65536 {
		t.Fatalf("context_cache %+v", c)
	}
	y := etcdYAML(storeFiles(t))
	y.Etcd.ContextCacheSet = &EtcdContextCache{TTL: 2 * time.Second}
	y.Etcd.HealthSet = &EtcdHealth{Interval: 500 * time.Millisecond, CloseAfter: 3}
	s, err = checkStoreShape("stores.directory", y, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Etcd.ContextCache.TTL != 2*time.Second || s.Etcd.ContextCache.MaxEntries != 65536 ||
		s.Etcd.Health.Interval != 500*time.Millisecond || s.Etcd.Health.CloseAfter != 3 || s.Etcd.Health.OpenAfter != 3 {
		t.Fatalf("%+v %+v", s.Etcd.Health, s.Etcd.ContextCache)
	}
}

func TestHealthAndCacheBounds(t *testing.T) {
	dir := storeFiles(t)
	for _, c := range []struct {
		name string
		edit func(*storeYAML)
		want string
	}{
		{"an interval too short", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{Interval: 100 * time.Millisecond} },
			"stores.directory.etcd.health.interval 100ms: must be 200ms to 10s"},
		{"an interval too long", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{Interval: 11 * time.Second} },
			"stores.directory.etcd.health.interval 11s: must be 200ms to 10s"},
		{"close after negative", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{CloseAfter: -1} },
			"stores.directory.etcd.health.close_after -1: must be 2 to 60"},
		{"a cache ttl too short", func(s *storeYAML) { s.Etcd.ContextCacheSet = &EtcdContextCache{TTL: 50 * time.Millisecond} },
			"stores.directory.etcd.context_cache.ttl 50ms: must be 100ms to 1m0s"},
		{"close after one", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{CloseAfter: 1} },
			"stores.directory.etcd.health.close_after 1: must be 2 to 60"},
		{"open after too many", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{OpenAfter: 61} },
			"stores.directory.etcd.health.open_after 61: must be 1 to 60"},
		{"a cache ttl of minutes", func(s *storeYAML) { s.Etcd.ContextCacheSet = &EtcdContextCache{TTL: 2 * time.Minute} },
			`stores.directory.etcd.context_cache.ttl 2m0s: must be 100ms to 1m0s ("seconds, not minutes": design §12)`},
		{"a cache with no ttl", func(s *storeYAML) { s.Etcd.ContextCacheSet = &EtcdContextCache{MaxEntries: 10} },
			"stores.directory.etcd.context_cache.ttl is not set: the cache's ttl is explicit configuration (design §12)"},
		{"a cache too large", func(s *storeYAML) {
			s.Etcd.ContextCacheSet = &EtcdContextCache{TTL: time.Second, MaxEntries: 1 << 21}
		}, "stores.directory.etcd.context_cache.max_entries 2097152: must be 1 to 1048576"},
	} {
		y := etcdYAML(dir)
		c.edit(&y)
		if _, err := checkStoreShape("stores.directory", y, true); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// Both blocks are port49d's: the broker never closes a listener on the
// store and serves no device (Ruling 7).
func TestTheBrokerRefusesTheDaemonsStoresBlocks(t *testing.T) {
	dir := storeFiles(t)
	for _, c := range []struct {
		edit func(*storeYAML)
		want string
	}{
		{func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{} }, "stores.directory.etcd.health is port49d's"},
		{func(s *storeYAML) { s.Etcd.ContextCacheSet = &EtcdContextCache{TTL: time.Second} }, "stores.directory.etcd.context_cache is port49d's"},
	} {
		y := etcdYAML(dir)
		y.Etcd.Daemon = EtcdIdentity{}
		c.edit(&y)
		if _, err := checkStore("stores.directory", y, true, RoleBroker, true, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v, want %q", err, c.want)
		}
	}
}

// max_entries 0 in a present block is the default, like every other key.
func TestCacheMaxEntriesZeroIsTheDefault(t *testing.T) {
	y := etcdYAML(storeFiles(t))
	y.Etcd.ContextCacheSet = &EtcdContextCache{TTL: time.Second, MaxEntries: 0}
	s, err := checkStoreShape("stores.directory", y, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Etcd.ContextCache.MaxEntries != 65536 {
		t.Fatalf("%+v", s.Etcd.ContextCache)
	}
}

// The health interval bounds each check, which is port49d's: a daemon whose
// call_timeout exceeds the interval is refused; the broker, which runs no
// check and cannot set health, loads with any call_timeout.
func TestHealthIntervalAgainstCallTimeoutIsPort49dsAlone(t *testing.T) {
	y := etcdYAML(storeFiles(t))
	y.Etcd.Broker = nil
	y.Etcd.CallTimeout = 2 * time.Second
	if _, err := checkStore("stores.directory", y, true, RoleDaemon, false, true); err == nil ||
		!strings.Contains(err.Error(), "stores.directory.etcd.health.interval 1s: must be at least stores.directory.etcd.call_timeout (2s), which bounds each check") {
		t.Errorf("daemon: %v", err)
	}
	y.Etcd.HealthSet = &EtcdHealth{Interval: 2 * time.Second}
	if _, err := checkStore("stores.directory", y, true, RoleDaemon, false, true); err != nil {
		t.Errorf("daemon with interval raised: %v", err)
	}
	b := etcdYAML(storeFiles(t))
	b.Etcd.Daemon = EtcdIdentity{}
	b.Etcd.CallTimeout = 2 * time.Second
	if _, err := checkStore("stores.directory", b, true, RoleBroker, true, false); err != nil {
		t.Errorf("broker: %v", err)
	}
}

// The yaml tags: both blocks decode from a real port49d.yaml, and the
// broker's file refuses health.
func TestHealthAndCacheDecodeFromYAML(t *testing.T) {
	raw := daemonRoleYAML(t) + "      health: {interval: 2s, close_after: 4}\n      context_cache: {ttl: 5s}\n"
	c, err := loadDaemonRole(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	e := c.Stores.Session.Etcd
	if e.Health.Interval != 2*time.Second || e.Health.CloseAfter != 4 || e.Health.OpenAfter != 3 ||
		e.ContextCache.TTL != 5*time.Second || e.ContextCache.MaxEntries != 65536 {
		t.Fatalf("%+v %+v", e.Health, e.ContextCache)
	}
	if _, err := loadBrokerRole(t, brokerRoleYAML(t)+"      health: {}\n"); err == nil ||
		!strings.Contains(err.Error(), "stores.directory.etcd.health is port49d's") {
		t.Errorf("broker: %v", err)
	}
}
