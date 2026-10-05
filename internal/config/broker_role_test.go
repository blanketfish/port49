package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// brokerRoleYAML is a port49-broker.yaml that loads under the broker's
// role; each test changes one key.
func brokerRoleYAML(t *testing.T) string {
	t.Helper()
	dir := storeFiles(t)
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{
		"inventory_file: " + write(t, "inv.yaml", inv),
		"key_refs: [prod_key]",
		"encryption:",
		"  current: {id: v2, secret_env: PORT49_ENC_V2}",
		"admin_socket: " + filepath.Join(dir, "broker.sock"),
		"broker:",
		"  listen: 127.0.0.1:0",
		"  tls_cert_file: /etc/port49/broker.pem",
		"  tls_key_file: /etc/port49/broker-key.pem",
		"  client_ca_file: /etc/port49/clients-ca.pem",
		"  policy_file: /etc/port49/policy.yaml",
		"  state_dir: " + state,
		"  certificate_status: {disabled: true}",
		"store:",
		"  backend: etcd",
		"  etcd:",
		"    endpoints: [https://etcd-0:2379]",
		"    ca_file: " + filepath.Join(dir, "ca.pem"),
		"    broker: {cert_file: " + filepath.Join(dir, "b.pem") + ", key_file: " + filepath.Join(dir, "b-key.pem") + "}",
	}, "\n") + "\n"
}

func loadBrokerRole(t *testing.T, raw string) (Config, error) {
	t.Helper()
	setKeyEnv(t)
	return LoadBroker(write(t, "port49-broker.yaml", raw))
}

// daemonRoleYAML is a port49d.yaml on etcd with no broker: the daemon's
// identity alone, and the policy it admits from under policy:.
func daemonRoleYAML(t *testing.T) string {
	t.Helper()
	dir := storeFiles(t)
	return fmt.Sprintf(sampleHead, write(t, "inv.yaml", inv)) +
		"encryption:\n  current: {id: v2, secret_env: PORT49_ENC_V2}\n" +
		"policy: {file: /etc/port49/policy.yaml}\n" +
		"admin_socket: " + filepath.Join(dir, "admin.sock") + "\n" +
		"store:\n  backend: etcd\n  etcd:\n    endpoints: [https://etcd-0:2379]\n" +
		"    ca_file: " + filepath.Join(dir, "ca.pem") + "\n" +
		"    daemon: {cert_file: " + filepath.Join(dir, "d.pem") + ", key_file: " + filepath.Join(dir, "d-key.pem") + "}\n"
}

func loadDaemonRole(t *testing.T, raw string) (Config, error) {
	t.Helper()
	setKeyEnv(t)
	return Load(write(t, "port49d.yaml", raw))
}

// A port49-broker.yaml loads under the broker's role: key_refs are its key
// names, its policy is broker.policy_file, and metrics default to :9050.
func TestABrokerConfigLoads(t *testing.T) {
	c, err := loadBrokerRole(t, brokerRoleYAML(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.Role != RoleBroker || len(c.KeyRefs()) != 1 || c.KeyRefs()[0] != "prod_key" || c.Policy == nil ||
		c.MetricsListen != ":9050" || c.Broker.StateDir == "" {
		t.Fatalf("%+v", c)
	}
	// KeyRefs comes back sorted, whatever order the file names them in.
	c, err = loadBrokerRole(t, strings.Replace(brokerRoleYAML(t), "key_refs: [prod_key]", "key_refs: [zeta_key, prod_key]", 1))
	if err != nil || strings.Join(c.KeyRefs(), " ") != "prod_key zeta_key" {
		t.Fatalf("%q %v", c.KeyRefs(), err)
	}
}

// The broker never holds a device key, nor the daemon's etcd identity, nor
// speaks TACACS+ (Review Focus 9; Rulings 1, 2): each is refused naming
// the key.
func TestTheBrokersConfigNeverNamesADeviceKey(t *testing.T) {
	for key, extra := range map[string]string{
		"keys:":                   "keys: {prod_key: {current: {version: 3, secret_env: T_PROD_V3}}}\n",
		"listen":                  "listen: :49\n",
		"store.etcd.daemon":       "", // added under store.etcd below
		"accounting":              "accounting: {spool_capacity: 10}\n",
		"limits":                  "limits: {per_nas_connections: 4}\n",
		"receipt_idle_ttl":        "receipt_idle_ttl: 5m\n",
		"platforms":               "platforms: {arista_eos: {session_services: [shell]}}\n",
		"policy:":                 "policy: {file: /etc/port49/policy.yaml}\n",
		"broker.revocations_file": "",
		"lab.fault_file":          "lab: {fault_file: /tmp/f}\n",
	} {
		raw := brokerRoleYAML(t) + extra
		switch key {
		case "store.etcd.daemon":
			raw = strings.Replace(raw, "    broker: {", "    daemon: {cert_file: /x, key_file: /y}\n    broker: {", 1)
		case "broker.revocations_file":
			raw = strings.Replace(raw, "  state_dir:", "  revocations_file: /var/lib/port49/r.json\n  state_dir:", 1)
		}
		if _, err := loadBrokerRole(t, raw); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("port49-broker.yaml with %s loaded, or the refusal does not name it: %v", key, err)
		}
	}
}

// port49-broker.yaml requires each of these, naming it.
func TestTheBrokersConfigRequiresItsKeys(t *testing.T) {
	for _, cut := range []string{"key_refs:", "state_dir:", "admin_socket:", "backend: etcd", "    broker: {",
		"  current: {id: v2"} {
		var lines []string
		for _, l := range strings.Split(brokerRoleYAML(t), "\n") {
			if !strings.Contains(l, cut) {
				lines = append(lines, l)
			}
		}
		if _, err := loadBrokerRole(t, strings.Join(lines, "\n")); err == nil {
			t.Errorf("port49-broker.yaml without %q loaded", cut)
		}
	}
}

// port49d.yaml on etcd never names the broker's identity, never carries a
// broker: block, and names the policy it admits from (Review Focus 9;
// Rulings 1, 2).
func TestTheDaemonsConfigNeverNamesTheBrokersIdentity(t *testing.T) {
	base := daemonRoleYAML(t)
	if c, err := loadDaemonRole(t, base); err != nil || c.Policy == nil || c.Broker != nil {
		t.Fatalf("the split daemon's config: %+v %v", c, err)
	}
	withBrokerID := strings.Replace(base, "    daemon: {", "    broker: {cert_file: /x, key_file: /y}\n    daemon: {", 1)
	if _, err := loadDaemonRole(t, withBrokerID); err == nil || !strings.Contains(err.Error(), "store.etcd.broker") {
		t.Fatalf("a daemon config naming the broker's identity: %v", err)
	}
	withBlock := strings.Replace(base, "policy: {file: /etc/port49/policy.yaml}\n", brokerBlock, 1)
	if _, err := loadDaemonRole(t, withBlock); err == nil || !strings.Contains(err.Error(), "port49-broker.yaml") {
		t.Fatalf("a broker: block in port49d.yaml on etcd: %v", err)
	}
	noPolicy := strings.Replace(base, "policy: {file: /etc/port49/policy.yaml}\n", "", 1)
	if _, err := loadDaemonRole(t, noPolicy); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("port49d.yaml on etcd with no policy: %v", err)
	}
}

// StoreBlocks reads either file's store: block whatever role would load
// it (pre-flight I8): a 7d port49d.yaml naming both identities yields
// both, as store-roles needs; Load under the daemon's role refuses the
// same file. A block whose shape is wrong is refused by both.
func TestStoreBlocksReadsEitherFileWithNoRole(t *testing.T) {
	dir := storeFiles(t)
	both := []byte(storeDoc(dir, ""))
	sc, err := StoreBlocks(both)
	if err != nil || sc.Etcd == nil || sc.Etcd.Daemon.CertFile == "" || sc.Etcd.Broker == nil {
		t.Fatalf("a 7d file's two identities: %+v %v", sc, err)
	}
	if sc, err := StoreBlocks([]byte(brokerRoleYAML(t))); err != nil || sc.Etcd.Broker == nil ||
		sc.Etcd.Daemon.CertFile != "" {
		t.Fatalf("port49-broker.yaml: %+v %v", sc, err)
	}
	if sc, err := StoreBlocks([]byte(daemonRoleYAML(t))); err != nil || sc.Etcd.Broker != nil ||
		sc.Etcd.Daemon.CertFile == "" {
		t.Fatalf("port49d.yaml with no broker: %+v %v", sc, err)
	}
	misshapen := strings.Replace(storeDoc(dir, ""), "    endpoints: [https://etcd-0:2379]", "    endpoints: []", 1)
	if _, err := StoreBlocks([]byte(misshapen)); err == nil || !strings.Contains(err.Error(), "endpoints") {
		t.Fatalf("a store block with no endpoint was read: %v", err)
	}
}

// The rest of what port49-broker.yaml refuses: a receipt bound, and every
// lab: key but the seeds, which port49-broker mints (Ruling 2). Each is
// refused naming the key, and the seeds alone load.
func TestTheBrokersConfigRefusesWhatIsPort49dsAlone(t *testing.T) {
	for key, extra := range map[string]string{
		"receipt_max_age":         "receipt_max_age: 1h\n",
		"lab.session_attributes":  "lab: {session_attributes: [priv-lvl=15]}\n",
		"lab.command_attributes":  "lab: {command_attributes: [priv-lvl=15]}\n",
		"lab.deny_prefixes":       "lab: {deny_prefixes: [reload]}\n",
		"lab.deny_message_length": "lab: {deny_message_length: 64}\n",
		"lab.deny_session":        "lab: {deny_session: true}\n",
	} {
		if _, err := loadBrokerRole(t, brokerRoleYAML(t)+extra); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("port49-broker.yaml with %s: %v", key, err)
		}
	}
	seeds := "lab:\n  seed_token_file: /tmp/p49-seeds.jsonl\n  seed_tokens:\n    - {nas: leaf-01, username: alice}\n"
	if c, err := loadBrokerRole(t, brokerRoleYAML(t)+seeds); err != nil || len(c.Lab.SeedTokens) != 1 {
		t.Fatalf("port49-broker.yaml with lab seeds: %+v %v", c.Lab, err)
	}
}

// key_refs are names, each once, and at least one. One that is not a name
// is refused by its index and never printed: it may be a secret pasted
// where its name goes.
func TestTheBrokersKeyRefsAreNamesEachOnce(t *testing.T) {
	for _, c := range []struct{ refs, want string }{
		{"[]", "key_refs is required"},
		{"[prod_key, prod_key]", "key_refs[1] prod_key"},
		{"[prod_key, \"hunter2 hunter2\"]", "key_refs[1] is not a valid key_ref name"},
	} {
		raw := strings.Replace(brokerRoleYAML(t), "key_refs: [prod_key]", "key_refs: "+c.refs, 1)
		_, err := loadBrokerRole(t, raw)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("key_refs: %s: %v, want %q", c.refs, err, c.want)
		}
	}
}

// broker.state_dir is an absolute path to a directory that exists: the
// broker keeps its CRLs there, and a start is no time to find it missing.
// Each refusal says which.
func TestTheBrokersStateDirIsAnExistingAbsoluteDirectory(t *testing.T) {
	notDir := write(t, "plain", "x")
	for _, c := range []struct{ dir, want string }{
		{`""`, "broker.state_dir is required in port49-broker.yaml"},
		{"state", "broker.state_dir must be an absolute path"},
		{filepath.Join(t.TempDir(), "missing"), "must be a directory that exists"},
		{notDir, "must be a directory that exists"},
	} {
		var lines []string
		for _, l := range strings.Split(brokerRoleYAML(t), "\n") {
			if strings.Contains(l, "state_dir:") {
				l = "  state_dir: " + c.dir
			}
			lines = append(lines, l)
		}
		if _, err := loadBrokerRole(t, strings.Join(lines, "\n")); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("state_dir %s: %v, want %q", c.dir, err, c.want)
		}
	}
}

// port49-broker runs on etcd: with the memory store there is nothing to
// separate, and the broker runs in port49d.
func TestTheBrokerRunsOnEtcd(t *testing.T) {
	raw := brokerRoleYAML(t)
	raw = raw[:strings.Index(raw, "store:")]
	if _, err := loadBrokerRole(t, raw); err == nil || !strings.Contains(err.Error(), "port49-broker runs on etcd") {
		t.Fatalf("port49-broker.yaml on memory: %v", err)
	}
}

// key_refs and broker.state_dir are port49-broker.yaml's: in port49d.yaml
// each would be ignored, so each is refused naming the key.
func TestPort49BrokerYamlsKeysAreRefusedInPort49dYaml(t *testing.T) {
	if _, err := loadWith(t, "key_refs: [prod_key]\n"); err == nil || !strings.Contains(err.Error(), "key_refs") {
		t.Errorf("key_refs in port49d.yaml: %v", err)
	}
	if _, err := loadWith(t, brokerBlock+"  state_dir: /var/lib/port49\n"); err == nil ||
		!strings.Contains(err.Error(), "broker.state_dir") {
		t.Errorf("broker.state_dir in port49d.yaml: %v", err)
	}
}

// port49d on etcd mints no lab seed: port49-broker does (Ruling 2).
func TestTheDaemonOnEtcdMintsNoSeed(t *testing.T) {
	raw := daemonRoleYAML(t) + "lab:\n  seed_token_file: /tmp/p49-seeds.jsonl\n  seed_tokens:\n    - {nas: leaf-01, username: alice}\n"
	if _, err := loadDaemonRole(t, raw); err == nil || !strings.Contains(err.Error(), "lab.seed_tokens") {
		t.Fatalf("seeds in port49d.yaml on etcd: %v", err)
	}
}

// policy: names its file, and watch_interval is bounded as
// broker.policy_watch_interval is.
func TestThePolicyBlock(t *testing.T) {
	c, err := loadDaemonRole(t, daemonRoleYAML(t))
	if err != nil || c.Policy.File != "/etc/port49/policy.yaml" || c.Policy.WatchInterval != 5*time.Second ||
		c.Admission != nil {
		t.Fatalf("%+v %v", c.Policy, err)
	}
	for block, want := range map[string]string{
		"policy: {watch_interval: 10s}\n":                  "policy.file is required",
		"policy: {file: /p.yaml, watch_interval: 500ms}\n": "policy.watch_interval must be between 1s and 5m",
		"policy: {file: /p.yaml, watch_interval: 6m}\n":    "policy.watch_interval must be between 1s and 5m",
	} {
		raw := strings.Replace(daemonRoleYAML(t), "policy: {file: /etc/port49/policy.yaml}\n", block, 1)
		if _, err := loadDaemonRole(t, raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", strings.TrimSpace(block), err, want)
		}
	}
	// On etcd the policy is required, so the refusal never advises removing
	// the block; on memory it may.
	raw := strings.Replace(daemonRoleYAML(t), "policy: {file: /etc/port49/policy.yaml}\n", "policy: {watch_interval: 10s}\n", 1)
	if _, err := loadDaemonRole(t, raw); err == nil || !strings.Contains(err.Error(), "name the policy file port49d admits from") ||
		strings.Contains(err.Error(), "remove the block") {
		t.Errorf("policy: with no file on etcd: %v", err)
	}
	if _, err := loadWith(t, "policy: {watch_interval: 10s}\n"); err == nil || !strings.Contains(err.Error(), "remove the block") {
		t.Errorf("policy: with no file on memory: %v", err)
	}
	raw = strings.Replace(daemonRoleYAML(t), "policy: {file: /etc/port49/policy.yaml}\n",
		"policy: {file: /p.yaml, watch_interval: 30s}\n", 1)
	if c, err := loadDaemonRole(t, raw); err != nil || c.Policy.WatchInterval != 30*time.Second {
		t.Fatalf("30s: %+v %v", c.Policy, err)
	}
}

// port49-broker.yaml with no broker: block is refused, named: it would
// have no listener and no policy.
func TestTheBrokersConfigRequiresABrokerBlock(t *testing.T) {
	var lines []string
	in := false
	for _, l := range strings.Split(brokerRoleYAML(t), "\n") {
		switch {
		case l == "broker:":
			in = true
			continue
		case in && strings.HasPrefix(l, "  "):
			continue
		}
		in = false
		lines = append(lines, l)
	}
	if _, err := loadBrokerRole(t, strings.Join(lines, "\n")); err == nil || !strings.Contains(err.Error(), "broker: is required") {
		t.Fatalf("port49-broker.yaml with no broker: block: %v", err)
	}
}

// inventory.service is applied against the policy in force, so policy:
// with no broker is enough for it (decision 29; Task 13 review M-4).
func TestTheInventoryServiceTakesThePolicyBlock(t *testing.T) {
	c, err := loadService(t, false, false, serviceBlock(t)+"policy: {file: /etc/port49/p.yaml}\n")
	if err != nil || c.InventoryService == nil || c.Policy == nil || c.Broker != nil {
		t.Fatalf("%+v %v", c.Policy, err)
	}
}

// StoreBlocks refuses a stale seed key with staleSeedKeys' line, naming
// the minter, before the strict decode can say only that the field is
// unknown (Task 13 review M-5).
func TestStoreBlocksSaysWhereAStaleSeedKeyWent(t *testing.T) {
	raw := storeDoc(storeFiles(t), "") + "lab:\n  seed_tokens:\n    - {nas: leaf-01, username: alice, secret: x}\n"
	if _, err := StoreBlocks([]byte(raw)); err == nil || !strings.Contains(err.Error(), `"secret" was removed`) {
		t.Fatalf("%v", err)
	}
}

// Under the broker's role the kept CRLs sit in broker.state_dir, so a list
// whose kept file would be another file the broker names is refused
// (Task 13 review M-6).
func TestTheBrokersKeptListsAreInItsStateDir(t *testing.T) {
	raw := brokerRoleYAML(t)
	state := regexp.MustCompile(`(?m)^  state_dir: (\S+)$`).FindStringSubmatch(raw)[1]
	raw = strings.Replace(raw, "  policy_file: /etc/port49/policy.yaml", "  policy_file: "+filepath.Join(state, "crl-main.der"), 1)
	raw = strings.Replace(raw, "  certificate_status: {disabled: true}",
		"  certificate_status: {crls: [{name: main, file: /etc/port49/main.crl, issuer_file: /etc/port49/ca.pem}]}", 1)
	if _, err := loadBrokerRole(t, raw); err == nil || !strings.Contains(err.Error(), "its kept list") ||
		!strings.Contains(err.Error(), "broker.policy_file") {
		t.Fatalf("%v", err)
	}
}

// broker.state_dir holds what the broker alone writes (its kept CRLs, and
// from Task 15 its copy of the marks), so it is fenced as the revocations
// file is: never a directory others can write, and never inside, nor
// around, a directory the inventory service rewrites (Task 13 review I-2).
// A 0700 or 0750 directory, as a container or Kubernetes volume mounts
// one, loads.
func TestTheBrokersStateDirIsItsOwn(t *testing.T) {
	stateOf := func(raw string) string {
		return regexp.MustCompile(`(?m)^  state_dir: (\S+)$`).FindStringSubmatch(raw)[1]
	}
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		raw := brokerRoleYAML(t)
		if err := os.Chmod(stateOf(raw), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBrokerRole(t, raw); err == nil || !strings.Contains(err.Error(), "broker.state_dir") ||
			!strings.Contains(err.Error(), "chmod 0700 it, or point broker.state_dir at a 0700 directory of its own inside the volume") {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o700, 0o750} {
		raw := brokerRoleYAML(t)
		if err := os.Chmod(stateOf(raw), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBrokerRole(t, raw); err != nil {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	// The inventory service's directories, by key.
	withService := func(raw, stateDir, mirrorDir string) string {
		raw = regexp.MustCompile(`(?m)^inventory_file: .*\n`).ReplaceAllString(raw, "")
		block := strings.Replace(serviceBlock(t), "    state_dir: /var/lib/port49/inventory\n", "    state_dir: "+stateDir+"\n", 1)
		if mirrorDir != "" {
			block += "    mirror_dir: " + mirrorDir + "\n"
		}
		return raw + block
	}
	for _, c := range []struct {
		name string
		edit func(state string) (svcState, mirror string)
		want string
	}{
		{"inside the service's state_dir", func(s string) (string, string) { return filepath.Dir(s), "" },
			"inventory.service.state_dir"},
		{"around the service's state_dir", func(s string) (string, string) { return filepath.Join(s, "inv"), "" },
			"inventory.service.state_dir"},
		{"the service's mirror_dir", func(s string) (string, string) { return "/var/lib/port49/inventory", s },
			"inventory.service.mirror_dir"},
	} {
		raw := brokerRoleYAML(t)
		svc, mirror := c.edit(stateOf(raw))
		if _, err := loadBrokerRole(t, withService(raw, svc, mirror)); err == nil || !strings.Contains(err.Error(), "broker.state_dir") ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	raw := brokerRoleYAML(t)
	if c, err := loadBrokerRole(t, withService(raw, "/var/lib/port49/inventory", "/var/lib/port49/mirror")); err != nil ||
		c.InventoryService == nil {
		t.Errorf("disjoint directories: %v", err)
	}
}
