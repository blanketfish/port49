package port49d

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/testpki"
)

// storeRolesFixture writes a CA and a client certificate per CN into dir,
// and a port49d.yaml naming them, the first CN as the daemon's.
func storeRolesFixture(t *testing.T, daemonCN, brokerCN string) string {
	t.Helper()
	return storeRolesFixtureWith(t, daemonCN, brokerCN, "")
}

// storeRolesFixtureWith is storeRolesFixture with etcd lines added to
// store.etcd, each indented four spaces.
func storeRolesFixtureWith(t *testing.T, daemonCN, brokerCN, etcdLines string) string {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	ca, err := testpki.NewCA("ca", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var ids [][2]string
	for i, cn := range []string{daemonCN, brokerCN} {
		c, err := ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		cp, kp, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		name := []string{"daemon", "broker"}[i]
		ids = append(ids, [2]string{write(name+".pem", cp), write(name+"-key.pem", kp)})
	}
	return writeStoreRolesConfig(t, dir, write("ca.pem", ca.PEM()), ids[0], ids[1], etcdLines)
}

// writeStoreRolesConfig writes a minimal valid port49d.yaml with a broker:
// block and a store: block naming those files.
func writeStoreRolesConfig(t *testing.T, dir, ca string, d, b [2]string, etcdLines string) string {
	t.Helper()
	base := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("\nstore:\n  backend: etcd\n  etcd:\n    endpoints: [https://127.0.0.1:2379]\n"+
		"    ca_file: "+ca+"\n    daemon: {cert_file: "+d[0]+", key_file: "+d[1]+"}\n"+
		"    broker: {cert_file: "+b[0]+", key_file: "+b[1]+"}\n"+etcdLines+
		"admin_socket: "+filepath.Join(dir, "admin.sock")+"\n")...) // etcd needs one (Task 10, I16)
	p := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// port49d store-roles prints the etcdctl commands for the keyspace and
// the two certificates' CNs, and touches nothing (spec §12).
func TestStoreRolesPrintsTheCommands(t *testing.T) {
	cfg := storeRolesFixture(t, "port49-daemon", "port49-broker")
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, want := range []string{
		"etcdctl role add port49_daemon",
		"etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/t/",
		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/rv/",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/witness\n",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/purged\n",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/seal_keys\n",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/judged_bundle\n",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/ping\n",
		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/lw/",
		"etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/",
		"etcdctl user add port49-daemon --no-password",
		"etcdctl user grant-role port49-daemon port49_daemon",
		"etcdctl user grant-role port49-broker port49_broker",
		// The residual, no wider than the spec's (§12; decision 35).
		"port49d holds it alone (plan 7e)",
		"store.etcd.roles: unenforced",
		"if a role already exists, check it with etcdctl role get first",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	for _, never := range []string{"/port49/v1/id/", "/port49/v1/meta/", "/port49/v1/rv/", "/port49/v1/tp/", "/port49/v1/tc/"} {
		if strings.Contains(out.String(), "port49_daemon readwrite --prefix=true "+never) {
			t.Errorf("the daemon is granted write on %s", never)
		}
	}
	for _, never := range []string{"/port49/v1/meta/ ", "/port49/v1/meta/judged\n", "/port49/v1/meta/holder"} {
		if strings.Contains(out.String(), "port49_daemon read --prefix=true "+never) ||
			strings.Contains(out.String(), "port49_daemon read "+never) {
			t.Errorf("the daemon is granted a read on %s", never)
		}
	}
	if strings.Contains(out.String(), "meta/ ") || strings.Contains(out.String(), "port49_daemon read --prefix=true /port49/v1/meta/\n") {
		t.Errorf("the daemon is granted meta/ whole:\n%s", out.String())
	}
	for _, never := range []string{"/port49/v1/id/", "/port49/v1/tp/", "/port49/v1/tc/"} {
		if strings.Contains(out.String(), "port49_daemon read --prefix=true "+never) {
			t.Errorf("the daemon is granted a read on %s", never)
		}
	}
	if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), "-key.pem") {
		t.Errorf("the output names a key:\n%s", out.String())
	}
}

// A CN or prefix holding anything a shell would read is refused, never
// printed into commands etcd's root runs (pre-flight M34). Config takes
// such a prefix (it must only start with /), so the refusal is
// store-roles' own.
func TestStoreRolesRefusesAShellUnsafeName(t *testing.T) {
	for name, cfg := range map[string]string{
		"a daemon CN": storeRolesFixture(t, "port49-daemon; rm -rf /", "port49-broker"),
		"a broker CN": storeRolesFixture(t, "port49-daemon", "port49-broker`id`"),
		"a prefix":    storeRolesFixtureWith(t, "port49-daemon", "port49-broker", "    prefix: \"/port49 $(x)/\"\n"),
	} {
		var out, errb bytes.Buffer
		if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 ||
			!strings.Contains(errb.String(), "A-Za-z0-9") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, out.String(), errb.String())
		}
	}
}

// A certificate whose CN is root is refused for either component,
// printing nothing: etcd would take it as its administrator (Ruling
// T11-a). Config refuses it first.
func TestStoreRolesRefusesRoot(t *testing.T) {
	for _, cns := range [][2]string{{"root", "port49-broker"}, {"port49-daemon", "root"}} {
		cfg := storeRolesFixture(t, cns[0], cns[1])
		var out, errb bytes.Buffer
		if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 ||
			!strings.Contains(errb.String(), `its CN is "root"`) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", cns, code, out.String(), errb.String())
		}
	}
}

// One certificate named for both components is refused: etcd would see
// one user, and the daemon would hold the broker's role.
func TestStoreRolesRefusesOneCNForBoth(t *testing.T) {
	cfg := storeRolesFixture(t, "port49", "port49")
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 ||
		!strings.Contains(errb.String(), "its own certificate") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

// A store on memory has no roles to make; a stray argument is usage.
func TestStoreRolesRefusesMemoryAndUsage(t *testing.T) {
	var out, errb bytes.Buffer
	cfg := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 ||
		!strings.Contains(errb.String(), "not etcd") {
		t.Fatalf("memory: exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := storeRolesCmd([]string{"--config", cfg, "extra"}, &out, &errb); code != 2 || out.Len() != 0 {
		t.Fatalf("usage: exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

// sevenDFile writes the fleet's daemon config as 7d's etcdRunServer wrote
// it: the broker: block and store.etcd.broker added back to port49d.yaml.
func (f *fleet) sevenDFile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(f.daemon)
	if err != nil {
		t.Fatal(err)
	}
	bro, err := os.ReadFile(f.broker)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(bro), "\nbroker:\n")
	if i < 0 {
		t.Fatal("port49-broker.yaml has no broker: block")
	}
	block, _, _ := strings.Cut(string(bro)[i+1:], "store:\n")
	bc, bk := f.srv.ClientFiles(t, "port49-broker")
	body := strings.Replace(string(raw), "\nstore:\n", "\n"+block+"store:\n", 1)
	body = strings.Replace(body, "    call_timeout:", "    broker: {cert_file: "+bc+", key_file: "+bk+"}\n    call_timeout:", 1)
	p := filepath.Join(t.TempDir(), "port49d.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// store-roles reads the daemon's CN from port49d.yaml and the broker's from
// port49-broker.yaml (Ruling 14); either alone is refused, naming the other.
func TestStoreRolesReadsBothFiles(t *testing.T) {
	f := splitFleet(t)
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", f.daemon, "--broker-config", f.broker}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/lw/") ||
		!strings.Contains(out.String(), "etcdctl user add port49-broker --no-password") {
		t.Fatalf("%s", out.String())
	}
	errb.Reset()
	if code := storeRolesCmd([]string{"--config", f.daemon}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "--broker-config") {
		t.Fatalf("one file: exit %d, %s", code, errb.String())
	}
}

// A 7d port49d.yaml naming both identities still yields both roles with
// no --broker-config, and says to move the broker's identity (pre-flight
// I8: StoreBlocks reads it with no role; Load would refuse it).
func TestStoreRolesStillReadsA7dFile(t *testing.T) {
	f := splitFleet(t)
	old := f.sevenDFile(t) // port49d.yaml as 7d wrote it: a broker: block and both identities
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", old}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "etcdctl user add port49-broker --no-password") ||
		!strings.Contains(errb.String(), "port49-broker.yaml") {
		t.Fatalf("out %s; err %s", out.String(), errb.String())
	}
	if _, err := config.Load(old); err == nil {
		t.Fatal("control: Load under the daemon's role must refuse the 7d file on etcd")
	}
}

// The two files must name one keyspace: roles for a prefix the other
// component does not use would grant nothing it needs.
func TestStoreRolesRefusesTwoKeyspaces(t *testing.T) {
	f := splitFleet(t)
	raw, err := os.ReadFile(f.broker)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "port49-broker.yaml")
	if err := os.WriteFile(other, []byte(strings.Replace(string(raw), "    call_timeout:",
		"    prefix: /other/\n    call_timeout:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", f.daemon, "--broker-config", other}, &out, &errb); code != 1 ||
		out.Len() != 0 || !strings.Contains(errb.String(), "different keyspaces") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

// A file passed for the wrong component is refused naming the identity it
// lacks: port49-broker.yaml as --config, port49d.yaml as --broker-config.
func TestStoreRolesRefusesAFileMissingItsIdentity(t *testing.T) {
	f := splitFleet(t)
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", f.broker, "--broker-config", f.broker}, &out, &errb); code != 1 ||
		out.Len() != 0 || !strings.Contains(errb.String(), "store.etcd.daemon") {
		t.Fatalf("no daemon identity: exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := storeRolesCmd([]string{"--config", f.daemon, "--broker-config", f.daemon}, &out, &errb); code != 1 ||
		out.Len() != 0 || !strings.Contains(errb.String(), "store.etcd.broker") {
		t.Fatalf("no broker identity: exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

// A 7d --config that still names store.etcd.broker, beside a --broker-config,
// is warned about, naming both CNs, and the --broker-config's wins: the
// stale identity cannot run (config.Load refuses that file at port49d's
// start), so the operator mid-migration needs a line, not a refusal.
func TestStoreRolesWarnsOfAStaleBrokerIdentity(t *testing.T) {
	f := splitFleet(t)
	old := f.sevenDFile(t)
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", old, "--broker-config", f.broker}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, want := range []string{"still names store.etcd.broker", "CN \"port49-broker\"", f.broker, "port49d refuses at start"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q: %s", want, errb.String())
		}
	}
	if !strings.Contains(out.String(), "etcdctl user add port49-broker --no-password") {
		t.Fatalf("%s", out.String())
	}
}
