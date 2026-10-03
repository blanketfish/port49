package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/meta/",
		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/lw/",
		"etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/",
		"etcdctl user add port49-daemon --no-password",
		"etcdctl user grant-role port49-daemon port49_daemon",
		"etcdctl user grant-role port49-broker port49_broker",
		// The residual, no wider than the spec's (§12; decision 35).
		"until plan 7e port49d also holds the broker's",
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
