package port49d

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
// stores.directory.etcd, each indented four spaces (the stores: nesting indents
// them two more).
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
	var deeper strings.Builder
	for _, l := range strings.SplitAfter(etcdLines, "\n") {
		if l != "" {
			deeper.WriteString("  " + l)
		}
	}
	raw = append(raw, []byte("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://127.0.0.1:2379]\n"+
		"      ca_file: "+ca+"\n      daemon: {cert_file: "+d[0]+", key_file: "+d[1]+"}\n"+
		"      broker: {cert_file: "+b[0]+", key_file: "+b[1]+"}\n"+deeper.String())...)
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
		"stores.directory.etcd.roles: unenforced",
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

// The two files must name one keyspace: roles for a prefix the other
// component does not use would grant nothing it needs.
func TestStoreRolesRefusesTwoKeyspaces(t *testing.T) {
	f := splitFleet(t)
	raw, err := os.ReadFile(f.broker)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "port49-broker.yaml")
	if err := os.WriteFile(other, []byte(strings.Replace(string(raw), "      call_timeout:",
		"      prefix: /other/\n      call_timeout:", 1)), 0o600); err != nil {
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
		out.Len() != 0 || !strings.Contains(errb.String(), "stores.directory.etcd.daemon") {
		t.Fatalf("no daemon identity: exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := storeRolesCmd([]string{"--config", f.daemon, "--broker-config", f.daemon}, &out, &errb); code != 1 ||
		out.Len() != 0 || !strings.Contains(errb.String(), "stores.directory.etcd.broker") {
		t.Fatalf("no broker identity: exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

// writeTwoStoreRolesConfig is writeStoreRolesConfig with a directory store
// of its own at dir-0 and the session store at sess-0, each naming both
// identities.
func writeTwoStoreRolesConfig(t *testing.T, dir, ca string, d, b [2]string) string {
	t.Helper()
	base := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	block := func(name, ep string) string {
		return "  " + name + ":\n    backend: etcd\n    etcd:\n      endpoints: [https://" + ep + ":2379]\n" +
			"      ca_file: " + ca + "\n      daemon: {cert_file: " + d[0] + ", key_file: " + d[1] + "}\n" +
			"      broker: {cert_file: " + b[0] + ", key_file: " + b[1] + "}\n"
	}
	raw = append(raw, []byte("\nstores:\n"+block("directory", "dir-0")+block("session", "sess-0"))...)
	p := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// R23: with a directory store of its own, a section per store, each run
// against its own cluster; on the directory the daemon reads rv/, meta/ping
// and meta/seal_keys alone, and on the session store it is granted no rv/.
func TestStoreRolesPrintsASectionPerStore(t *testing.T) {
	single := storeRolesFixture(t, "port49-daemon", "port49-broker")
	dir := filepath.Dir(single)
	cfg := writeTwoStoreRolesConfig(t, dir, filepath.Join(dir, "ca.pem"),
		[2]string{filepath.Join(dir, "daemon.pem"), filepath.Join(dir, "daemon-key.pem")},
		[2]string{filepath.Join(dir, "broker.pem"), filepath.Join(dir, "broker-key.pem")})
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	text := out.String()
	d := strings.Index(text, "# port49 roles for the directory store")
	s := strings.Index(text, "# port49 roles for the session store")
	if d < 0 || s < d {
		t.Fatalf("the sections:\n%s", text)
	}
	dirPart, sessPart := text[d:s], text[s:]
	for _, want := range []string{
		"ETCDCTL_ENDPOINTS=https://dir-0:2379",
		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/rv/",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/ping",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/seal_keys",
		"the second section's role add lines fail",
		"etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/",
	} {
		if !strings.Contains(dirPart, want) {
			t.Fatalf("the directory section lacks %q:\n%s", want, dirPart)
		}
	}
	if strings.Contains(dirPart, "/port49/v1/c/") {
		t.Fatalf("the directory section grants the contexts:\n%s", dirPart)
	}
	if !strings.Contains(sessPart, "ETCDCTL_ENDPOINTS=https://sess-0:2379") ||
		strings.Contains(sessPart, "port49_daemon read --prefix=true /port49/v1/rv/") {
		t.Fatalf("the session section:\n%s", sessPart)
	}
}

// twoStoreRolesFixture is a config with a store of its own for each of the
// directory and the session.
func twoStoreRolesFixture(t *testing.T) string {
	t.Helper()
	single := storeRolesFixture(t, "port49-daemon", "port49-broker")
	dir := filepath.Dir(single)
	return writeTwoStoreRolesConfig(t, dir, filepath.Join(dir, "ca.pem"),
		[2]string{filepath.Join(dir, "daemon.pem"), filepath.Join(dir, "daemon-key.pem")},
		[2]string{filepath.Join(dir, "broker.pem"), filepath.Join(dir, "broker-key.pem")})
}

// rewriteConfig replaces old with repl once in the file at path.
func rewriteConfig(t *testing.T, path, old, repl string, n int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), old) {
		t.Fatalf("%q is not in %s", old, path)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), old, repl, n)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An endpoint is printed into a comment of the script etcd's root runs; one
// that holds anything a shell reads is refused by store-roles itself (config
// refuses a newline or a path first, but passes a ";" in a host). It is
// refused, and nothing is printed even though the directory section is
// sound.
func TestStoreRolesRefusesAnUnsafeEndpoint(t *testing.T) {
	cfg := twoStoreRolesFixture(t)
	rewriteConfig(t, cfg, "[https://sess-0:2379]", `["https://x;etcdctl-auth-disable:2379"]`, 1)
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 ||
		!strings.Contains(errb.String(), "stores.session.etcd.endpoints \"https://x;etcdctl-auth-disable:2379\" holds a character") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

// One file with a session store of its own and the other without are not
// one fleet: refused, nothing printed.
func TestStoreRolesRefusesFilesThatDisagreeOnTheSplit(t *testing.T) {
	one := storeRolesFixture(t, "port49-daemon", "port49-broker")
	two := twoStoreRolesFixture(t)
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", one, "--broker-config", two}, &out, &errb); code != 1 ||
		out.Len() != 0 || !strings.Contains(errb.String(), "disagree on whether stores.session is a store of its own") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

// --broker-config wins over a broker identity port49d.yaml also names.
func TestStoreRolesBrokerConfigWinsOverTheDaemonFilesBroker(t *testing.T) {
	stale := storeRolesFixture(t, "port49-daemon", "stale-broker")
	given := storeRolesFixture(t, "port49-daemon", "port49-broker")
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", stale, "--broker-config", given}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "etcdctl user add port49-broker --no-password") ||
		strings.Contains(out.String(), "stale-broker") {
		t.Fatalf("%s", out.String())
	}
}

// A session section lacking its broker identity is refused, naming the
// session store's key.
func TestStoreRolesRefusesASessionSectionMissingItsIdentity(t *testing.T) {
	cfg := twoStoreRolesFixture(t)
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.LastIndex(string(raw), "      broker: {")
	j := i + strings.Index(string(raw)[i:], "\n") + 1
	if err := os.WriteFile(cfg, append(raw[:i:i], raw[j:]...), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 ||
		!strings.Contains(errb.String(), "stores.session.etcd.broker") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}
