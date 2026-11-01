package shapes

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/config"
)

// The systemd roots the shipped files name, each moved under a temporary
// directory by a plain string replacement, as the lab's unit tests do
// (tests/lab/directory_e2e_unit_test.go).
var roots = []string{"/etc/port49", "/var/spool/port49d", "/var/lib/port49-broker"}

// tree is a temporary filesystem the shipped files can be loaded against: the
// files the loaders insist on reading, made with obviously fake content, in
// directories at the modes the fence wants.
type tree struct {
	t    *testing.T
	dir  string
	move func(string) string
}

func newTree(t *testing.T) *tree {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir is 0777 under the umask; the fence refuses a group-writable ancestor.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tr := &tree{t: t, dir: dir}
	tr.move = func(s string) string {
		for _, r := range roots {
			s = strings.ReplaceAll(s, r, filepath.Join(dir, r))
		}
		return s
	}
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"/etc/port49", 0o755}, {"/etc/port49/keys", 0o750}, {"/etc/port49/secrets", 0o755},
		{"/etc/port49/etcd", 0o755}, {"/etc/port49/broker", 0o755},
		{"/var/spool/port49d", 0o700}, {"/var/lib/port49-broker", 0o700},
	} {
		tr.mkdir(d.path, d.mode)
	}
	for _, f := range []string{
		"/etc/port49/etcd/ca.pem", "/etc/port49/etcd/port49d.pem", "/etc/port49/etcd/port49d-key.pem",
		"/etc/port49/etcd/port49-broker.pem", "/etc/port49/etcd/port49-broker-key.pem",
		"/etc/port49/broker/broker.pem", "/etc/port49/broker/broker-key.pem", "/etc/port49/broker/client-ca.pem",
		"/etc/port49/tls/server.pem", "/etc/port49/tls/server-key.pem", "/etc/port49/tls/device-ca.pem",
	} {
		tr.write(f, "not-a-real-pem\n", 0o600)
	}
	tr.write("/etc/port49/secrets/encryption.key", "not-a-real-key-v1-not-a-real-key", 0o400)
	tr.write("/etc/port49/secrets/broker-encryption.key", "not-a-real-key-v1-not-a-real-key", 0o400)
	tr.write("/etc/port49/keys/example-v1", "not-a-real-key-v1\n", 0o440)
	return tr
}

func (tr *tree) mkdir(abs string, mode os.FileMode) {
	tr.t.Helper()
	p := filepath.Join(tr.dir, abs)
	if err := os.MkdirAll(p, mode); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) write(abs, body string, mode os.FileMode) {
	tr.t.Helper()
	p := filepath.Join(tr.dir, abs)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	// a file made 0400 cannot be opened for writing again
	_ = os.Remove(p)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		tr.t.Fatal(err)
	}
}

// install writes a shipped config, moved, as abs under the tree.
func (tr *tree) install(rel, abs string) string {
	tr.t.Helper()
	tr.write(abs, tr.move(read(tr.t, rel)), 0o644)
	return filepath.Join(tr.dir, abs)
}

// load installs the four files of a shipped set and loads both configs.
func (tr *tree) load(dir string) (d, b config.Config) {
	tr.t.Helper()
	tr.install(dir+"/policy.yaml", "/etc/port49/policy.yaml")
	tr.install(dir+"/inventory.yaml", "/etc/port49/inventory.yaml")
	dp := tr.install(dir+"/port49d.yaml", "/etc/port49/port49d.yaml")
	bp := tr.install(dir+"/port49-broker.yaml", "/etc/port49/port49-broker.yaml")
	d, err := config.Load(dp)
	if err != nil {
		tr.t.Fatalf("port49d.yaml does not load: %v", err)
	}
	b, err = config.LoadBroker(bp)
	if err != nil {
		tr.t.Fatalf("port49-broker.yaml does not load: %v", err)
	}
	return d, b
}

func TestTheSystemdConfigsLoad(t *testing.T) {
	tr := newTree(t)
	d, b := tr.load("deploy/systemd/config")
	if want := filepath.Join(tr.dir, "/etc/port49/keys"); d.KeySecretRefs.FileDir != want {
		t.Errorf("key_secret_refs.file_dir is %q, want %s", d.KeySecretRefs.FileDir, want)
	}
	for _, name := range []string{"port49d.yaml", "port49-broker.yaml"} {
		if strings.Contains(read(t, "deploy/systemd/config/"+name), "admin_socket") {
			t.Errorf("%s names admin_socket, which was removed", name)
		}
	}
	if got := len(d.Stores.Directory.Etcd.Endpoints); got != 3 {
		t.Errorf("port49d names %d etcd endpoints, want 3", got)
	}
	if got := len(b.Stores.Directory.Etcd.Endpoints); got != 3 {
		t.Errorf("the broker names %d etcd endpoints, want 3", got)
	}
	if d.Limits.MaxConnections != 0 {
		t.Errorf("limits.max_connections is %d: leave it unset, so it is sized from LimitNOFILE", d.Limits.MaxConnections)
	}
	if d.TLSListener != nil {
		t.Error("tls_listener is on in the shipped file; it ships commented out")
	}
}

// The TLS listener ships commented out, with its port. Uncommented, the file
// still loads.
func TestTheTLSListenerIsCommentedOut(t *testing.T) {
	raw := read(t, "deploy/systemd/config/port49d.yaml")
	block := regexp.MustCompile(`(?m)^# tls_listener:\n(?:#[^\n]*\n)+`).FindString(raw)
	if block == "" || !strings.Contains(block, `listen: ":300"`) {
		t.Fatalf("no commented # tls_listener: block with listen: \":300\"")
	}
	var live []string
	for _, ln := range strings.Split(strings.TrimSuffix(block, "\n"), "\n") {
		live = append(live, strings.TrimPrefix(strings.TrimPrefix(ln, "#"), " "))
	}
	tr := newTree(t)
	tr.install("deploy/systemd/config/policy.yaml", "/etc/port49/policy.yaml")
	tr.install("deploy/systemd/config/inventory.yaml", "/etc/port49/inventory.yaml")
	tr.write("/etc/port49/port49d.yaml", tr.move(strings.Replace(raw, block, strings.Join(live, "\n")+"\n", 1)), 0o644)
	c, err := config.Load(filepath.Join(tr.dir, "/etc/port49/port49d.yaml"))
	if err != nil {
		t.Fatalf("with tls_listener uncommented: %v", err)
	}
	if c.TLSListener == nil || c.TLSListener.Listen != ":300" {
		t.Errorf("tls_listener resolved to %+v", c.TLSListener)
	}
}

func TestTheStoreExamplesLoad(t *testing.T) {
	for _, set := range []string{"single-site", "multi-region"} {
		t.Run(set, func(t *testing.T) {
			tr := newTree(t)
			// the fragments are the stores: blocks of the systemd shape's files, so
			// the rest comes from it
			tr.install("deploy/systemd/config/policy.yaml", "/etc/port49/policy.yaml")
			tr.install("deploy/systemd/config/inventory.yaml", "/etc/port49/inventory.yaml")
			dp := tr.install("deploy/examples/stores/"+set+"/port49d.yaml", "/etc/port49/port49d.yaml")
			bp := tr.install("deploy/examples/stores/"+set+"/port49-broker.yaml", "/etc/port49/port49-broker.yaml")
			d, err := config.Load(dp)
			if err != nil {
				t.Fatalf("port49d.yaml: %v", err)
			}
			if _, err := config.LoadBroker(bp); err != nil {
				t.Fatalf("port49-broker.yaml: %v", err)
			}
			if set != "multi-region" {
				return
			}
			if got := len(d.Stores.Directory.Etcd.Endpoints); got != 3 {
				t.Errorf("stores.directory has %d members, want 3 (one per region)", got)
			}
			hosts := map[string]bool{}
			for _, e := range d.Stores.Directory.Etcd.Endpoints {
				hosts[e] = true
			}
			if len(hosts) != 3 {
				t.Errorf("stores.directory repeats a member: %v", d.Stores.Directory.Etcd.Endpoints)
			}
			if d.Stores.Shared || d.Stores.Session.Etcd == nil || len(d.Stores.Session.Etcd.Endpoints) == 0 {
				t.Fatalf("stores.session has no endpoints of its own (shared: %v)", d.Stores.Shared)
			}
			for _, e := range d.Stores.Session.Etcd.Endpoints {
				if hosts[e] {
					t.Errorf("stores.session shares the directory's member %s", e)
				}
			}
		})
	}
}

var (
	privateKey = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY`)
	secretRef  = regexp.MustCompile(`secret_ref:\s*"?([^\s"}]+)`)
)

func TestNoExampleHoldsASecret(t *testing.T) {
	n := 0
	err := filepath.WalkDir(filepath.Join("..", "..", "deploy"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.Contains(filepath.ToSlash(p), "/deploy/compose/local/") {
			return nil // the trial PKI, generated and git-ignored
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n++
		if privateKey.Match(raw) {
			t.Errorf("%s holds a private key", p)
		}
		for _, m := range secretRef.FindAllStringSubmatch(string(raw), -1) {
			if !strings.HasPrefix(m[1], "env:PORT49_") && !strings.HasPrefix(m[1], "file:") {
				t.Errorf("%s: secret_ref %q is neither env:PORT49_... nor file:", p, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("walked no file under deploy/")
	}
}

// The compose etcd is pinned by the digest the chart's example pins, and port49d and the broker carry the
// chart's hardening: a tag can move, and a container with a writable root and every capability is more than it needs.
func TestComposeIsPinnedAndHardenedLikeTheChart(t *testing.T) {
	digest := regexp.MustCompile(`etcd:v[0-9.]+@sha256:[0-9a-f]{64}`)
	compose := read(t, "deploy/compose/compose.yaml")
	want := digest.FindString(read(t, "deploy/helm/port49/examples/etcd/statefulset.yaml"))
	if want == "" || !strings.Contains(compose, want) {
		t.Errorf("compose's etcd is not pinned to the chart's %q", want)
	}
	for _, svc := range []string{"port49-broker", "port49d"} {
		i := strings.Index(compose, "\n  "+svc+":\n")
		if i < 0 {
			t.Fatalf("no %s service", svc)
		}
		block := compose[i+1:]
		if end := regexp.MustCompile("\n  [a-z]").FindStringIndex(block[3:]); end != nil {
			block = block[:3+end[0]] // up to the next service
		}
		for _, line := range []string{"no-new-privileges:true", "cap_drop: [ALL]", "read_only: true"} {
			if !strings.Contains(block, line) {
				t.Errorf("%s lacks %q", svc, line)
			}
		}
	}
}
