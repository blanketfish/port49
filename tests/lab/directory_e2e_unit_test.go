//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/policy"
)

// The directory end-to-end's configs, derived from the compose lab's, load
// under the real loaders in their roles: a broker with the directory block
// the brief names, a daemon with the lab's staleness ceiling. A run that fails
// here would fail minutes into a stack's start.
func TestDirectoryE2EConfigsLoad(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files, err := composeLabFiles(read("port49d-lab.yaml"), read(filepath.Join("slice", "broker.yaml")),
		read(filepath.Join("slice", "policy.yaml")), read("inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e2eFiles(files); err != nil {
		t.Fatal(err)
	}
	// The containers' paths, moved under a temporary directory with the files
	// the loaders insist on reading.
	dir := t.TempDir()
	t.Setenv("PORT49_LAB_KEY", "labsecret")
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	for _, d := range []string{"etc/etcd", "etc/broker", "directory", "run", "state", "spool"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"etc/etcd/ca.pem", "etc/etcd/port49d.pem", "etc/etcd/port49d-key.pem", "etc/etcd/port49-broker.pem",
		"etc/etcd/port49-broker-key.pem", "etc/broker/broker.pem", "etc/broker/broker-key.pem", "etc/broker/broker-ca.pem",
		"directory/users-ca.pem", "directory/directory-ca.pem", "directory/directory-client.pem",
		"directory/directory-client-key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	requireDaemonPolicy(t, files)
	placeComposeSecrets(t, dir, files)
	moved := func(s string) string {
		s = strings.ReplaceAll(s, e2eDirDir, filepath.Join(dir, "directory"))
		s = strings.ReplaceAll(s, "/etc/port49", filepath.Join(dir, "etc"))
		s = strings.ReplaceAll(s, "/var/lib/port49-broker", filepath.Join(dir, "state"))
		s = strings.ReplaceAll(s, "/var/spool/port49d", filepath.Join(dir, "spool"))
		return strings.ReplaceAll(s, "/run/port49", filepath.Join(dir, "run"))
	}
	for name, body := range files {
		if strings.HasSuffix(name, ".yaml") {
			if err := os.WriteFile(filepath.Join(dir, "etc", name), []byte(moved(body)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	b, err := config.LoadBroker(filepath.Join(dir, "etc", "port49-broker.yaml"))
	if err != nil {
		t.Fatalf("the broker's config does not load: %v\n%s", err, moved(files["port49-broker.yaml"]))
	}
	if b.Broker == nil || b.Broker.Directory == nil || b.Broker.RefreshInterval != e2eRefreshInterval {
		t.Fatalf("the broker block: %+v", b.Broker)
	}
	d := b.Broker.Directory
	if d.Nested != "recursive" || d.Grace != e2eGrace || d.PrincipalAttribute != "mail" || d.UsernameAttribute != "uid" ||
		d.Mapping.Kind != "san_email" || !d.Mapping.AllowWeak || len(d.Mapping.Issuers) != 1 || d.Mapping.Issuers[0] != dirUsersCAIssuer ||
		d.Bind.Mechanism != "external" || d.Site != "lab" || len(d.Servers) != 1 || d.Servers[0].URI != "ldaps://openldap:636" ||
		d.PrewarmInterval != 5*time.Minute || d.Servers[0].Priority != 100 || d.Servers[0].Site != "lab" {
		t.Errorf("the directory block resolved to %+v", d)
	}
	if !strings.Contains(files["port49-broker.yaml"], "client_ca_file: "+e2eDirDir+"/users-ca.pem") {
		t.Errorf("the broker does not trust the users CA for client certificates:\n%s", files["port49-broker.yaml"])
	}

	dm, err := config.Load(filepath.Join(dir, "etc", "port49d.yaml"))
	if err != nil {
		t.Fatalf("port49d's config does not load: %v\n%s", err, moved(files["port49d.yaml"]))
	}
	if dm.Session.StalenessCeiling != e2eCeiling {
		t.Errorf("port49d's staleness ceiling is %s, want %s", dm.Session.StalenessCeiling, e2eCeiling)
	}
	// broker.directory is told by its base_dn: stores.directory: is a store.
	if strings.Contains(files["port49d.yaml"], "base_dn:") {
		t.Errorf("port49d.yaml names a directory; the broker's alone does:\n%s", files["port49d.yaml"])
	}
}

// The lab policy loads: a group subject with no username, an identity subject
// with none, each granted network_admin on every device.
func TestDirectoryE2EPolicyLoads(t *testing.T) {
	p, err := policy.Parse([]byte(e2ePolicy), policy.Env{})
	if err != nil {
		t.Fatalf("the lab policy does not load: %v", err)
	}
	if p == nil {
		t.Fatal("no policy")
	}
}

// The overlay names every file the test writes and the broker reads, and the
// service the compose project needs for openldap.
func TestDirectoryE2EOverlayNamesWhatTheTestWrites(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("compose", "directory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	o := string(raw)
	for _, want := range []string{"directory-ca.pem", "users-ca.pem", "directory-client.pem", "directory-client-key.pem",
		"/etc/port49-directory", "openldap.env", "LAB_OPENLDAP_WRITER", "directory/openldap-pki:/pki:ro"} {
		if !strings.Contains(o, want) {
			t.Errorf("tests/lab/compose/directory.yaml lacks %q", want)
		}
	}
	// The key is the broker's alone, 0600, owned by the uid the image runs as.
	if !strings.Contains(o, "install -o 65532 -g 65532 -m 0600 /src/directory-client-key.pem") {
		t.Error("the directory client key is not installed 0600 for uid 65532")
	}
}

func TestDirectoryE2EParseGauge(t *testing.T) {
	text := "# HELP x\nport49_other 3\nport49_directory_refresh_last_complete_timestamp_seconds 1.7e+09\n"
	if got, err := parseGauge(text, refreshComplete); err != nil || got != 1.7e9 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := parseGauge(text, "port49_missing"); err == nil {
		t.Fatal("a missing metric read as a value")
	}
}

func TestDirectoryE2EMembershipKeys(t *testing.T) {
	list := "/port49/v1/c/leaf1/alice\n\n/port49/v1/mb/user:alice@corp.example.com\n/port49/v1/mk/x\n"
	got := membershipKeys(list)
	if len(got) != 1 || !anyContains(got, "alice") || anyContains(got, "bob") {
		t.Fatalf("got %v", got)
	}
}

// Removing g-leaf from g-mid adds a placeholder member in the same modify:
// groupOfNames needs one, and g-leaf is g-mid's only. Putting it back is the
// reverse.
func TestDirectoryE2EMemberLDIF(t *testing.T) {
	rm, add := e2eMemberLDIF(true), e2eMemberLDIF(false)
	if !strings.Contains(rm, "add: member\nmember: cn=nobody") || !strings.Contains(rm, "delete: member\nmember: cn=g-leaf") {
		t.Errorf("the removal:\n%s", rm)
	}
	if !strings.Contains(add, "add: member\nmember: cn=g-leaf") || !strings.Contains(add, "delete: member\nmember: cn=nobody") {
		t.Errorf("the restore:\n%s", add)
	}
}

func TestDirectoryE2EPlatforms(t *testing.T) {
	if !e2ePlatform("arista_eos") || !e2ePlatform("juniper_vjunos-router") || e2ePlatform("cisco_nxos") || e2ePlatform("juniper_vsrx") {
		t.Fatal("the end-to-end runs on arista_eos and juniper_vjunos-router only")
	}
}
