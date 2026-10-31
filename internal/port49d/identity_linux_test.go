//go:build linux

package port49d

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// keptKeys waits for the key file at path: a Fetch returning does not mean
// its Save ran (Task 4 moved Save out of the fetch flight).
func keptKeys(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fetched keys were never kept at %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stateDirT is a state directory as ownStateDir accepts one: 0700, whatever
// the umask.
func stateDirT(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenOIDCSharesOneKeySetPerIssuer(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := stateDirT(t)
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	set, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Verifiers) != 2 || set.Verifiers[0].Keys != set.Verifiers[1].Keys {
		t.Fatalf("verifiers %+v: one issuer, one key set", set.Verifiers)
	}
	if err := set.Verifiers[0].Keys.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	keptKeys(t, keyFile(dir, iss.URL))
	cfg.Broker.Identity.OIDC = nil
	if set, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {}); err != nil || set != nil {
		t.Fatalf("no oidc verifier: %v %v", set, err)
	}
}

// Decision 1: the kept file is written whole or not at all, at 0600, and
// leaves no temporary file behind: a crash mid-write never truncates it.
func TestTheKeptKeyFileIsWrittenAtomicallyAndPrivately(t *testing.T) {
	dir := stateDirT(t)
	path := keyFile(dir, "https://sso.example.com")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnly(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("the key file is mode %04o, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("the key file holds %q", b)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("a stray file %s beside the key file", e.Name())
		}
	}
	// A rename that cannot happen leaves the old file whole.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnly(filepath.Join(dir, "sub"), []byte("x")); err == nil {
		t.Fatal("a directory was replaced by a key file")
	}
}

// Review Focus 3: a broker restarted while the provider is down validates
// from the kept keys.
func TestARestartDuringAnOutageKeepsTheKeys(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := stateDirT(t)
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	first, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Verifiers[0].Keys.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	keptKeys(t, keyFile(dir, iss.URL))
	raw := iss.IDToken(t, "k1", "port49-cli", "s", time.Now(), map[string]any{"email": "a@corp.example.com",
		"email_verified": true})
	iss.Close()
	var said syncBuffer
	second, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(f string, a ...any) {
		said.Write([]byte(fmtLine(f, a...)))
	})
	if err != nil {
		t.Fatal(err)
	}
	if a, err := second.Verify(context.Background(), raw); err != nil || a.Principal != "user:a@corp.example.com" {
		t.Fatalf("after a restart with the provider down: %+v %v", a, err)
	}
	if !strings.Contains(said.String(), "restored 1 keys fetched") {
		t.Fatalf("the restore was not said:\n%s", said.String())
	}
}

// Pre-flight M-21: a state directory the broker cannot keep keys in is said
// at start, when an OIDC verifier is configured, not first at a save.
func TestAnUnusableStateDirIsSaidAtStart(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := stateDirT(t)
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	notADir := writeFile(t, dir, "a-file", []byte("x"))
	var said syncBuffer
	if _, err := openOIDC(cfg, filepath.Join(notADir, "state"), metrics.New(prometheus.NewRegistry()),
		func(f string, a ...any) { said.Write([]byte(fmtLine(f, a...))) }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said.String(), "cannot keep the providers' keys") {
		t.Fatalf("an unusable state directory was not said:\n%s", said.String())
	}
}

// Review Focus 3: a kept key file is the broker's own; a link, or one
// another user owns, is refused, since it names the keys the broker trusts.
func TestAKeyFileTheBrokerDidNotWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := keyFile(dir, "https://sso.example.com")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnly(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a link: %v", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("the owner check needs root to chown (CI runs it as root)")
	}
	owned := keyFile(dir, "https://other.example.com")
	if err := os.WriteFile(owned, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(owned, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnly(owned); err == nil {
		t.Fatal("a key file another user owns was read")
	}
}

// Readiness never follows the provider (design §12; the Global Constraint
// this test pins; pre-flight I-12). The real start path runs with its only
// issuer unreachable and no kept keys: the key-set loop runs and says it has
// none, and /readyz still answers 200 serving. It mirrors 7g's
// TestReadinessNeverFollowsTheDirectory, and fails on any code that adds a
// key-set condition to readiness.
func TestReadinessNeverFollowsTheProvider(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, io.Discard
	iss := oidctest.NewIssuer(t)
	b := brokerConfig(t, minimalPolicy).Broker
	pki := filepath.Dir(b.ClientCAFile)
	ca := writeFile(t, pki, "idp-ca.pem", iss.CertPEM())
	issuer := iss.URL
	iss.Close() // unreachable from the start: nothing fetched, nothing kept
	cfgPath := writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	clientCA := regexp.MustCompile(`(?m)^  client_ca_file: .*\n`)
	if !clientCA.Match(raw) {
		t.Fatal("the run config has no client_ca_file to replace")
	}
	identity := fmt.Sprintf("  identity:\n    humans:\n      - {type: x509, trust_anchor_file: %s}\n"+
		"      - {type: oidc, issuer: %q, client_id: port49-cli, principal_claim: email, "+
		"principal_domains: [example.com], ca_file: %s}\n", b.ClientCAFile, issuer, ca)
	if err := os.WriteFile(cfgPath, clientCA.ReplaceAllLiteral(raw, []byte(identity)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	waitFor(t, &out, "identity: "+issuer+": no keys fetched yet")
	addr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	if code, body := brokerReadyz(t, pki, addr); code != http.StatusOK || body != broker.ReadyServing {
		t.Fatalf("broker /readyz with the provider unreachable: %d %q", code, body)
	}
}

// waitKeyFile waits for the key file the fetch of issuer saves in dir. The keys are saved after
// Fetch returns, by a write to a temporary file and a rename, so the file's presence means the
// save is done: a test that returns before it races its temporary directory's removal.
func waitKeyFile(t *testing.T, dir, issuer string) {
	t.Helper()
	kept := filepath.Join(dir, oidc.KeyFileName(issuer))
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(kept); err == nil {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("the fetched keys were never saved: %v", err)
		}
	}
}

// The stale-keys line restarts the process that runs the broker: port49d when
// it is embedded, port49-broker when it is the broker alone (final review F5).
func TestTheStaleKeysLineNamesTheRunningProcess(t *testing.T) {
	for _, tc := range []struct {
		role config.Role
		want string
	}{{config.RoleBroker, "and restart port49-broker"}, {config.RoleDaemon, "and restart port49d"}} {
		iss := oidctest.NewIssuer(t)
		dir := stateDirT(t)
		cfg := brokerConfig(t, directoryPolicy)
		cfg.Role = tc.role
		cfg.Broker.Identity = identityCfg(t, iss, dir)
		cfg.Broker.Identity.Timing.JWKSMaxAge = 20 * time.Millisecond
		var said syncBuffer
		set, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(f string, a ...any) {
			said.Write([]byte(fmtLine(f, a...)))
		})
		if err != nil {
			t.Fatal(err)
		}
		ks := set.Verifiers[0].Keys
		if err := ks.Fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitKeyFile(t, dir, iss.URL)
		iss.Fail(503)
		time.Sleep(60 * time.Millisecond)
		_ = ks.Fetch(context.Background())
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(said.String(), "no key refreshed within") && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if !strings.Contains(said.String(), tc.want) {
			t.Errorf("role %v: the stale line:\n%s", tc.role, said.String())
		}
	}
}

// openOIDC builds a key set for a k8s verifier, reading its jwks.
func TestOpenOIDCBuildsAClusterKeySet(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := stateDirT(t)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := k8sConfig()
	cfg.Broker.Identity.K8s[0].JWKS, cfg.Broker.Identity.K8s[0].CAFile = iss.URL+"/jwks", caFile
	cfg.Broker.StateDir = dir
	set, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	if err != nil || set == nil || len(set.Verifiers) != 1 || set.Verifiers[0].Kind != oidc.KindK8s {
		t.Fatalf("%v %+v", err, set)
	}
	if err := set.Verifiers[0].Keys.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitKeyFile(t, dir, cfg.Broker.Identity.K8s[0].Issuer)
	set.Verifiers[0].Keys.WaitNotes()
}

// A cluster whose ca_file does not load is refused naming the k8s verifier.
func TestAClusterCAFileThatDoesNotLoadIsRefusedByName(t *testing.T) {
	cfg := k8sConfig()
	cfg.Broker.StateDir = stateDirT(t)
	cfg.Broker.Identity.K8s[0].CAFile = filepath.Join(cfg.Broker.StateDir, "missing.pem")
	_, err := openOIDC(cfg, cfg.Broker.StateDir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "broker.identity machines k8s verifier 0") {
		t.Fatalf("%v", err)
	}
}

// A cluster migrating its issuer has two verifiers on one jwks; discovery
// names only the new issuer, and that is no mismatch for the old one's key
// set (decision 49 ruling 4). The control: the old verifier alone, over the
// same discovery, says its tokens are refused.
func TestAMigratingClusterKeySetsAreQuietAboutDiscoveryNamingTheOtherIssuer(t *testing.T) {
	const oldIssuer, newIssuer = "https://l69-a.port49.lab", "https://l69-a-new.port49.lab"
	notes := func(verifiers ...string) string {
		iss := oidctest.NewIssuer(t)
		iss.Discovery(func(d map[string]any) { d["issuer"] = newIssuer })
		dir := stateDirT(t)
		caFile := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(caFile, iss.CertPEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := k8sConfig()
		cfg.Broker.StateDir = dir
		base := cfg.Broker.Identity.K8s[0]
		base.JWKS, base.CAFile = iss.URL+"/jwks", caFile
		cfg.Broker.Identity.K8s = nil
		for _, issuer := range verifiers {
			v := base
			v.Issuer = issuer
			cfg.Broker.Identity.K8s = append(cfg.Broker.Identity.K8s, v)
		}
		var mu sync.Mutex
		var said strings.Builder
		set, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(f string, a ...any) {
			mu.Lock()
			defer mu.Unlock()
			fmt.Fprintf(&said, f+"\n", a...)
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range set.Verifiers {
			if err := v.Keys.Fetch(context.Background()); err != nil {
				t.Fatal(err)
			}
			v.Keys.WaitNotes()
		}
		for _, v := range cfg.Broker.Identity.K8s {
			waitKeyFile(t, dir, v.Issuer)
		}
		mu.Lock()
		defer mu.Unlock()
		return said.String()
	}
	if got := notes(oldIssuer); !strings.Contains(got, "names issuer "+newIssuer) {
		t.Fatalf("the control says nothing, so the test below proves nothing: %q", got)
	}
	if got := notes(oldIssuer, newIssuer); strings.Contains(got, "names issuer") {
		t.Fatalf("a migration is said to be a mismatch: %q", got)
	}
}
