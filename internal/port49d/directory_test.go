package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// secretBindValue is a bind password's value in these tests: no line the
// process says may hold it.
const secretBindValue = "hunter2-the-bind-secret"

// directoryCfg is a broker.directory as config resolves it: two servers in
// one site, an issuer_serial mapping, a bind of mech.
func directoryCfg(mech string) *directory.Config {
	d := &directory.Config{
		Servers: []directory.Server{{URI: "ldaps://dc1.corp.example:636", Site: "hq", Priority: 100},
			{URI: "ldaps://dc2.corp.example", Site: "hq", Priority: 90}},
		Site: "hq", SiteFrom: "PORT49_SITE", CAFile: "/etc/port49/dir-ca.pem",
		BaseDN: "dc=corp,dc=example", GroupsBaseDN: "ou=groups,dc=corp,dc=example",
		PrincipalAttribute: "userPrincipalName", UsernameAttribute: "sAMAccountName",
		Mapping: directory.Mapping{Kind: directory.MapIssuerSerial, Attribute: "altSecurityIdentities"},
		Nested:  directory.Nested("in_chain"), MaxDepth: 16, QueryTimeout: 5 * time.Second,
		HealthInterval: 30 * time.Second, HealthTimeout: 2 * time.Second, FailureThreshold: 3,
		ProbeInterval: time.Minute, StabilityWindow: 5 * time.Minute, Grace: 4 * time.Hour,
		PrewarmInterval: time.Hour, PrewarmMax: 10000}
	switch mech {
	case "gssapi":
		d.Bind = directory.Bind{Mechanism: "gssapi", KeytabFile: "/etc/port49/svc.keytab",
			Principal: "svc-port49@CORP.EXAMPLE", KRB5Conf: "/etc/port49/krb5.conf"}
	case "simple":
		d.Bind = directory.Bind{Mechanism: "simple", BindDN: "cn=svc,dc=corp,dc=example", PasswordRef: "env:T_DIR_BIND_PW"}
	}
	return d
}

// The start says the pool, the bind (never its secret), the mapping, the
// nested mode, grace, pre-warm and the refresh (What the operator sees).
func TestTheDirectoryStartLines(t *testing.T) {
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("gssapi")
	cfg.Broker.RefreshInterval = 5 * time.Minute
	pol := buildPolicy(t, cfg, directoryPolicy)
	var out syncBuffer
	announceDirectory(&out, "port49-broker", cfg, pol)
	got := out.String()
	for _, want := range []string{
		"port49-broker: directory: 2 servers (dc1.corp.example:636 site hq priority 100, dc2.corp.example:636 site hq priority 90); " +
			"this broker's site is hq (PORT49_SITE); bind gssapi as svc-port49@CORP.EXAMPLE\n",
		"certificates map by issuer_serial (strong) through altSecurityIdentities; principal from userPrincipalName, " +
			"username from sAMAccountName; nested groups in_chain under ou=groups,dc=corp,dc=example\n",
		"must be writable only by directory administrators",
		"grace 4h0m0s; pre-warm every 1h0m0s; the scheduled refresh every 5m0s stamps refreshed_at",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the start lines lack %q:\n%s", want, got)
		}
	}
	// A server is named by its label alone, never its URI.
	if strings.Contains(got, "ldaps://") || strings.Contains(got, "svc.keytab") {
		t.Errorf("a URI or a keytab path in the start lines:\n%s", got)
	}
}

// With no x509 verifier there is no certificate mapping, and the start says
// so rather than naming a kind that is empty (plan 9e).
func TestTheStartSaysThereIsNoCertificateMapping(t *testing.T) {
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("gssapi")
	cfg.Broker.Directory.Mapping = directory.Mapping{}
	cfg.Broker.RefreshInterval = 5 * time.Minute
	var out syncBuffer
	announceDirectory(&out, "port49-broker", cfg, buildPolicy(t, cfg, directoryPolicy))
	got := out.String()
	if !strings.Contains(got, "port49-broker: directory: no certificate mapping (no x509 verifier); principal from "+
		"userPrincipalName, username from sAMAccountName; nested groups in_chain under ou=groups,dc=corp,dc=example\n") ||
		strings.Contains(got, "certificates map by") {
		t.Errorf("the start lines:\n%s", got)
	}
}

// A simple bind is said as the weakest, naming the env var, never its value.
func TestASimpleBindIsSaidAsTheWeakest(t *testing.T) {
	t.Setenv("T_DIR_BIND_PW", secretBindValue)
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("simple")
	cfg.Broker.RefreshInterval = 5 * time.Minute
	var out syncBuffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	if err := buildWith(cfg); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "bind simple as cn=svc,dc=corp,dc=example: the weakest of the three") ||
		!strings.Contains(got, "read from env:T_DIR_BIND_PW") {
		t.Errorf("the weakest bind is not said:\n%s", got)
	}
	if strings.Contains(got, secretBindValue) {
		t.Errorf("the bind password is in the start lines:\n%s", got)
	}
}

// Group subjects with no directory: said, by name (Ruling 17).
func TestGroupSubjectsWithoutADirectoryAreSaid(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: netops, group: netops-ro, token_ttl: 5m}
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: netops, scope: all_devices, roles: [r]}]
` + runKeys
	cfg := brokerConfig(t, body)
	var out syncBuffer
	announceDirectory(&out, "port49d", cfg, buildPolicy(t, cfg, body))
	want := "port49d: policy: 1 group subjects (netops) mint for no one: no broker.directory is configured\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

// directoryPolicy is minimalPolicy as a policy under a directory has it: the
// directory supplies a human's username, so the subject declares none.
const directoryPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
` + runKeys

// buildPolicy is body compiled for cfg as a start compiles it.
func buildPolicy(t *testing.T, cfg config.Config, body string) *policy.Policy {
	t.Helper()
	pol, err := startPolicy(cfg, []byte(body), "inventory_file")
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// failingPasses is a store whose ActivePrincipals, the scheduled pass's
// first read, counts its calls and fails the first.
type failingPasses struct {
	store.Store
	calls atomic.Int64
	busy  bool // the second pass ends on contexts still changing
}

func (f *failingPasses) ActivePrincipals(ctx context.Context) ([]string, error) {
	if n := f.calls.Add(1); n == 1 {
		return nil, errors.New("store: an injected failure")
	} else if n == 2 && f.busy {
		return nil, store.ErrConflict
	}
	return f.Store.ActivePrincipals(ctx)
}

// The scheduled loop runs RefreshDirectory every interval and stops with
// ctx; a pass error is said and the next pass runs on schedule. It runs on a
// broker with no directory: the pass is what stamps refreshed_at there too.
func TestTheScheduledLoop(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	fp := &failingPasses{Store: rig.b.Store, busy: true}
	rig.b.Store = fp
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		scheduled(ctx, rig.b, 20*time.Millisecond, func(f string, a ...any) { fmt.Fprintf(&out, f+"\n", a...) })
	}()
	waitUntil(t, "three passes", func() bool { return fp.calls.Load() >= 3 })
	if !strings.Contains(out.String(), "refresh: the scheduled refresh stopped") ||
		!strings.Contains(out.String(), "an injected failure") ||
		!strings.Contains(out.String(), "the next runs in 20ms") {
		t.Fatalf("the failed pass is not said: %q", out.String())
	}
	// A pass that ends on busy contexts is not a broken refresh.
	if !strings.Contains(out.String(), "context(s) still changing keep their last stamp; the next pass runs in 20ms") ||
		strings.Contains(out.String(), "stopped (0 live context(s) updated, 0 revoked, 0 unchanged, 0 left on quarantined devices, 0 failed; unspent tokens superseded on 0 (device, username) key(s), 0 token(s) on changed keys kept so far): the scheduled refresh: "+store.ErrConflict.Error()) {
		t.Fatalf("a busy pass is not said as busy: %q", out.String())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop outlived its context")
	}
	n := fp.calls.Load()
	time.Sleep(100 * time.Millisecond)
	if fp.calls.Load() != n {
		t.Fatal("a pass ran after ctx ended")
	}
}

// A grace mint's session, end to end on port49d with a broker inside and
// the memory store: the context's refreshed_at is the membership's
// verification, and its command is denied context_stale once the ceiling
// passes from then, not from the login (Review Focus 5). The clock is the
// real one: the membership was verified ceiling-minus-twenty-seconds ago, so
// the ceiling passes twenty seconds after the test starts.
func TestAGraceMintsSessionGoesStaleFromItsVerification(t *testing.T) {
	var out, log syncBuffer
	e, o, h := stderr, stdout, openDirectoryHook
	t.Cleanup(func() { stderr, stdout, openDirectoryHook = e, o, h })
	stderr, stdout = &out, &log
	verified := time.Now().Add(-config.DefaultStalenessCeiling + 20*time.Second)
	openDirectoryHook = func(_ config.Config, st store.Store, _ *policy.Live, _ *metrics.Metrics,
		_ func(string, ...any)) (*directory.Resolver, error) {
		a := directory.Answer{Source: directory.Grace, Membership: store.Membership{
			Principal: "user:alice@example.com", EntryID: "dn:cn=alice", Username: "corp_alice", VerifiedAt: verified}}
		return directory.ForTestsStaticResolver(st, map[string]directory.Answer{
			"user:alice@example.com": a}, nil), nil
	}
	b := brokerConfig(t, minimalPolicy).Broker
	pkiDir := filepath.Dir(b.TLSCertFile)
	cfgPath := writeRunConfig(t, b)
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
	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(addrs) != 2 {
		t.Fatalf("stderr: %q", out.String())
	}
	dev := tacacsClient{t: t, addr: addrs[0][1], key: []byte("run-test-secret")}
	// The directory's username for her, one no subject declares: the mint
	// refuses username_collision under the held policy.
	tok := mint(t, addrs[1][1], pkiDir, "leaf1")
	if st := dev.login("corp_alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("login: %d; log %s", st, log.String())
	}
	if r := dev.authorize("corp_alice"); r.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("session authorization: %+v", r)
	}
	if !dev.permits("corp_alice", "show", "version") {
		t.Fatalf("a command before the ceiling is denied; log %s", log.String())
	}
	// The session began a moment ago, a ceiling's worth of minutes from its
	// idle and age limits; only the verification it was minted on is old.
	for deadline := time.Now().Add(40 * time.Second); dev.permits("corp_alice", "show", "version"); time.Sleep(250 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the ceiling never passed from the verification; log %s", log.String())
		}
	}
	if !strings.Contains(log.String(), "context_stale") {
		t.Fatalf("the denial is not context_stale: %s", log.String())
	}
}

// /readyz stays ready with every directory server down and every breaker
// open: readiness never follows the directory (design §10, §12; pre-flight
// M-15). The broker's /readyz, over a resolver whose pool dials a refusing
// fake, after enough health checks to open each breaker.
func TestReadinessNeverFollowsTheDirectory(t *testing.T) {
	var out syncBuffer
	e, o, h := stderr, stdout, openDirectoryHook
	t.Cleanup(func() { stderr, stdout, openDirectoryHook = e, o, h })
	stderr, stdout = &out, io.Discard
	var dials atomic.Int64
	openDirectoryHook = func(_ config.Config, st store.Store, _ *policy.Live, m *metrics.Metrics,
		say func(string, ...any)) (*directory.Resolver, error) {
		cfg := *directoryCfg("simple")
		cfg.HealthInterval, cfg.HealthTimeout, cfg.FailureThreshold = 10*time.Millisecond, time.Second, 1
		cfg.ProbeInterval = 20 * time.Millisecond
		refuse := func(context.Context, directory.Server) (directory.Client, error) {
			dials.Add(1)
			return nil, errors.New("connection refused")
		}
		pool := directory.NewPool(cfg, refuse, directory.RootDSE, time.Now, m, say)
		return &directory.Resolver{Cfg: cfg, Pool: pool, Store: st, Now: time.Now, M: m, Say: say}, nil
	}
	b := brokerConfig(t, minimalPolicy).Broker
	pki := filepath.Dir(b.ClientCAFile)
	cfgPath := writeRunConfig(t, b)
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
	addr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	// The pool's checks run with the process: both breakers open on the
	// first failures at a threshold of 1.
	waitUntil(t, "the health checks to refuse twice over", func() bool { return dials.Load() >= 4 })
	if code, body := brokerReadyz(t, pki, addr); code != http.StatusOK || body != broker.ReadyServing {
		t.Fatalf("broker /readyz with the directory down: %d %q", code, body)
	}
}

// The runner's duties start and stop cleanly with no directory: the
// pre-warm goroutine returns at once and wg.Wait does not hang
// (pre-flight M-13). duties itself needs the etcd takeover, so this runs its
// two directory goroutines (scheduledDuty, prewarmDuty) and not the wg.Add(8)
// count; the final review covers duties on etcd.
func TestTheDutiesRunWithoutADirectory(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.cfg.Broker.RefreshInterval = 20 * time.Millisecond
	fp := &failingPasses{Store: rig.b.Store}
	rig.b.Store = fp
	r := &runner{cfg: rig.cfg, brk: rig.b}
	if prewarmInterval(rig.cfg) != 0 || rig.b.Directory != nil {
		t.Fatal("the rig has a directory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.scheduledDuty(ctx) }()
	prewarmed := make(chan struct{})
	go func() { defer wg.Done(); defer close(prewarmed); r.prewarmDuty(ctx) }()
	select {
	case <-prewarmed: // at once, not at ctx's end
	case <-time.After(5 * time.Second):
		t.Fatal("pre-warm did not return at once with no directory")
	}
	waitUntil(t, "the scheduled pass to run with no directory", func() bool { return fp.calls.Load() >= 2 })
	cancel()
	stopped := make(chan struct{})
	go func() { wg.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("wg.Wait hangs")
	}
}

// A bind credential that does not load (an unreadable keytab, a missing
// password variable) stops the start, naming the key, never the secret
// (pre-flight M-3).
func TestABindCredentialThatDoesNotLoadStopsTheStart(t *testing.T) {
	t.Setenv("T_DIR_BIND_PW", "")
	os.Unsetenv("T_DIR_BIND_PW")
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("simple")
	err := buildWith(cfg)
	if err == nil || !strings.Contains(err.Error(), "broker.directory.bind.password_secret_ref the environment variable it names is not set") ||
		strings.Contains(err.Error(), "T_DIR_BIND_PW") {
		t.Fatalf("a missing password variable: %v", err)
	}
	cfg.Broker.Directory = directoryCfg("gssapi")
	cfg.Broker.Directory.Bind.KeytabFile = filepath.Join(t.TempDir(), "absent.keytab")
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), "broker.directory.bind.keytab_file") {
		t.Fatalf("an unreadable keytab: %v", err)
	}
	// A keytab that is not one: the key is named, its bytes never.
	kt := filepath.Join(t.TempDir(), "bad.keytab")
	if err := os.WriteFile(kt, []byte(secretBindValue), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Broker.Directory.Bind.KeytabFile = kt
	err = buildWith(cfg)
	if err == nil || !strings.Contains(err.Error(), "broker.directory.bind.keytab_file") ||
		strings.Contains(err.Error(), secretBindValue) {
		t.Fatalf("a keytab that is not one: %v", err)
	}
}

// The resolver's username-collision check reads the live policy: a machine
// subject's declared username is there, and a reload's is the next check's.
// Only tests set Declared otherwise, so a wiring that left it nil would make
// the check do nothing in a real deployment.
func TestTheResolverReadsTheLivePolicysDeclaredUsernames(t *testing.T) {
	t.Setenv("T_DIR_BIND_PW", secretBindValue)
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("simple")
	live := policy.NewLive(buildPolicy(t, cfg, directoryPolicy))
	m := metrics.New(prometheus.NewRegistry())
	r, err := openDirectory(cfg, nil, live, m, func(string, ...any) {})
	if err != nil || r == nil || r.Declared == nil {
		t.Fatalf("%v %v", r, err)
	}
	if who, ok := r.DeclaredBy("ci"); ok {
		t.Fatalf("ci declared by %q before a policy declares it", who)
	}
	with := strings.Replace(directoryPolicy, "subjects: [", `subjects: [{name: ci_runner, identity: ["app:ci"], username: ci, token_ttl: 60s}, `, 1)
	with = strings.Replace(with, "grants: [", "grants: [{subject: ci_runner, scope: all_devices, roles: [r]}, ", 1)
	live.Swap(buildPolicy(t, cfg, with))
	if who, ok := r.DeclaredBy("ci"); !ok || who != "ci_runner" {
		t.Fatalf("a reload's declaration is not the next check's: %q %v", who, ok)
	}
}
