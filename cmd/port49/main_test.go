package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

// fakeAgent answers the agent socket's POST /token with a fixed item, or with
// status and an error body when status is not 200, whose detail is the item's. The socket protocol is the
// contract between `port49 token` and the agent; this tests the CLI's half.
func fakeAgent(t *testing.T, status int, item api.MintItem) string {
	t.Helper()
	return agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(item)
			return
		}
		_ = json.NewEncoder(w).Encode(api.Error{Error: "session_over", Detail: item.Detail})
	}))
}

// agentStub serves h on an agent socket in a private directory and returns
// the socket's path.
func agentStub(t *testing.T, h http.Handler) string {
	t.Helper()
	d, err := os.MkdirTemp("", "p49c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	p := filepath.Join(d, "agent.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return p
}

var permit = api.MintItem{Device: "leaf1", Verdict: "permit", Username: "alice", Login: "LOGINTOKEN", Enable: "ENABLETOKEN"}

// stdout carries the login token and nothing else, so `$(port49 token leaf1)`
// is the credential; --json carries the whole item, enable token included.
func TestTokenPrintsTheLoginTokenAndNothingElse(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, permit)
	var out, errb bytes.Buffer
	if code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb); code != 0 || out.String() != "LOGINTOKEN\n" {
		t.Fatalf("code %d stdout %s stderr %q", code, tokenOut(out.String()), errb.String())
	}
	out.Reset()
	if code := run([]string{"token", "--json", "--socket", p, "leaf1"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	var item api.MintItem
	if err := json.Unmarshal(out.Bytes(), &item); err != nil || item.Enable != "ENABLETOKEN" || item.Username != "alice" {
		t.Fatalf("json: %s %v", tokenOut(out.String()), err)
	}
}

func TestADenialIsAFailureWithItsReason(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	var out, errb bytes.Buffer
	code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb)
	if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "leaf1: deny no_grants_matched") {
		t.Fatalf("code %d stdout %s stderr %q", code, tokenOut(out.String()), errb.String())
	}
}

// A device the broker could not decide is a failure that names the device and
// the broker's code, and no token from that item is printed anywhere — even
// one a faulty broker put beside the error.
func TestAnItemErrorNamesTheDeviceAndPrintsNoToken(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Error: "device_unconfigured",
		Detail: "not in the inventory", Login: "LOGINTOKEN"})
	for _, args := range [][]string{{"token", "--socket", p, "leaf1"}, {"token", "--json", "--socket", p, "leaf1"}} {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		if code != 1 || out.Len() != 0 || strings.Contains(errb.String(), "LOGINTOKEN") ||
			!strings.Contains(errb.String(), "leaf1") || !strings.Contains(errb.String(), "device_unconfigured") {
			t.Fatalf("%v: code %d stdout %s stderr %q", args, code, tokenOut(out.String()), errb.String())
		}
	}
}

func TestAnEndedSessionOrNoAgentSaysToLogIn(t *testing.T) {
	// A private directory with no socket in it, as a dead agent leaves one.
	// t.TempDir is not 0700, and the client refuses a socket in such a
	// directory before it dials.
	empty, err := os.MkdirTemp("", "p49c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(empty) })
	for name, p := range map[string]string{
		"ended":        fakeAgent(t, http.StatusGone, api.MintItem{}),
		"no agent":     filepath.Join(empty, "nobody.sock"),
		"no directory": filepath.Join(empty, "port49", "agent.sock"),
	} {
		var out, errb bytes.Buffer
		if code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "port49 login") {
			t.Errorf("%s: code %d stderr %q", name, code, errb.String())
		}
	}
}

// The agent's 410 says why the session ended. An operator told only to log in
// again would do it with the same expired certificate, so the reason is
// printed with the instruction.
func TestAnEndedSessionSaysWhy(t *testing.T) {
	p := fakeAgent(t, http.StatusGone, api.MintItem{Detail: "agent: the session is over; run `port49 login`: " +
		"the broker no longer trusts this certificate (x509: certificate has expired)"})
	var out, errb bytes.Buffer
	code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb)
	if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "port49 login") ||
		!strings.Contains(errb.String(), "no longer trusts this certificate (x509: certificate has expired)") {
		t.Fatalf("code %d stdout %s stderr %q", code, tokenOut(out.String()), errb.String())
	}
}

// A permit with no login token is a broker fault: printing it would hand
// `$(port49 token leaf1)` an empty password.
func TestAPermitWithNoTokenIsAFailure(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Verdict: "permit", Username: "alice"})
	for _, args := range [][]string{{"token", "--socket", p, "leaf1"}, {"token", "--json", "--socket", p, "leaf1"}} {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "leaf1: the broker answered permit with no token") {
			t.Fatalf("%v: code %d stdout %s stderr %q", args, code, tokenOut(out.String()), errb.String())
		}
	}
}

// login checks what it can before it starts anything.
func TestLoginRefusesWhatItCanCheckFirst(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	var out, errb bytes.Buffer
	if code := run([]string{"login", "--socket", sock}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "all required") {
		t.Fatalf("no flags: code %d %q", code, errb.String())
	}
	errb.Reset()
	code := run([]string{"login", "--broker", "https://127.0.0.1:1", "--cert", "/nonexistent.pem", "--key", "/nonexistent.pem",
		"--broker-ca", "/nonexistent.pem", "--socket", sock}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "client certificate") {
		t.Fatalf("missing files: code %d %q", code, errb.String())
	}
	// A client key anyone but its owner can read is refused before anything
	// starts (keyfile; pre-flight F14).
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, testpki.LabClientKey)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	code = run([]string{"login", "--broker", "https://127.0.0.1:1", "--cert", filepath.Join(dir, testpki.LabClientCert),
		"--key", key, "--broker-ca", filepath.Join(dir, testpki.LabCA), "--socket", sock}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "chmod 600") {
		t.Fatalf("a world-readable key: code %d %q", code, errb.String())
	}
}

// Without --broker-ca the agent would trust every public CA for the broker,
// whose certificate a private CA issued. It is required, not defaulted, even
// when everything else is in order.
func TestLoginRequiresTheBrokerCA(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"login", "--broker", "https://127.0.0.1:1", "--cert", filepath.Join(dir, testpki.LabClientCert),
		"--key", filepath.Join(dir, testpki.LabClientKey), "--socket", filepath.Join(t.TempDir(), "agent.sock")}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "--broker-ca") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A broker whose certificate the trust anchor did not issue stops the agent
// with the agent's own diagnosis, which login shows from the agent's log.
func TestTheAgentSaysWhyTheBrokerDoesNotVerify(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewTLSServer(http.NotFoundHandler())
	defer broker.Close()
	sockDir, err := os.MkdirTemp("", "p49c")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	var out, errb bytes.Buffer
	code := run([]string{"agent", "--broker", broker.URL, "--cert", filepath.Join(dir, testpki.LabClientCert),
		"--key", filepath.Join(dir, testpki.LabClientKey), "--broker-ca", filepath.Join(dir, testpki.LabCA),
		"--socket", filepath.Join(sockDir, "agent.sock")}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "does not verify") || !strings.Contains(errb.String(), "--broker-ca") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	// One prefix: the agent package's own "agent: " is not repeated after
	// the command's "port49 agent: " (T13 review).
	if strings.Contains(errb.String(), "agent: agent:") {
		t.Fatalf("doubled prefix: %q", errb.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "port49 token") {
		t.Fatalf("code %d %q", code, errb.String())
	}
}

// login prints the agent package's refusals under its own prefix, once.
func TestLoginSaysAgentRefusalsWithOnePrefix(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "p49w")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"login", "--broker", "https://127.0.0.1:1", "--cert", filepath.Join(dir, testpki.LabClientCert),
		"--key", filepath.Join(dir, testpki.LabClientKey), "--broker-ca", filepath.Join(dir, testpki.LabCA),
		"--socket", filepath.Join(sockDir, "agent.sock")}, &out, &errb)
	if code != 1 || !strings.HasPrefix(errb.String(), "port49 login: ") || !strings.Contains(errb.String(), "0700") ||
		strings.Contains(errb.String(), "agent: agent:") || strings.Contains(errb.String(), "login: agent:") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// runCLIEnv makes the test binary run as port49 itself, so `port49 login`
// can start the agent from os.Executable as it does in production.
const runCLIEnv = "PORT49_TEST_RUN_CLI"

func TestMain(m *testing.M) {
	if os.Getenv(runCLIEnv) == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// labBroker is a real broker behind its own Listener, as port49d serves it,
// on the lab PKI WriteLab wrote to dir, with one live context for alice on
// leaf1 an hour from its ceiling. Its clock runs skew ahead of the wall
// clock, so a test can step past the refresh pacing without waiting.
type labBroker struct {
	url  string
	dir  string
	b    *broker.Broker
	st   *memory.Store
	mu   sync.Mutex
	skew time.Duration
}

func (l *labBroker) now() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Now().Add(l.skew)
}

func (l *labBroker) step(d time.Duration) {
	l.mu.Lock()
	l.skew += d
	l.mu.Unlock()
}

func (l *labBroker) flags(socket string) []string {
	return []string{"--broker", l.url, "--cert", filepath.Join(l.dir, testpki.LabClientCert),
		"--key", filepath.Join(l.dir, testpki.LabClientKey), "--broker-ca", filepath.Join(l.dir, testpki.LabCA),
		"--socket", socket}
}

func newLabBroker(t *testing.T, maxAge time.Duration) *labBroker {
	t.Helper()
	l := &labBroker{dir: t.TempDir()}
	if err := testpki.WriteLab(l.dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	srvCert, err := tls.LoadX509KeyPair(filepath.Join(l.dir, testpki.LabServerCert), filepath.Join(l.dir, testpki.LabServerKey))
	if err != nil {
		t.Fatal(err)
	}
	cli, err := tls.LoadX509KeyPair(filepath.Join(l.dir, testpki.LabClientCert), filepath.Join(l.dir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(l.dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	policyFile := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf1 := admission.Device{Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}}
	pol, err := policy.Load(policyFile, policy.Env{Devices: []admission.Device{leaf1}})
	if err != nil {
		t.Fatal(err)
	}
	l.st = memory.New(l.now)
	log := decision.NewJSONLines(io.Discard)
	l.b = &broker.Broker{Policy: policy.NewLive(pol),
		Minter: token.NewMinter(l.st, log, rand.Reader, token.TagKey([]byte("k")), l.now, 8),
		Store:  l.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: l.now,
		MaxSessionAge: maxAge, BatchMax: 4, Sessions: session.New(l.st, l.now, time.Hour, time.Hour),
		ContextIdleTTL: time.Hour, CeilingWarning: 30 * time.Minute, GraceWindow: 5 * time.Minute}

	ctx := context.Background()
	at := l.now()
	res, err := pol.Resolve("user:alice@example.com", leaf1, at)
	if err != nil {
		t.Fatal(err)
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.st.PutBlob(ctx, hash, body, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := l.st.PutContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}, store.Context{CtxID: "ctx_leaf1",
		Principal: "user:alice@example.com", Username: "alice", PrivLvl: 1, BlobHash: hash, AuthTime: at,
		SessionExpires: at.Add(time.Hour), RefreshedAt: at, LastTouchedAt: at}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cli.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := l.st.IndexContext(ctx, "user:alice@example.com", "",
		store.CertKey(leaf.Issuer.String(), leaf.SerialNumber.Text(16)),
		store.ContextRef{NAS: "leaf1", Username: "alice"}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	srv, err := l.b.Server("127.0.0.1:0", srvCert, pool)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bl := broker.NewListener(broker.Limit(raw, broker.MaxConns), srv.TLSConfig, broker.DefaultListenerLimits,
		l.b.Metrics, l.b.Now, nil)
	bl.Refused = l.b.RefusedAtBind
	go func() { _ = srv.Serve(bl) }()
	t.Cleanup(func() { _ = srv.Close() })
	l.url = "https://" + raw.Addr().String()
	return l
}

// privateSocket is an agent socket path in a fresh 0700 directory short
// enough for a Unix socket address.
func privateSocket(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "p49c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "agent.sock")
}

// lockedBuffer is a bytes.Buffer an agent goroutine writes while the test
// reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// refreshStub is an agent socket whose /status answers st and whose
// /refresh answers status with body.
func refreshStub(t *testing.T, st agent.Status, status int, body any) string {
	t.Helper()
	p, _ := countingRefreshStub(t, st, status, body)
	return p
}

// countingRefreshStub is refreshStub, counting the /refresh requests.
func countingRefreshStub(t *testing.T, st agent.Status, status int, body any) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	return agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			_ = json.NewEncoder(w).Encode(st)
		case "/refresh":
			n.Add(1)
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})), &n
}

// port49 refresh says when it refreshed, how long the login now lasts, and
// one line per device: what happened to it, and whether the device's own
// session is out of reach (pre-flight M6).
func TestRefreshSaysWhatHappenedToEachDevice(t *testing.T) {
	p := refreshStub(t, agent.Status{}, http.StatusOK, api.RefreshResponse{
		AuthTime: "2026-10-01T09:00:00Z", SessionEndsAt: "2026-10-01T21:00:00Z",
		Sessions: []api.RefreshedSession{
			{Device: "leaf1", Username: "alice", Outcome: "extended", SessionExpires: "2026-10-01T21:00:00Z"},
			{Device: "mx1", Username: "alice", Outcome: "extended", SessionExpires: "2026-10-01T21:00:00Z", Unreached: true},
			{Device: "spine01", Username: "alice", Outcome: "revoked"},
			{Device: "nx1", Username: "alice", Outcome: "past_grace"},
			{Device: "bare", Username: "alice", Outcome: "not_judged"},
		}})
	var out, errb bytes.Buffer
	if code := run([]string{"refresh", "--socket", p}, &out, &errb); code != 0 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	want := "refreshed at 2026-10-01T09:00:00Z; this login lasts until 2026-10-01T21:00:00Z\n" +
		"  leaf1 (alice)    extended to 2026-10-01T21:00:00Z\n" +
		"  mx1 (alice)      extended to 2026-10-01T21:00:00Z, not reached: the device keeps its own session\n" +
		"  spine01 (alice)  revoked by the policy in force, not extended\n" +
		"  nx1 (alice)      past the grace window, not resumed: log in again there\n" +
		"  bare (alice)     not extended this time (the policy could not be applied to it): run 'port49 refresh' again\n"
	if out.String() != want {
		t.Fatalf("stdout:\n%s\nwant:\n%s", out.String(), want)
	}

	p = refreshStub(t, agent.Status{}, http.StatusOK, api.RefreshResponse{AuthTime: "2026-10-01T09:00:00Z",
		SessionEndsAt: "2026-10-01T21:00:00Z", Sessions: []api.RefreshedSession{}})
	out.Reset()
	if code := run([]string{"refresh", "--socket", p}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "  no live device session to extend\n") {
		t.Fatalf("code %d stdout %q", code, out.String())
	}
}

// With no agent, port49 refresh says to log in; an agent's refusal is said
// under the command's own prefix, once.
func TestRefreshWithNoAgentOrARefusal(t *testing.T) {
	empty, err := os.MkdirTemp("", "p49c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(empty) })
	var out, errb bytes.Buffer
	if code := run([]string{"refresh", "--socket", filepath.Join(empty, "nobody.sock")}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "run 'port49 login'") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	p := refreshStub(t, agent.Status{}, http.StatusBadGateway, api.Error{Error: "refresh_failed",
		Detail: "agent: the broker refused a refresh challenge: this connection refreshed moments ago; wait and retry (refresh_too_soon); retry in 7s"})
	errb.Reset()
	if code := run([]string{"refresh", "--socket", p}, &out, &errb); code != 1 ||
		errb.String() != "port49 refresh: the broker refused a refresh challenge: this connection refreshed moments ago; "+
			"wait and retry (refresh_too_soon); retry in 7s\n" {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if code := run([]string{"refresh", "--socket", p, "extra"}, &out, &errb); code != 2 {
		t.Fatalf("an argument: code %d", code)
	}
}

// port49 login with an agent already running for the same broker and
// certificate names the broker and refreshes that agent's session, rather
// than "already logged in"; a refusal is a failure. An agent for another
// broker, or another certificate, is refused by name and not refreshed: it
// is another identity's session (anti-escalation).
func TestLoginWithAnAgentRunningRefreshes(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	const brokerURL = "https://broker.example:8443"
	args := func(sock string) []string {
		return []string{"login", "--broker", brokerURL + "/", "--cert", filepath.Join(dir, testpki.LabClientCert),
			"--key", filepath.Join(dir, testpki.LabClientKey), "--broker-ca", filepath.Join(dir, testpki.LabCA), "--socket", sock}
	}
	ours := agent.Status{Broker: brokerURL, CertFingerprint: agent.CertFingerprint(cert)}
	p, refreshes := countingRefreshStub(t, ours, http.StatusOK, api.RefreshResponse{
		AuthTime: "2026-10-01T09:00:00Z", SessionEndsAt: "2026-10-01T21:00:00Z",
		Sessions: []api.RefreshedSession{{Device: "leaf1", Username: "alice", Outcome: "extended",
			SessionExpires: "2026-10-01T21:00:00Z"}}})
	var out, errb bytes.Buffer
	if code := run(args(p), &out, &errb); code != 0 || refreshes.Load() != 1 ||
		!strings.HasPrefix(out.String(), "port49: already logged in to "+brokerURL+"; refreshing\n"+
			"refreshed at 2026-10-01T09:00:00Z; this login lasts until 2026-10-01T21:00:00Z\n") ||
		!strings.Contains(out.String(), "leaf1 (alice)  extended to 2026-10-01T21:00:00Z") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	p, _ = countingRefreshStub(t, ours, http.StatusGone, api.Error{Error: "credential_revoked",
		Detail: "this principal was revoked at 2026-10-01T00:00:00Z"})
	out.Reset()
	errb.Reset()
	if code := run(args(p), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "port49 login: refreshing the running agent's session: the session is over: this principal was revoked") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}

	for name, c := range map[string]struct {
		st   agent.Status
		want string
	}{
		"another broker": {agent.Status{Broker: "https://prod-broker.example:8443", CertFingerprint: ours.CertFingerprint},
			"port49 login: an agent logged in to https://prod-broker.example:8443 already holds "},
		"another certificate": {agent.Status{Broker: brokerURL, CertFingerprint: "sha256:" + strings.Repeat("ab", 32)},
			"port49 login: an agent for " + brokerURL + " with another certificate already holds "},
		"an agent that names no certificate": {agent.Status{Broker: brokerURL},
			"port49 login: an agent for " + brokerURL + " with another certificate already holds "},
	} {
		p, refreshes := countingRefreshStub(t, c.st, http.StatusOK, api.RefreshResponse{})
		out.Reset()
		errb.Reset()
		if code := run(args(p), &out, &errb); code != 1 || out.Len() != 0 || refreshes.Load() != 0 ||
			!strings.HasPrefix(errb.String(), c.want+p+"; run 'port49 refresh' to extend that session, "+
				"stop that agent first, or use --socket\n") {
			t.Errorf("%s: code %d, %d refreshes, stdout %q stderr %q", name, code, refreshes.Load(), out.String(), errb.String())
		}
	}
}

// An agent refreshed before its first deadline is still serving after it:
// the agent process re-arms its timer on the new deadline (pre-flight I6).
// A revoked refresh then ends it.
func TestARefreshedAgentOutlivesItsFirstDeadline(t *testing.T) {
	l := newLabBroker(t, 4*time.Second)
	sock := privateSocket(t)
	var log lockedBuffer
	exited := make(chan int, 1)
	go func() { exited <- run(append([]string{"agent"}, l.flags(sock)...), io.Discard, &log) }()
	c := agent.NewClient(sock)
	var up time.Time
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := c.Status(context.Background()); err == nil {
			up = time.Now() // the agent connected before this: its deadline is before up+4s
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent never answered: %s", log.String())
		}
	}
	time.Sleep(time.Until(up.Add(2 * time.Second)))
	var out, errb bytes.Buffer
	if code := run([]string{"refresh", "--socket", sock}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	// Past the first deadline; the new one is at least up+5s (the refresh's
	// second, truncated, plus 4s).
	time.Sleep(time.Until(up.Add(4*time.Second + 400*time.Millisecond)))
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatalf("the agent stopped at its first deadline: %v\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "port49 agent: refreshed; the session now ends at ") {
		t.Fatalf("the agent's log: %s", log.String())
	}

	if err := l.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: "user:alice@example.com", At: l.now(), Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	l.step(11 * time.Second)
	errb.Reset()
	if code := run([]string{"refresh", "--socket", sock}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "this principal was revoked") || strings.Contains(errb.String(), "port49 login") {
		t.Fatalf("a revoked refresh: code %d stderr %q", code, errb.String())
	}
	select {
	case code := <-exited:
		if code != 0 || !strings.Contains(log.String(), "port49 agent: exiting") {
			t.Fatalf("code %d log %s", code, log.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("a revoked session did not end the agent: %s", log.String())
	}
}

// port49 token warns on stderr when the device's own session ends within
// the broker's ceiling_warning, plain and under --json, whose stdout stays
// one object; outside the window, or with no warning configured, it says
// nothing (decision 33; pre-flight M12).
func TestTokenWarnsNearTheDevicesCeiling(t *testing.T) {
	stub := func(warn int, expires time.Time) string {
		item := permit
		item.SessionExpiresAt = expires.UTC().Format(time.RFC3339)
		return agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/status" {
				_ = json.NewEncoder(w).Encode(agent.Status{CeilingWarningSeconds: warn})
				return
			}
			_ = json.NewEncoder(w).Encode(item)
		}))
	}
	expires := time.Now().Add(29*time.Minute + 20*time.Second)
	p := stub(1800, expires)
	want := fmt.Sprintf("port49: your session on leaf1 ends at %s (in 29m); run 'port49 refresh'\n",
		expires.UTC().Format(time.RFC3339))
	var out, errb bytes.Buffer
	if code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb); code != 0 || out.String() != "LOGINTOKEN\n" ||
		errb.String() != want {
		t.Fatalf("code %d stdout %s stderr %q", code, tokenOut(out.String()), errb.String())
	}
	out.Reset()
	errb.Reset()
	var item api.MintItem
	if code := run([]string{"token", "--json", "--socket", p, "leaf1"}, &out, &errb); code != 0 || errb.String() != want ||
		json.Unmarshal(out.Bytes(), &item) != nil || item.Login != "LOGINTOKEN" {
		t.Fatalf("--json: code %d stderr %q", code, errb.String())
	}
	for name, p := range map[string]string{
		"outside the window": stub(1800, time.Now().Add(2*time.Hour)),
		"no warning":         stub(0, expires),
		"no ceiling":         fakeAgent(t, http.StatusOK, permit),
	} {
		out.Reset()
		errb.Reset()
		if code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb); code != 0 || out.String() != "LOGINTOKEN\n" ||
			errb.Len() != 0 {
			t.Errorf("%s: code %d stdout %s stderr %q", name, code, tokenOut(out.String()), errb.String())
		}
	}
}

// A device refused session_expired is said with the broker's detail, which
// tells the operator to refresh (pre-flight M12).
func TestASessionExpiredDenialSaysToRefresh(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "session_expired",
		Detail: "your session on leaf1 reached its ceiling; run 'port49 refresh'"})
	var out, errb bytes.Buffer
	if code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb); code != 1 || out.Len() != 0 ||
		errb.String() != "port49 token: leaf1: deny session_expired: your session on leaf1 reached its ceiling; run 'port49 refresh'\n" {
		t.Fatalf("code %d stdout %s stderr %q", code, tokenOut(out.String()), errb.String())
	}
}

// An expiry already past, as a permit inside the grace window can carry, is
// said so rather than as a time left.
func TestTimeLeft(t *testing.T) {
	for d, want := range map[time.Duration]string{
		29*time.Minute + 20*time.Second: "in 29m",
		65 * time.Minute:                "in 1h5m",
		20 * time.Second:                "in under a minute",
		0:                               "already past",
		-3 * time.Minute:                "already past",
	} {
		if got := timeLeft(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

// tokenOut is port49 token's stdout for a failure message: its length, never
// its text, which is the token (plan 7b final review M-1).
func tokenOut(s string) string {
	return fmt.Sprintf("(%d bytes, withheld: it carries the token)", len(s))
}
