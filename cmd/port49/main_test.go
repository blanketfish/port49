package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/hwkey/tpm"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/enrollfile"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
	"github.com/rhwendt/port49/internal/userconfig"
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
		if code != 1 || strings.Contains(errb.String(), "LOGINTOKEN") || strings.Contains(out.String(), "LOGINTOKEN") ||
			!strings.Contains(errb.String(), "leaf1") || !strings.Contains(errb.String(), "device_unconfigured") {
			t.Fatalf("%v: code %d stdout %s stderr %q", args, code, tokenOut(out.String()), errb.String())
		}
		// Plain prints nothing; --json prints the failure object, never the item.
		var f tokenFailure
		if len(args) == 5 && (json.Unmarshal(out.Bytes(), &f) != nil || f.Error != "device_unconfigured") ||
			len(args) == 4 && out.Len() != 0 {
			t.Fatalf("%v: stdout %s", args, tokenOut(out.String()))
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
		if code != 1 || !strings.Contains(errb.String(), "leaf1: the broker answered permit with no token") {
			t.Fatalf("%v: code %d stdout %s stderr %q", args, code, tokenOut(out.String()), errb.String())
		}
		var f tokenFailure
		if len(args) == 5 && (json.Unmarshal(out.Bytes(), &f) != nil || f.Error != "no_token") ||
			len(args) == 4 && out.Len() != 0 {
			t.Fatalf("%v: stdout %s", args, tokenOut(out.String()))
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
	// A CA this host does not trust is what a host away through a whole
	// rotation meets: the line names the fix (decision 43 ruling 25).
	if code != 1 || !strings.Contains(errb.String(), "does not verify") ||
		!strings.Contains(errb.String(), "; "+agent.RotatedCAHint) {
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
	// touch_key is a fleet setting, so the login line names its flag.
	if !strings.Contains(errb.String(), "[--touch-key REF]") {
		t.Errorf("the usage does not name --touch-key: %q", errb.String())
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

// testSystemConfig carries TestMain's stand-in for /etc/port49/config.yaml
// to the test binary run as port49.
const testSystemConfig = "PORT49_TEST_SYSTEM_CONFIG"

// subreaperHook is set by the Linux test that needs a child subreaper.
var subreaperHook func()

func TestMain(m *testing.M) {
	// A child the tests start reads the system file the parent named.
	if p := os.Getenv(testSystemConfig); p != "" {
		// This user stands in for root, whom no test can make own a file.
		userconfig.SystemPath, userconfig.SystemOwner = p, uint32(os.Getuid())
	}
	if subreaperHook != nil && os.Getenv("PORT49_TEST_SUBREAPER") == "1" {
		subreaperHook()
	}
	// No test, and no child a test starts (the askpass and port49 branches
	// below), opens this machine's TPM: `auto` would find /dev/tpmrm0 and a
	// login would make a key in it. The hwkey tests dial a swtpm: hwtest's
	// init points a child at the one PORT49_TEST_SWTPM (hwtest.EnvSWTPM)
	// names, and that is left in place.
	if os.Getenv("PORT49_TEST_SWTPM") == "" {
		tpm.Dial = func() (transport.TPMCloser, error) {
			return nil, errors.New("the tests do not open this machine's TPM")
		}
	}
	// The test binary is port49 ssh's askpass in the ssh tests, as port49
	// is in production.
	if sock, ok := askpassCall(os.Args[1:]); ok {
		os.Exit(askpassMain(sock, os.Args[1:], os.Stdout, os.Stderr))
	}
	if os.Getenv(runCLIEnv) == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	// The tests that run the agent in-process (run([]string{"agent", …}))
	// would make this whole binary non-dumpable, and every later ssh test
	// would then fail to exec /proc/<pid>/exe as its askpass. A child agent
	// the login starts takes the branch above, and hardens for real.
	hardenAgent = func() error { return nil }
	// No test reads the developer's own ~/.port49, ~/.config/port49 or
	// /etc/port49 (plans 9a and 9b): every default path lands in a
	// directory of the test's, 0700 as a home directory is.
	dir, err := os.MkdirTemp("", "p49cfg")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", dir)
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	os.Unsetenv(userconfig.EnvConfig)
	userconfig.SystemPath = filepath.Join(dir, "etc", "port49", "config.yaml")
	os.Setenv(testSystemConfig, userconfig.SystemPath)
	code := runTests(m)
	os.RemoveAll(dir)
	os.Exit(code)
}

// runTests runs the package's tests: m.Run, or, under the hwkey tags
// (main_hwkey_test.go), SoftHSM's setup around it.
var runTests = func(m *testing.M) int { return m.Run() }

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
	stop func() // closes the broker's server: the broker is down
	bl   *broker.Listener
	// The directory sign-in (labOpts.signIn): the directory it asks, the
	// sealed file its second factors live in, the key that seals it, and the
	// admin socket `port49 directory ...` is run against.
	signIn     *fakeSignInDirectory
	enrollPath string
	enrollKeys crypt.Keys
	adminSock  string
	// onAccept, when set, runs for each connection the broker accepts, before
	// it is served.
	onAccept atomic.Pointer[func()]
}

// acceptHook is the lab broker's listener: it tells l each connection.
type acceptHook struct {
	net.Listener
	l *labBroker
}

func (a acceptHook) Accept() (net.Conn, error) {
	c, err := a.Listener.Accept()
	if err == nil {
		if f := a.l.onAccept.Load(); f != nil {
			(*f)()
		}
	}
	return c, err
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
	return newLabBrokerWith(t, maxAge, nil, false)
}

func newLabBrokerWith(t *testing.T, maxAge time.Duration, iss *oidctest.Issuer, issue bool) *labBroker {
	return newLabBrokerOpts(t, labOpts{maxAge: maxAge, iss: iss, issue: issue})
}

// labOpts are the lab broker's variations. mfa puts a per_login_mfa
// requirement on every device (accept hardware_key_touch and idp_mfa, reuse
// 15m); piv, when set, gives the broker its root as the attestation anchors;
// acr is the acr_values an idp_mfa sign-in sends; logs receives the decision
// log; spy sees every request the broker serves.
type labOpts struct {
	maxAge time.Duration
	iss    *oidctest.Issuer
	issue  bool
	mfa    bool
	// keepX509 keeps a broker that trusts certificates beside the OIDC
	// verifier iss gives it (the idp_mfa proof's bearer).
	keepX509 bool
	piv      *testpki.PIV
	acr      string
	logs     io.Writer
	spy      func(*http.Request)
	// signIn, when set, makes the broker a password-only directory sign-in
	// (plan 9e): an issuing CA, a directory_password verifier for example.com
	// asking this directory, no certificate trusted but its own, and an
	// enrollment store that does not exist until `port49 directory
	// init-enrollments` creates it.
	signIn *fakeSignInDirectory
}

// fakeSignInDirectory is a directory of people by name: their entry and
// password. down makes every call fail as a directory that does not answer.
type fakeSignInDirectory struct {
	mu     sync.Mutex
	people map[string]fakeDirectoryPerson
	down   bool
}

type fakeDirectoryPerson struct {
	entry    directory.SignInEntry
	password string
}

func (d *fakeSignInDirectory) SignInEntry(_ context.Context, name, _ string) (directory.SignInEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down {
		return directory.SignInEntry{}, fmt.Errorf("%w: dc-01", directory.ErrUnavailable)
	}
	p, ok := d.people[name]
	if !ok {
		return directory.SignInEntry{}, fmt.Errorf("%w: no entry", directory.ErrUnmapped)
	}
	return p.entry, nil
}

func (d *fakeSignInDirectory) CheckPassword(_ context.Context, _ directory.Server, dn, password string) error {
	if strings.TrimSpace(password) == "" {
		return directory.ErrEmptyPassword
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down {
		return fmt.Errorf("%w: dc-01", directory.ErrUnavailable)
	}
	for _, p := range d.people {
		if p.entry.DN != dn {
			continue
		}
		if p.password != password {
			return &directory.PasswordRefusal{Result: 49, Data: "52e"}
		}
		return nil
	}
	return &directory.PasswordRefusal{Result: 49, Data: "525"}
}

func (d *fakeSignInDirectory) setDown(v bool) { d.mu.Lock(); d.down = v; d.mu.Unlock() }

func newLabBrokerOpts(t *testing.T, o labOpts) *labBroker {
	t.Helper()
	// A home of the lab's own, which the agent a login starts inherits: the
	// issued pairs, kept CA bundles and CRLs are named by host and port
	// alone, and a port an earlier lab used would hand this one that lab's
	// pair, signed by another CA (final review client I3).
	home := privateDir(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	maxAge, iss, issue := o.maxAge, o.iss, o.issue
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

	requirement := ""
	if o.mfa {
		requirement = ", per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 15m}"
	}
	policyFile := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(`
scopes: [{name: all_devices, match: {}`+requirement+`}]
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
	var logOut io.Writer = io.Discard
	if o.logs != nil {
		logOut = o.logs
	}
	log := decision.NewJSONLines(logOut)
	l.b = &broker.Broker{Policy: policy.NewLive(pol),
		Minter: token.NewMinter(l.st, log, rand.Reader, token.TagKey([]byte("k")), l.now, 8),
		Store:  l.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: l.now,
		MaxSessionAge: maxAge, BatchMax: 4, Sessions: session.New(l.st, l.now, time.Hour, time.Hour),
		ContextIdleTTL: time.Hour, CeilingWarning: 30 * time.Minute, GraceWindow: 5 * time.Minute}
	if o.piv != nil || o.acr != "" {
		v := &broker.MFAVerifiers{ACRValues: o.acr}
		if o.piv != nil {
			anchors, err := pivattest.ParseAnchors(o.piv.Anchors())
			if err != nil {
				t.Fatal(err)
			}
			v.Anchors = &anchors
		}
		l.b.PerLoginMFA = v
	}
	if iss != nil {
		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
			MaxAge: 24 * time.Hour, Now: l.now, M: l.b.Metrics})
		l.b.NoX509 = !o.keepX509
		l.b.Identity = &oidc.Set{Timing: oidc.DefaultTiming, Now: l.now, M: l.b.Metrics,
			Verifiers: []*oidc.Verifier{{VerifierConfig: oidc.VerifierConfig{Domain: oidc.Humans, Issuer: iss.URL,
				ClientID: "port49-cli", PrincipalClaim: oidc.ClaimPreferredUsername,
				PrincipalDomains: []string{"example.com"}, Scopes: []string{"openid"},
				Algorithms: []oidc.Alg{oidc.RS256}}, Keys: ks}}}
		if issue {
			// A day back: the CA refuses to issue outside its window, and
			// tests hold certificates issued hours ago (holdCertificate).
			ca, err := issuer.Ephemeral(l.now().Add(-24 * time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			l.b.Issuer = ca
		}
	}
	if o.signIn != nil {
		l.wireSignIn(t, o.signIn)
	}

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
	certKey, anchor := store.CertKey(leaf.Issuer.String(), leaf.SerialNumber.Text(16)), pool
	if (iss != nil || o.signIn != nil) && !o.keepX509 {
		// A context before an OIDC or a directory login names no certificate; a
		// broker that issues its own takes no anchor.
		certKey, anchor = "", nil
	}
	if err := l.st.IndexContext(ctx, "user:alice@example.com", "", certKey,
		store.ContextRef{NAS: "leaf1", Username: "alice"}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	srv, err := l.b.Server("127.0.0.1:0", srvCert, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if o.spy != nil {
		inner := srv.Handler
		srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			o.spy(r)
			inner.ServeHTTP(w, r)
		})
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bl := broker.NewListener(broker.Limit(acceptHook{raw, l}, broker.MaxConns), srv.TLSConfig, broker.DefaultListenerLimits,
		l.b.Metrics, l.b.Now, nil)
	bl.Refused = l.b.RefusedAtBind
	l.bl = bl
	if iss != nil || o.signIn != nil {
		// As port49d wires it: Caller reads a certificate the broker issued.
		l.b.Wire(bl)
	}
	go func() { _ = srv.Serve(bl) }()
	t.Cleanup(func() { _ = srv.Close() })
	l.stop = func() { _ = srv.Close() }
	l.url = "https://" + raw.Addr().String()
	return l
}

// wireSignIn is what port49d does for a broker with a directory_password
// verifier (internal/port49d/signin.go): the verifier, the directory, an
// issuing CA, certificates trusted only if the broker issued them, the
// enrollment store as a sealed file in a private directory under test keys
// (never created: `port49 directory init-enrollments` is the one creator),
// and an admin socket answering the directory sign-in's operator commands.
func (l *labBroker) wireSignIn(t *testing.T, dir *fakeSignInDirectory) {
	t.Helper()
	if l.b.Issuer == nil {
		// A day back: the CA refuses to issue outside its window.
		ca, err := issuer.Ephemeral(l.now().Add(-24 * time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		l.b.Issuer = ca
	}
	l.b.NoX509 = true
	l.b.PasswordSignIn = &oidc.PasswordSignIn{PrincipalDomains: []string{"example.com"},
		NewEntriesFor: oidc.DefaultNewEntriesFor, ReopenFor: oidc.DefaultReopenFor,
		FailuresPerPrincipal: oidc.DefaultFailuresPerPrincipal, FailuresPerSource: oidc.DefaultFailuresPerSource,
		Window: oidc.DefaultSignInWindow, TOTPLabel: "port49 (lab)"}
	l.b.SignInDirectory, l.signIn = dir, dir

	var key crypt.Key
	key.ID = "lab"
	copy(key.Bytes[:], bytes.Repeat([]byte{0x5a}, 32))
	l.enrollKeys = crypt.Keys{Current: key}
	l.enrollPath = filepath.Join(privateDir(t), "enrollments.json")
	l.b.EnrollmentFile = l.enrollPath
	l.reopenEnrollments(t)

	l.adminSock = privateSocket(t)
	ln, err := admin.Listen(l.adminSock)
	if err != nil {
		t.Fatal(err)
	}
	origin := func(uid uint32) string { return fmt.Sprintf("admin_socket uid %d", uid) }
	srv := &admin.Server{Now: time.Now, Proc: "port49-broker",
		SecondFactorReset: func(ctx context.Context, p string, all bool, uid uint32) (string, error) {
			return l.b.ResetSecondFactor(ctx, p, all, origin(uid))
		},
		SignInUnlock: func(ctx context.Context, p string, uid uint32) (string, error) {
			return l.b.UnlockSignIn(ctx, p, origin(uid))
		},
		EnrollmentsInit: func(ctx context.Context, uid uint32) (string, error) {
			return l.b.InitEnrollments(ctx, origin(uid))
		}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
}

// reopenEnrollments opens the enrollment file afresh, as a broker's start
// does, and looks at it: no file, or one that does not open, is the lost
// state password sign-in is refused in.
func (l *labBroker) reopenEnrollments(t *testing.T) {
	t.Helper()
	f, err := enrollfile.Open(l.enrollPath, l.enrollKeys, l.now)
	if err != nil {
		t.Fatal(err)
	}
	l.b.Enrollments = crypt.WrapEnrollments(f, l.enrollKeys, l.b.Metrics.CryptOpenFailures)
	if err := l.b.CheckEnrollmentStore(context.Background()); err != nil {
		t.Fatal(err)
	}
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
		"  spine01 (alice)  revoked, not extended (see 'port49 revoke --list' and the refresh record)\n" +
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
		t.Fatalf("a revoked refresh: code %d stderr %q\n%s", code, errb.String(), log.String())
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

// A revocation the agent did not send, because an earlier one still held
// its connection, says so on port49 revoke's line, exit 1 (Task 14
// review, Minor 2). The agent's half is internal/agent's
// TestARevocationBehindARunningRevocationSaysItWasNotSent; this stub
// answers as its socket does.
func TestRevokeMineBehindAnEarlierRevocationSaysItWasNotSent(t *testing.T) {
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "broker_error",
			Detail: "agent: an earlier revocation still held the connection; this one was not sent"})
	}))
	var out, errb bytes.Buffer
	if code := run([]string{"revoke", "--mine", "--agent-socket", sock}, &out, &errb); code != 1 ||
		errb.String() != "port49 revoke: an earlier revocation still held the connection; this one was not sent\n" {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
}

// An ending agent lets the call that ended its session finish its answer
// before the socket closes (f6e5a26; final review 7e-1 M-2): a refresh the
// broker answered credential_revoked is still writing that 410 when
// Agent.Done wakes agentMain, and a Close would cut it, so the client
// would say "no agent". And a call that never returns keeps it up no
// longer than the wait.
func TestAnEndingAgentDeliversTheAnswerInFlight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inFlight, held := make(chan struct{}), make(chan struct{})
	defer close(held)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/held" {
			close(inFlight)
			<-held
			return
		}
		close(inFlight)
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusGone)
		io.WriteString(w, `{"error":"credential_revoked"}`)
	})}
	go srv.Serve(ln)
	type answer struct {
		status int
		body   string
		err    error
	}
	got := make(chan answer, 1)
	go func() {
		resp, err := http.Post("http://"+ln.Addr().String()+"/v1/refresh", "application/json", nil)
		if err != nil {
			got <- answer{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		got <- answer{resp.StatusCode, string(body), err}
	}()
	<-inFlight
	shutdownSocket(srv, agentShutdownWait)
	if a := <-got; a.err != nil || a.status != http.StatusGone || a.body != `{"error":"credential_revoked"}` {
		t.Fatalf("the answer in flight as the agent ended: %d %q %v", a.status, a.body, a.err)
	}

	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inFlight = make(chan struct{})
	srv = &http.Server{Handler: srv.Handler}
	go srv.Serve(ln)
	go http.Get("http://" + ln.Addr().String() + "/held")
	<-inFlight
	start := time.Now()
	shutdownSocket(srv, 100*time.Millisecond)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a call held open kept the agent up %v", d)
	}
}
