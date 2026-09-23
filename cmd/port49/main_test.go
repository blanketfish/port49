package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// fakeAgent answers the agent socket's POST /token with a fixed item, or with
// status and an error body when status is not 200, whose detail is the item's. The socket protocol is the
// contract between `port49 token` and the agent; this tests the CLI's half.
func fakeAgent(t *testing.T, status int, item api.MintItem) string {
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
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(item)
			return
		}
		_ = json.NewEncoder(w).Encode(api.Error{Error: "session_over", Detail: item.Detail})
	})}
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
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"token", "--json", "--socket", p, "leaf1"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	var item api.MintItem
	if err := json.Unmarshal(out.Bytes(), &item); err != nil || item.Enable != "ENABLETOKEN" || item.Username != "alice" {
		t.Fatalf("json: %s %v", out.String(), err)
	}
}

func TestADenialIsAFailureWithItsReason(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	var out, errb bytes.Buffer
	code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb)
	if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "leaf1: deny no_grants_matched") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
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
			t.Fatalf("%v: code %d stdout %q stderr %q", args, code, out.String(), errb.String())
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
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
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
			t.Fatalf("%v: code %d stdout %q stderr %q", args, code, out.String(), errb.String())
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
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "port49 token") {
		t.Fatalf("code %d %q", code, errb.String())
	}
}
