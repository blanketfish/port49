//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/store/crypt"
)

// The admin commands go through the agent (plan 12b task 3d): the agent finds
// the operation and target in the request, shows the prompt, and presses on
// only for a challenge that names them. The key here is a fake one.

// adminStub is an agent that answers POST /admin with what answer returns and
// records the requests. It is found as the tests find an agent.
type adminStub struct {
	mu   sync.Mutex
	reqs []agent.AdminRequest
}

func newAdminStub(t *testing.T, answer func(agent.AdminRequest) (int, any)) *adminStub {
	t.Helper()
	s := &adminStub{}
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req agent.AdminRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || r.URL.Path != "/admin" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.reqs = append(s.reqs, req)
		s.mu.Unlock()
		status, v := answer(req)
		body, _ := json.Marshal(v)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(agent.AdminResponse{Status: status, Body: body})
	}))
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	return s
}

func (s *adminStub) requests() []agent.AdminRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]agent.AdminRequest(nil), s.reqs...)
}

// withNoQuestion keeps the test's own stdin, which may be a terminal, from
// being asked the y/N of a revocation.
func withNoQuestion(t *testing.T) {
	t.Helper()
	saved := confirmTTY
	confirmTTY = func() bool { return false }
	t.Cleanup(func() { confirmTTY = saved })
}

// adminLab is a lab broker whose alice may revoke and lift, behind a real
// agent holding a fake touch key; PORT49_TEST_AGENT_SOCKET names the agent.
func adminLab(t *testing.T, front func(http.Handler) http.Handler) *mfaLab {
	t.Helper()
	withNoQuestion(t)
	m := newMFALabWith(t, true, nil, "", labOpts{admin: true, front: front})
	m.b.Persist = func(context.Context) error { return nil } // a revocations_file, so the mark is saved
	t.Setenv("PORT49_TEST_AGENT_SOCKET", m.socket)
	return m
}

func cli(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// No command that makes an admin call names a socket: a flag that did is
// unknown, usage, exit 2 (spec §5.1.6; the agent is found where it is).
func TestRevokeHasNoSocketFlag(t *testing.T) {
	for _, args := range [][]string{
		{"revoke", "--socket", "/tmp/x.sock", "--list"},
		{"revoke", "--agent-socket", "/tmp/x.sock", "--mine"},
		{"revoke", "--via-agent", "--principal", "user:bob@example.com"},
		{"directory", "forget", "--socket", "/tmp/x.sock", "user:bob@example.com"},
		{"directory", "unlock", "--socket", "/tmp/x.sock", "user:bob@example.com"},
		{"directory", "reset-second-factor", "--socket", "/tmp/x.sock", "--all"},
		{"directory", "import", "--socket", "/tmp/x.sock"},
	} {
		code, _, se := cli(args...)
		if code != 2 || !strings.Contains(se, "flag provided but not defined") {
			t.Errorf("%v: exit %d %q", args, code, se)
		}
	}
}

// A challenge for another target than the request's is refused by the agent:
// nothing to touch is printed, the key signs nothing, and the command says so.
func TestAChallengeForAnotherTargetIsRefused(t *testing.T) {
	front := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			if rec.Code == http.StatusUnauthorized {
				body = bytes.ReplaceAll(body, []byte("user:bob@example.com"), []byte("user:carol@example.com"))
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(body)
		})
	}
	m := adminLab(t, front)
	code, _, se := cli("revoke", "--principal", "user:bob@example.com", "--yes")
	if code != 1 || strings.Contains(se, "touch your key") || strings.Contains(se, "carol") || m.touch.Signs() != 0 {
		t.Fatalf("exit %d, signs %d: %q", code, m.touch.Signs(), se)
	}
	if !strings.Contains(se, "different request than the one sent") {
		t.Fatalf("the refusal does not say why: %q", se)
	}
}

// The prompt names the operation and the target before the key is waited on;
// the revocation is then in force.
func TestRevokePrintsTheTouchPrompt(t *testing.T) {
	m := adminLab(t, nil)
	code, so, se := cli("revoke", "--principal", "User:Bob@Example.com", "--yes")
	if code != 0 || !strings.Contains(se, "touch your key to revoke_principal user:bob@example.com") ||
		!strings.Contains(so, "user:bob@example.com") || m.touch.Signs() != 1 {
		t.Fatalf("exit %d, signs %d: %q %q", code, m.touch.Signs(), so, se)
	}
	if i, j := strings.Index(se, "touch your key"), strings.Index(se, "revoked"); j >= 0 && j < i {
		t.Fatalf("the prompt came after the result: %q", se)
	}
	// The list needs no press.
	code, so, se = cli("revoke", "--list")
	if code != 0 || !strings.Contains(so, "user:bob@example.com") || strings.Contains(se, "touch your key") || m.touch.Signs() != 1 {
		t.Fatalf("list: exit %d, signs %d: %q %q", code, m.touch.Signs(), so, se)
	}
	// And a lift needs one of its own.
	code, _, se = cli("revoke", "--lift", "--principal", "user:bob@example.com")
	if code != 0 || !strings.Contains(se, "touch your key to lift user:bob@example.com") || m.touch.Signs() != 2 {
		t.Fatalf("lift: exit %d, signs %d: %q", code, m.touch.Signs(), se)
	}
}

// Without the right the broker refuses before it asks for a touch: no prompt,
// no press, and the line says what to do.
func TestARefusalBeforeTheChallengePromptsNothing(t *testing.T) {
	withNoQuestion(t)
	m := newMFALab(t, true, nil, "")
	t.Setenv("PORT49_TEST_AGENT_SOCKET", m.socket)
	code, _, se := cli("revoke", "--principal", "user:bob@example.com", "--yes")
	if code != 1 || strings.Contains(se, "touch your key") || m.touch.Signs() != 0 ||
		!strings.Contains(se, "api: revoke_others") || !strings.Contains(se, "no key press was asked") {
		t.Fatalf("exit %d, signs %d: %q", code, m.touch.Signs(), se)
	}
}

// A second admin call while one waits on the key is refused, and the first
// goes on to completion.
func TestOneTouchAtATime(t *testing.T) {
	m := adminLab(t, nil)
	inSign, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	m.touch.OnSign(func() error {
		once.Do(func() { close(inSign) })
		<-release
		return nil
	})
	done := make(chan int, 1)
	go func() {
		code, _, _ := cli("revoke", "--principal", "user:bob@example.com", "--yes")
		done <- code
	}()
	select {
	case <-inSign:
	case <-time.After(10 * time.Second):
		t.Fatal("the first call never reached the key")
	}
	code, _, se := cli("revoke", "--principal", "user:carol@example.com", "--yes")
	if code != 1 || !strings.Contains(se, "another touch is waiting on your key") {
		t.Fatalf("the second call: exit %d %q", code, se)
	}
	close(release)
	if code := <-done; code != 0 {
		t.Fatalf("the first call: exit %d", code)
	}
}

// An import says whether it merges or replaces, and which body, in the prompt:
// the 12 hex of the body's SHA-256 are what the broker's challenge names.
func TestTheImportPromptShowsReplace(t *testing.T) {
	m := adminLab(t, nil)
	// A broker that holds second factors: the availability check passes, so
	// the touch is asked for (a store with no file fails after it).
	m.b.PasswordSignIn = &oidc.PasswordSignIn{PrincipalDomains: []string{"example.com"}, NewEntriesFor: oidc.DefaultNewEntriesFor,
		ReopenFor: oidc.DefaultReopenFor, FailuresPerPrincipal: oidc.DefaultFailuresPerPrincipal,
		FailuresPerSource: oidc.DefaultFailuresPerSource, Window: oidc.DefaultSignInWindow}
	m.enrollKeys = crypt.Keys{Current: crypt.NewKey("lab", [32]byte(bytes.Repeat([]byte{0x5a}, 32)))}
	m.enrollPath = filepath.Join(privateDir(t), "enrollments.json")
	m.b.EnrollmentFile = m.enrollPath
	m.reopenEnrollments(t)
	body := `{"port49_enrollments":1,"key_id":"k","sealed":"c2VhbGVk"}`
	sum := sha256.Sum256([]byte(body))
	for _, tc := range []struct {
		args []string
		mode string
	}{{[]string{"directory", "import", "--replace"}, "replace"}, {[]string{"directory", "import"}, "merge"}} {
		directoryStdin = strings.NewReader(body)
		_, _, se := cli(tc.args...)
		want := "touch your key to import_enrollments " + tc.mode + " " + hex.EncodeToString(sum[:])[:12]
		if !strings.Contains(se, want) {
			t.Errorf("%v: no %q in %q", tc.args, want, se)
		}
	}
	if m.touch.Signs() != 2 {
		t.Fatalf("the key signed %d times, want 2", m.touch.Signs())
	}
	directoryStdin = nil
}

// init-enrollments and export are the broker host's, and are said to be.
func TestDirectoryExportAndInitAreTheBrokerHosts(t *testing.T) {
	for cmd, want := range map[string]string{"export": "port49-broker export-enrollments",
		"init-enrollments": "port49-broker init-enrollments"} {
		if code, _, se := cli("directory", cmd); code != 2 || !strings.Contains(se, want) {
			t.Errorf("%s: exit %d %q", cmd, code, se)
		}
	}
}

// With no agent the command says to log in, and asks nothing.
func TestAdminWithNoAgentSaysToLogIn(t *testing.T) {
	withNoQuestion(t)
	t.Setenv("PORT49_TEST_AGENT_SOCKET", privateSocket(t))
	code, _, se := cli("revoke", "--principal", "user:bob@example.com", "--yes")
	if code != 1 || !strings.Contains(se, "port49 login") {
		t.Fatalf("exit %d %q", code, se)
	}
}

// A session is ended by sid through the agent: the request names the sid and
// its issuer, both, and nothing else. The prompt is the agent's
// (internal/agent's TestTheSidFormIsShownAsSidAtIssuer).
func TestRevokeSidSendsTheSidAndItsIssuer(t *testing.T) {
	withNoQuestion(t)
	stub := newAdminStub(t, func(agent.AdminRequest) (int, any) {
		return 200, api.RevokeResponse{By: "logout_sid", Text: "ended the session"}
	})
	if code, so, se := cli("revoke", "--sid", "s-1", "--sid-issuer", "https://idp.example.com"); code != 0 ||
		!strings.Contains(so, "ended the session") {
		t.Fatalf("exit %d %q %q", code, so, se)
	}
	reqs := stub.requests()
	if len(reqs) != 1 || reqs[0].Method != "POST" || reqs[0].Path != "/v1/tokens/revoke" {
		t.Fatalf("%+v", reqs)
	}
	var body map[string]any
	if err := json.Unmarshal(reqs[0].Body, &body); err != nil || body["sid"] != "s-1" || body["issuer"] != "https://idp.example.com" || len(body) != 2 {
		t.Fatalf("the body: %s", reqs[0].Body)
	}
	for _, args := range [][]string{
		{"revoke", "--sid", "s-1"},
		{"revoke", "--sid-issuer", "https://idp.example.com"},
		{"revoke", "--sid", "s-1", "--sid-issuer", "x", "--principal", "user:a@b.example"},
		{"revoke", "--sid", "s-1", "--sid-issuer", "x", "--lift"},
		{"revoke", "--sid", "s-1", "--sid-issuer", "x", "--yes"},
	} {
		if code, _, _ := cli(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if n := len(stub.requests()); n != 1 {
		t.Fatalf("a usage error sent a request: %d", n)
	}
}
