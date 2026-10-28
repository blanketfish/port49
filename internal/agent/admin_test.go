package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
)

// The agent makes admin calls (spec §5.1.6; plan 12b task 3d): it derives the
// operation and target from its own request, holds the broker's challenge to
// them, shows the prompt, and sends the proved retry on the connection it
// signed over. Every key here is the rig's own fake token.

const (
	bobBody   = `{"principal":"user:bob@example.com"}`
	carolBody = `{"principal":"user:carol@example.com"}`
)

func revokeCall(body string) AdminRequest {
	return AdminRequest{Method: http.MethodPost, Path: "/v1/tokens/revoke", Body: []byte(body)}
}

// logRecords is how many records the broker's decision log holds with the
// given event and, when reason is not "", reason.
func (r *realRig) logRecords(t *testing.T, event, reason string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(r.logs.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["event"] == event && (reason == "" || rec["reason"] == reason) {
			n++
		}
	}
	return n
}

// Two calls make two touches, each signed over its own request: the broker
// proves each once, for its own target.
func TestTheAgentTouchesOncePerCall(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	for i, body := range []string{bobBody, carolBody} {
		var prompts []string
		out, err := r.a.AdminPrompt(context.Background(), revokeCall(body), func(l string) { prompts = append(prompts, l) })
		if err != nil || out.Status != http.StatusOK {
			t.Fatalf("call %d: %d %v", i, out.Status, err)
		}
		want := "touch your key to revoke_principal " + map[int]string{0: "user:bob@example.com", 1: "user:carol@example.com"}[i]
		if len(prompts) != 1 || prompts[0] != want {
			t.Fatalf("call %d prompt %q, want %q", i, prompts, want)
		}
		if r.touch.Signs() != i+1 {
			t.Fatalf("after call %d the key signed %d times", i, r.touch.Signs())
		}
	}
	if n := r.logRecords(t, "admin_touch", "admin_touch_proved"); n != 2 {
		t.Fatalf("the broker proved %d touches, want 2", n)
	}
	if n := r.logRecords(t, "admin_touch", "admin_touch_refused"); n != 0 {
		t.Fatalf("the broker refused %d proofs", n)
	}
}

// A touch key that cannot be used is refused before anything is sent: the
// reason is the agent's, and the broker has no record of the call.
func TestAnUnusableTouchKeySendsNothing(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	r.a.touchUnusable = "your session key is in the TPM"
	r.a.touch = nil
	_, err := r.a.Admin(context.Background(), revokeCall(bobBody))
	var un *TouchUnusableError
	if !errors.As(err, &un) || !strings.Contains(err.Error(), "your session key is in the TPM") {
		t.Fatalf("got %v, want a *TouchUnusableError naming the reason", err)
	}
	if r.logRecords(t, "admin_touch", "") != 0 || r.logRecords(t, "revoke", "") != 0 {
		t.Fatal("the broker saw a request")
	}
	r.a.touchUnusable = ""
	if _, err := r.a.Admin(context.Background(), revokeCall(bobBody)); !errors.As(err, &un) ||
		!strings.Contains(err.Error(), "no touch_key is configured") {
		t.Fatalf("with no touch key at all: %v", err)
	}
}

// A connection replaced between the challenge and the retry posts nothing:
// the signature covers a connection that is gone, and the broker records no
// refused proof.
func TestAChangedConnectionPostsNothing(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	_, err := r.a.AdminPrompt(context.Background(), revokeCall(bobBody), func(string) {
		r.a.client.CloseIdleConnections() // the held connection goes; the retry would dial another
	})
	if !errors.Is(err, ErrConnectionChanged) {
		t.Fatalf("got %v, want ErrConnectionChanged", err)
	}
	if n := r.logRecords(t, "admin_touch", "admin_touch_refused"); n != 0 {
		t.Fatalf("the broker recorded %d refused proofs", n)
	}
	if n := r.logRecords(t, "admin_touch", "admin_touch_required"); n != 1 {
		t.Fatalf("the broker issued %d challenges, want 1", n)
	}
	if r.logRecords(t, "revoke", "") != 0 {
		t.Fatal("the revocation ran")
	}
}

// Only the routes of spec §5.1.6 are made, and a revocation of one's own
// sessions is not one of them. The broker sees none of the refused calls.
func TestThePathIsAllowlisted(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	for _, req := range []AdminRequest{
		{Method: "POST", Path: "/v1/tokens", Body: []byte(`{}`)},
		{Method: "GET", Path: "/v1/identity"},
		{Method: "POST", Path: "/v1/explain", Body: []byte(`{}`)},
		{Method: "POST", Path: "/v1/mfa", Body: []byte(`{}`)},
		{Method: "DELETE", Path: "/v1/revocations"},
		{Method: "POST", Path: "/v1/revocations", Body: []byte(`{}`)},
		{Method: "POST", Path: "/v1/directory/import?replace=maybe", Body: []byte("x")},
		{Method: "POST", Path: "/v1/directory/import?force=1", Body: []byte("x")},
		{Method: "POST", Path: "/v1/directory/import?replace=true&replace=false", Body: []byte("x")},
		{Method: "POST", Path: "/v1/revocations/../tokens/revoke", Body: []byte(bobBody)},
		{Method: "POST", Path: "/v1/directory%2Fforget", Body: []byte(bobBody)},
		{Method: "POST", Path: "/v1/directory/forget?x=1", Body: []byte(bobBody)},
		{Method: "POST", Path: "/v1/directory/forget/", Body: []byte(bobBody)},
		{Method: "GET", Path: "/v1/revocationsX"},
		{Method: "GET", Path: "/v1/revocations?x=1"},
		{Method: "GET", Path: "/v1/revocations/lift"},
		{Method: "POST", Path: "/v1/directory/export", Body: []byte(`{}`)},
		revokeCall(`{"mine":true}`),
		revokeCall(`{"principal":"user:bob@example.com","force":true}`),
		revokeCall(`{"principal":"user:bob@example.com","cert_issuer":"CN=X","cert_serial":"1"}`),
		revokeCall(`{}`),
		revokeCall(`{"principal":"bob"}`),
		{Method: "POST", Path: "/v1/directory/forget", Body: []byte(`{"principal":"user:bob@example.com"} {}`)},
	} {
		_, err := r.a.Admin(context.Background(), req)
		var refused *AdminRefusedError
		if !errors.As(err, &refused) {
			t.Errorf("%s %s %s: got %v, want an *AdminRefusedError", req.Method, req.Path, req.Body, err)
		}
	}
	if r.logRecords(t, "admin_touch", "") != 0 || r.touch.Signs() != 0 {
		t.Fatal("a refused call reached the broker or the key")
	}
}

// A list takes no touch: it is sent as is, and the key is never asked.
func TestAListTakesNoTouch(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	prompted := false
	out, err := r.a.AdminPrompt(context.Background(), AdminRequest{Method: "GET", Path: "/v1/revocations"},
		func(string) { prompted = true })
	if err != nil || out.Status != http.StatusOK || prompted || r.touch.Signs() != 0 {
		t.Fatalf("%d %v prompted=%v signs=%d", out.Status, err, prompted, r.touch.Signs())
	}
	var list api.RevocationList
	if json.Unmarshal(out.Body, &list) != nil {
		t.Fatal("the answer is not a revocation list")
	}
}

// A challenge that names another target or another operation than the
// request is refused: nothing is shown, nothing is signed, and the words of
// the broker are not repeated.
func TestAChallengeForAnotherTargetIsRefusedByTheAgent(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"target", "user:bob@example.com", "user:carol@example.com"},
		{"operation", `"operation":"revoke_principal"`, `"operation":"lift"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			front := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					rec := httptest.NewRecorder()
					next.ServeHTTP(rec, req)
					body := rec.Body.Bytes()
					if rec.Code == http.StatusUnauthorized && req.URL.Path == "/v1/tokens/revoke" {
						body = bytes.ReplaceAll(body, []byte(tc.from), []byte(tc.to))
					}
					for k, v := range rec.Header() {
						w.Header()[k] = v
					}
					w.WriteHeader(rec.Code)
					_, _ = w.Write(body)
				})
			}
			r := newRealRigWith(t, realOpts{mfa: true, admin: true, front: front})
			prompted := false
			_, err := r.a.AdminPrompt(context.Background(), revokeCall(bobBody), func(string) { prompted = true })
			if !errors.Is(err, ErrChallengeMismatch) {
				t.Fatalf("got %v, want ErrChallengeMismatch", err)
			}
			if strings.Contains(err.Error(), "carol") || strings.Contains(err.Error(), "lift") {
				t.Fatal("the error repeats the broker's words")
			}
			if prompted || r.touch.Signs() != 0 {
				t.Fatalf("prompted=%v, the key signed %d times", prompted, r.touch.Signs())
			}
		})
	}
}

// A second admin call while one waits on the key is refused, over the socket
// as in process; the first goes on and completes. The prompt reaches the
// command before the key is waited on.
func TestOneTouchAtATimeOverTheSocket(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	c := socketFor(t, r.a)
	inSign, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.touch.OnSign(func() error {
		once.Do(func() { close(inSign) })
		<-release
		return nil
	})
	var prompts []string
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() {
		_, err := c.Admin(context.Background(), revokeCall(bobBody), func(l string) {
			mu.Lock()
			prompts = append(prompts, l)
			mu.Unlock()
		})
		done <- err
	}()
	select {
	case <-inSign:
	case <-time.After(10 * time.Second):
		t.Fatal("the first call never reached the key")
	}
	var seen []string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		seen = append([]string(nil), prompts...)
		mu.Unlock()
		if len(seen) > 0 {
			break // the key is still blocked: the prompt came first
		}
	}
	if len(seen) != 1 || seen[0] != "touch your key to revoke_principal user:bob@example.com" {
		t.Fatalf("the prompt did not reach the command before the touch: %q", seen)
	}
	_, err := c.Admin(context.Background(), revokeCall(carolBody), nil)
	if !errors.Is(err, ErrTouchBusy) || !strings.Contains(err.Error(), "another touch is waiting on your key") {
		t.Fatalf("the second call: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the first call: %v", err)
	}
	if r.touch.Signs() != 1 {
		t.Fatalf("the key signed %d times, want 1", r.touch.Signs())
	}
}

// Over the socket every refusal of the agent comes back as the same error.
func TestTheAgentsAdminRefusalsTravelTheSocket(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	c := socketFor(t, r.a)
	_, err := c.Admin(context.Background(), AdminRequest{Method: "POST", Path: "/v1/tokens", Body: []byte(`{}`)}, nil)
	var refused *AdminRefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("an unlisted path: %v", err)
	}
	r.a.touchUnusable, r.a.touch = "the key is in the TPM", nil
	var un *TouchUnusableError
	if _, err = c.Admin(context.Background(), revokeCall(bobBody), nil); !errors.As(err, &un) ||
		!strings.Contains(err.Error(), "the key is in the TPM") {
		t.Fatalf("an unusable key: %v", err)
	}
}

// The sid form is shown as "sid at issuer", and needs its issuer: the agent
// cannot know which provider the broker would pick.
func TestTheSidFormIsShownAsSidAtIssuer(t *testing.T) {
	c, err := classifyAdmin(revokeCall(`{"sid":"s-1","issuer":"https://idp.example.com"}`))
	if err != nil || c.op != "revoke_sid" || c.target != "s-1 at https://idp.example.com" {
		t.Fatalf("%+v %v", c, err)
	}
	var refused *AdminRefusedError
	if _, err := classifyAdmin(revokeCall(`{"sid":"s-1"}`)); !errors.As(err, &refused) {
		t.Fatalf("a sid with no issuer: %v", err)
	}
}

// An absent or a locked touch key sends nothing: the broker sees no request.
func TestAnAbsentOrLockedKeySendsNothing(t *testing.T) {
	for name, st := range map[string]hwkey.State{"absent": hwkey.Absent, "locked": hwkey.Locked} {
		t.Run(name, func(t *testing.T) {
			r := newRealRigWith(t, realOpts{mfa: true, admin: true})
			r.touch.SetState(st)
			if _, err := r.a.Admin(context.Background(), revokeCall(bobBody)); err == nil {
				t.Fatal("no error")
			}
			if r.logRecords(t, "admin_touch", "") != 0 || r.touch.Signs() != 0 {
				t.Fatal("the broker saw a request or the key signed")
			}
		})
	}
}

// Each prompt the agent shows is also in its own log, with the operation, the
// target and the uid, and never the challenge or the signature.
func TestThePromptIsInTheAgentsLog(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	var log bytes.Buffer
	r.a.log = &log
	if _, err := r.a.AdminPrompt(context.Background(), revokeCall(bobBody), func(string) {}); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("admin_prompt operation=revoke_principal target=%q uid=%d", "user:bob@example.com", getuid())
	if !strings.Contains(log.String(), want) {
		t.Fatalf("the log lacks %q: %q", want, log.String())
	}
	if strings.Contains(strings.ToLower(log.String()), "challenge") || strings.Contains(log.String(), "signature") {
		t.Fatalf("the log carries proof material: %q", log.String())
	}
}
