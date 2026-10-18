package author

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

var peer = authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}

func setupClock(t *testing.T, now func() time.Time, ceiling, grace, idle time.Duration) (*Handler, *memory.Store, *bytes.Buffer) {
	t.Helper()
	st := memory.New(now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Port: "ssh", PrivLvl: 15, RefreshedAt: now()}, time.Hour)
	log := &bytes.Buffer{}
	lab := &Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload", "copy running-config tftp:"}}
	return New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), now,
		platform.Defaults(), ceiling, grace, idle), st, log
}

func setup(t *testing.T) (*Handler, *memory.Store, *bytes.Buffer) {
	return setupClock(t, time.Now, time.Hour, time.Minute, time.Hour)
}

func req(user, port string, args ...string) wire.AuthorRequest {
	r := wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte(port), RemAddr: []byte("198.51.100.4")}
	for _, a := range args {
		r.Args = append(r.Args, []byte(a))
	}
	return r
}

func lastRecord(t *testing.T, log *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseArgs(t *testing.T) {
	kv, cmd, cmdArgs, raw := ParseArgs([][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=running-config"), []byte("cmd-arg=<cr>"), []byte("priv-lvl*15")})
	if kv["service"] != "shell" || kv["priv-lvl"] != "15" || cmd != "show" || strings.Join(cmdArgs, " ") != "running-config" || len(raw) != 5 {
		t.Fatalf("%v %q %v %v", kv, cmd, cmdArgs, raw)
	}
}

func TestSessionAuthorizationReturnsAttributes(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd="))
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 1 || string(resp.Args[0]) != "priv-lvl=15" {
		t.Fatalf("%+v", resp)
	}
	if r := lastRecord(t, log); r["event"] != "authorize_session" || r["reason"] != "context_matched" {
		t.Fatalf("%v", r)
	}
}

func TestCommandPermitAndDenyWithServerMsg(t *testing.T) {
	h, _, log := setup(t)
	if resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>")); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	r := lastRecord(t, log)
	vec := r["request"].(map[string]any)["vector"].([]any)
	if r["event"] != "authorize_command" || len(vec) != 2 || vec[1] != "version" {
		t.Fatalf("%v", r)
	}
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=reload", "cmd-arg=<cr>"))
	if resp.Status != wire.AuthorStatusFail || !strings.HasPrefix(string(resp.ServerMsg), "port49: denied") {
		t.Fatalf("%+v", resp)
	}
}

// TestNoContextIsDistinct: a name port49 never authenticated. The port is
// irrelevant to the lookup now, so what makes this a miss is the username.
func TestNoContextIsDistinct(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("carol", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "context_missing" || len(resp.ServerMsg) == 0 {
		t.Fatalf("%+v", resp)
	}
	// The record names whoever sent the command. Under the old (nas, port)
	// key this mattered because a stranger's command landed on someone else's
	// context and used to be logged against its owner; the collision is gone
	// with the key, but the record must still name the sender.
	if s := lastRecord(t, log)["session"].(map[string]any); s["username"] != "carol" {
		t.Fatalf("the record must name the user who sent the request, got %v", s["username"])
	}
}

// TestUsernameMismatchInvalidates was here. It asserted that a command from
// one user landing on another user's context denied `username_mismatch` and
// deleted that context. Both halves went with the re-key (spec §13,
// decision 15): the username is the lookup key, so a command cannot land on
// another user's context, and nothing of anyone else's is deleted. Its
// successor is TestUnknownUserIsContextMissingAndLeavesOthersAlone in
// key_test.go, which asserts the opposite of the deletion.

func TestUnsupportedService(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=ppp", "protocol=ip"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "service_unsupported" {
		t.Fatalf("%+v", resp)
	}
}

func TestVector(t *testing.T) {
	if v := Vector("", nil); v != nil {
		t.Fatalf("expected nil vector for an empty command, got %v", v)
	}
	if v := Vector("show", []string{"version"}); len(v) != 2 || v[0] != "show" || v[1] != "version" {
		t.Fatalf("%v", v)
	}
}

func TestLabCommandPrefixBoundary(t *testing.T) {
	l := &Lab{DenyPrefixes: []string{"show"}}
	if d := l.Command(context.Background(), Request{Vector: []string{"show", "version"}}); d.Permit {
		t.Fatalf("expected \"show version\" to be denied by prefix \"show\": %+v", d)
	}
	if d := l.Command(context.Background(), Request{Vector: []string{"shower"}}); !d.Permit {
		t.Fatalf("expected \"shower\" to be permitted (no token boundary match): %+v", d)
	}
}

// TestServiceUnsupportedDoesNotEchoDeviceInput guards against a NAS-supplied
// service value landing verbatim in a server_msg rendered on a device console.
func TestServiceUnsupportedDoesNotEchoDeviceInput(t *testing.T) {
	h, _, _ := setup(t)
	svc := "ppp\x1b[31m"
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service="+svc, "protocol=ip"))
	if resp.Status != wire.AuthorStatusFail {
		t.Fatalf("%+v", resp)
	}
	if strings.Contains(string(resp.ServerMsg), svc) {
		t.Fatalf("server_msg echoes device-supplied service value: %q", resp.ServerMsg)
	}
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// TestServerMsgIsPrintableASCII covers every server_msg this package can
// produce: server_msg is never anything but printable ASCII, since it is
// rendered on a device console.
func TestServerMsgIsPrintableASCII(t *testing.T) {
	tests := []struct {
		name string
		resp func(t *testing.T) wire.AuthorResponse
	}{
		{"context_missing", func(t *testing.T) wire.AuthorResponse {
			h, _, _ := setup(t)
			return h.Handle(context.Background(), peer, req("carol", "vty0", "service=shell", "cmd=show"))
		}},
		// username_mismatch was a case here. This package can no longer produce
		// it — the username is the lookup key — so there is no server_msg of
		// its own left to check. The reason code survives for the enable path
		// (spec §5.7), which plan 2 builds.
		{"service_unsupported", func(t *testing.T) wire.AuthorResponse {
			h, _, _ := setup(t)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=ppp\x1b[31m", "protocol=ip"))
		}},
		{"store_unavailable", func(t *testing.T) wire.AuthorResponse {
			st := &errGetContextStore{Store: memory.New(time.Now), err: errors.New("store: connection refused")}
			log := &bytes.Buffer{}
			lab := &Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload"}}
			h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now,
				platform.Defaults(), time.Hour, time.Minute, time.Hour)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
		}},
		{"lab_deny", func(t *testing.T) wire.AuthorResponse {
			h, _, _ := setup(t)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=reload", "cmd-arg=<cr>"))
		}},
		// The §5.3 denials. Their messages are the ones an operator is most
		// likely to see mid-session, and an em dash renders as garbage on a
		// console that speaks whatever the device's terminal speaks, so they
		// are held to the same rule as every other server_msg here.
		{"credential_revoked", func(t *testing.T) wire.AuthorResponse {
			h, st, _ := setup(t)
			st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
				store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RevokedAt: time.Now().Add(-time.Second)}, time.Hour)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
		}},
		{"session_expired", func(t *testing.T) wire.AuthorResponse {
			h, st, _ := setup(t)
			st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
				store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, SessionExpires: time.Now().Add(-time.Minute)}, time.Hour)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
		}},
		{"context_stale", func(t *testing.T) wire.AuthorResponse {
			h, st, _ := setupClock(t, time.Now, time.Minute, time.Minute, time.Hour)
			st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
				store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: time.Now().Add(-2 * time.Minute)}, time.Hour)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
		}},
		{"privilege_exceeded", func(t *testing.T) wire.AuthorResponse {
			h, st, _ := setup(t)
			st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
				store.Context{CtxID: "c", Username: "alice", PrivLvl: 1}, time.Hour)
			r := req("alice", "vty0", "service=shell", "cmd=configure")
			r.PrivLvl = 15
			return h.Handle(context.Background(), peer, r)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := tt.resp(t)
			if len(resp.ServerMsg) == 0 {
				t.Fatal("expected a non-empty server_msg")
			}
			if !isPrintableASCII(string(resp.ServerMsg)) {
				t.Fatalf("server_msg is not printable ASCII: %q", resp.ServerMsg)
			}
		})
	}
}

// errGetContextStore embeds a real memory.Store (for DeleteContext and any
// other calls) but forces GetContext to fail with a non-ErrNotFound error, to
// exercise the store_unavailable path.
type errGetContextStore struct {
	*memory.Store
	err error
}

func (e *errGetContextStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	return store.Context{}, e.err
}

func TestGetContextStoreErrorIsNotContextMissing(t *testing.T) {
	st := &errGetContextStore{Store: memory.New(time.Now), err: errors.New("store: connection refused")}
	log := &bytes.Buffer{}
	lab := &Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload"}}
	h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now,
		platform.Defaults(), time.Hour, time.Minute, time.Hour)

	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || string(resp.ServerMsg) != storeUnavailableMsg {
		t.Fatalf("%+v", resp)
	}
	r := lastRecord(t, log)
	if r["reason"] != "store_unavailable" {
		t.Fatalf("%v", r)
	}
}

// ---------------------------------------------------------------------------
// The session `service` is a per-platform list (spec §5.2, §8; §15, L10).
// ---------------------------------------------------------------------------

var junosPeer = authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "juniper_junos"}

// setupOn is setup with a chosen session-service table, which is what an
// operator override produces.
func setupOn(t *testing.T, services map[string][]string) (*Handler, *bytes.Buffer) {
	t.Helper()
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Port: "ssh", PrivLvl: 15}, time.Hour)
	log := &bytes.Buffer{}
	lab := &Lab{DenyPrefixes: []string{"reload"}}
	return New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now,
		services, time.Hour, time.Minute, time.Hour), log
}

// TestJunosSessionServiceIsPermitted is the regression this change exists for.
// L10 measured Junos sending `service=junos-exec`, and until 2026-09-21
// port49 required `shell`, so every Junos session authorization it had ever
// answered was a denial (spec §15, L10).
func TestJunosSessionServiceIsPermitted(t *testing.T) {
	h, log := setupOn(t, platform.Defaults())
	resp := h.Handle(context.Background(), junosPeer, req("alice", "", "service=junos-exec"))
	if resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("a Junos session authorization must be permitted, got %+v", resp)
	}
	r := lastRecord(t, log)
	if r["event"] != "authorize_session" || r["reason"] != "context_matched" {
		t.Fatalf("%v", r)
	}
}

// TestHandlerInventsNoAttributeOfItsOwn. Recognising `junos-exec` must not
// start sending a session-only platform attributes nobody has measured it
// accepting: the Junos projection — class, `local-user-name`,
// `user-permissions`, the allow/deny regexes — is plan 5, decision 22, gated
// on L12. This package is a pass-through, so what reaches the device is
// exactly what the authorizer returned and nothing else; the Junos
// authorizer is configured to return nothing (tests/lab/harness_test.go,
// (*lab).configPath).
func TestHandlerInventsNoAttributeOfItsOwn(t *testing.T) {
	for _, attrs := range [][]string{nil, {"priv-lvl=15"}, {"priv-lvl=15", "shell:roles*network-admin"}} {
		st := memory.New(time.Now)
		st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
			store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15}, time.Hour)
		log := &bytes.Buffer{}
		h := New(st, &Lab{SessionAttributes: attrs}, decision.NewJSONLines(log),
			metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

		resp := h.Handle(context.Background(), junosPeer, req("alice", "", "service=junos-exec"))
		if resp.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("%v: %+v", attrs, resp)
		}
		if len(resp.Args) != len(attrs) {
			t.Fatalf("authorizer returned %d attributes, the reply carries %d: %q", len(attrs), len(resp.Args), resp.Args)
		}
		for i, a := range attrs {
			if string(resp.Args[i]) != a {
				t.Fatalf("reply attribute %d is %q, the authorizer returned %q", i, resp.Args[i], a)
			}
		}
	}
}

// TestPlatformsDoNotShareEachOthersServices: the check is per platform, not a
// union. An EOS device asking `junos-exec` is asking something EOS has never
// been measured asking, and a Junos device asking `shell` likewise.
func TestPlatformsDoNotShareEachOthersServices(t *testing.T) {
	for _, tt := range []struct {
		name    string
		peer    authen.Peer
		service string
	}{
		{"eos asking junos-exec", peer, "junos-exec"},
		{"junos asking shell", junosPeer, "shell"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, log := setupOn(t, platform.Defaults())
			resp := h.Handle(context.Background(), tt.peer, req("alice", "vty0", "service="+tt.service))
			if resp.Status != wire.AuthorStatusFail {
				t.Fatalf("%+v", resp)
			}
			if r := lastRecord(t, log); r["reason"] != "service_unsupported" {
				t.Fatalf("%v", r)
			}
		})
	}
}

// TestOperatorCanNameACustomJunosService. Production SRX firewalls run
// `set system tacplus-options service-name junos-exec-fw`, so the name on the
// wire is a device setting and a custom one has to be configurable.
func TestOperatorCanNameACustomJunosService(t *testing.T) {
	services := platform.Defaults()
	services["juniper_junos"] = []string{"junos-exec-fw"}
	h, log := setupOn(t, services)

	if resp := h.Handle(context.Background(), junosPeer, req("alice", "", "service=junos-exec-fw")); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("the configured service must be permitted, got %+v", resp)
	}
	// The override replaces the default, so the built-in name is now refused.
	if resp := h.Handle(context.Background(), junosPeer, req("alice", "", "service=junos-exec")); resp.Status != wire.AuthorStatusFail {
		t.Fatalf("the override must replace the built-in, got %+v", resp)
	}
	if r := lastRecord(t, log); r["reason"] != "service_unsupported" {
		t.Fatalf("%v", r)
	}
}

// TestUnmodeledPlatformStillAuthorizesShell: spec §8, "Unknown platforms". A
// device port49 has no adapter for is legitimately admitted and must still
// reach a prompt.
func TestUnmodeledPlatformStillAuthorizesShell(t *testing.T) {
	h, _ := setupOn(t, platform.Defaults())
	odd := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "meinberg_lantime"}
	if resp := h.Handle(context.Background(), odd, req("alice", "vty0", "service=shell")); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("an unmodeled platform must still authorize a shell session, got %+v", resp)
	}
}

// TestServiceIsRecordedOnEveryAuthorizationRecord. The value the fleet's
// devices actually ask under has to be a field to group by, not a string to
// parse out of `request.raw` — including on the denials, where it is the
// whole explanation (spec §5.7).
func TestServiceIsRecordedOnEveryAuthorizationRecord(t *testing.T) {
	for _, tt := range []struct {
		name   string
		peer   authen.Peer
		user   string
		args   []string
		event  string
		reason string
		want   string
	}{
		{"session permit", peer, "alice", []string{"service=shell", "cmd="}, "authorize_session", "context_matched", "shell"},
		{"command permit", peer, "alice", []string{"service=shell", "cmd=show", "cmd-arg=version"}, "authorize_command", "permit_dominates", "shell"},
		{"command deny", peer, "alice", []string{"service=shell", "cmd=reload"}, "authorize_command", "no_permit_dominates_deny", "shell"},
		{"junos session permit", junosPeer, "alice", []string{"service=junos-exec"}, "authorize_session", "context_matched", "junos-exec"},
		{"service_unsupported", peer, "alice", []string{"service=ppp", "protocol=ip"}, "authorize_session", "service_unsupported", "ppp"},
		{"context_missing", peer, "carol", []string{"service=shell", "cmd="}, "authorize_session", "context_missing", "shell"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, log := setupOn(t, platform.Defaults())
			h.Handle(context.Background(), tt.peer, req(tt.user, "vty0", tt.args...))
			r := lastRecord(t, log)
			if r["event"] != tt.event || r["reason"] != tt.reason {
				t.Fatalf("event/reason = %v/%v, want %v/%v", r["event"], r["reason"], tt.event, tt.reason)
			}
			got := r["request"].(map[string]any)["service"]
			if got != tt.want {
				t.Fatalf("request.service = %v, want %q", got, tt.want)
			}
		})
	}
}

// TestRecordedServiceIsNeverConsultedForPolicy: the rule in spec §5.2. Two
// devices on two platforms, asking under two different service names, reach
// the same authorizer decision for the same command — the service selects
// nothing.
func TestRecordedServiceIsNeverConsultedForPolicy(t *testing.T) {
	services := map[string][]string{"arista_eos": {"shell"}, "juniper_junos": {"junos-exec"}}
	for _, tt := range []struct {
		peer    authen.Peer
		service string
	}{{peer, "shell"}, {junosPeer, "junos-exec"}} {
		h, log := setupOn(t, services)
		resp := h.Handle(context.Background(), tt.peer, req("alice", "vty0", "service="+tt.service, "cmd=reload", "cmd-arg=<cr>"))
		if resp.Status != wire.AuthorStatusFail {
			t.Fatalf("%s: a denied command must be denied whatever service asked, got %+v", tt.service, resp)
		}
		if r := lastRecord(t, log); r["reason"] != "no_permit_dominates_deny" {
			t.Fatalf("%s: %v", tt.service, r)
		}
	}
}

// TestLabCommandAttributes: the lab authorizer carries a second attribute list
// for the COMMAND path, so a reply to a per-command authorization can be given
// attributes the way a session reply can.
//
// It exists for register entry L18. That row asks what a device does with a
// reply attribute it did not ask for, and it could only ask the question of
// session authorizations: `Lab.Command` returned a bare permit, so there was no
// command reply to put a bad attribute in. The wire side was never the
// obstacle -- Handler copies a decision's attributes onto the response for
// commands and sessions alike (TestHandlerInventsNoAttributeOfItsOwn) -- it was
// that the lab authorizer had nothing to hand it.
//
// A DENY carries none of them. The attributes are a reply-shaping knob for the
// permit path; a denial's payload is its server_msg, and attaching arguments to
// a FAIL would be inventing protocol behaviour to measure protocol behaviour.
func TestLabCommandAttributes(t *testing.T) {
	l := &Lab{
		SessionAttributes: []string{"priv-lvl=15"},
		CommandAttributes: []string{"p49-nonsense*1"},
		DenyPrefixes:      []string{"reload"},
	}

	d := l.Command(context.Background(), Request{Vector: []string{"show", "version"}})
	if !d.Permit {
		t.Fatalf("expected a permit for \"show version\": %+v", d)
	}
	if len(d.Attributes) != 1 || d.Attributes[0] != "p49-nonsense*1" {
		t.Fatalf("a permitted command reply should carry the configured command attributes, got %q", d.Attributes)
	}

	if d := l.Command(context.Background(), Request{Vector: []string{"reload"}}); d.Permit {
		t.Fatalf("expected \"reload\" to be denied: %+v", d)
	} else if len(d.Attributes) != 0 {
		t.Fatalf("a DENIED command reply must carry no attributes, got %q", d.Attributes)
	}

	// The two lists are separate: a session reply does not pick up command
	// attributes, which is what makes L18 able to vary one at a time.
	s := l.Session(context.Background(), Request{})
	if len(s.Attributes) != 1 || s.Attributes[0] != "priv-lvl=15" {
		t.Fatalf("the session reply should carry only the session attributes, got %q", s.Attributes)
	}

	// Unset is the shipped shape and must stay a bare permit.
	bare := &Lab{DenyPrefixes: []string{"reload"}}
	if d := bare.Command(context.Background(), Request{Vector: []string{"show", "version"}}); len(d.Attributes) != 0 {
		t.Fatalf("with no command_attributes configured the reply must carry none, got %q", d.Attributes)
	}
}

// ---------------------------------------------------------------------------
// The §5.3 checks, in order, and the idle TTL (spec §5.3, §5.6).
// ---------------------------------------------------------------------------

func TestRevokedContextDenies(t *testing.T) {
	h, st, log := setup(t)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: time.Now(), RevokedAt: time.Now().Add(-time.Second)}, time.Hour)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "credential_revoked" || len(resp.ServerMsg) == 0 {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
}

func TestStaleContextDenies(t *testing.T) {
	h, st, log := setupClock(t, time.Now, time.Minute, time.Minute, time.Hour)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: time.Now().Add(-2 * time.Minute)}, time.Hour)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "context_stale" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
	// port49d cannot tell a broker outage from a directory it cannot verify
	// against: the message blames neither alone (plan 7g Task 18 review, I2).
	if !strings.Contains(string(resp.ServerMsg), "broker is unreachable or cannot verify your directory membership") {
		t.Fatalf("server_msg %q", resp.ServerMsg)
	}
}

// The name says what it asserts: the context is still there afterwards,
// a minute into a 10m grace window. TestTheGraceWindowKeepsThenDeletes is the
// one that crosses the window.
func TestExpiredSessionDeniesAndDoesNotDeleteTheContext(t *testing.T) {
	h, st, log := setupClock(t, time.Now, time.Hour, 10*time.Minute, time.Hour)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: time.Now(), SessionExpires: time.Now().Add(-time.Minute)}, time.Hour)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "session_expired" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
	if _, err := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); err != nil {
		t.Fatal("context must be retained through the grace window so `port49 refresh` resumes it")
	}
}

func TestPrivilegeExceededDenies(t *testing.T) {
	h, st, log := setup(t)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, RefreshedAt: time.Now()}, time.Hour)
	r := req("alice", "vty0", "service=shell", "cmd=configure")
	r.PrivLvl = 15
	resp := h.Handle(context.Background(), peer, r)
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "privilege_exceeded" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
}

func TestNoCeilingMeansNoExpiry(t *testing.T) {
	h, st, log := setup(t)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: time.Now()}, time.Hour)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusPassAdd || lastRecord(t, log)["reason"] != "permit_dominates" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
}

// context_idle_ttl is an IDLE ttl: an operator working steadily is never
// dropped, and the same context with no activity is (spec §5.6).
//
// The staleness ceiling is 24h — longer than the 2h this test drives the clock
// through — because it is the idle TTL under test here and nothing refreshes
// `RefreshedAt`. With the ceiling at an hour the fifth command would be denied
// `context_stale` and the test would be measuring the other clock.
func TestActivityExtendsTheIdleTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	h, st, _ := setupClock(t, clock, 24*time.Hour, time.Minute, 30*time.Minute)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: now, LastTouchedAt: now}, 30*time.Minute)
	for i := 0; i < 6; i++ { // 2h of work on a 30m idle TTL
		now = now.Add(20 * time.Minute)
		if resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show")); resp.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("command %d denied: %+v", i, resp)
		}
	}
	now = now.Add(31 * time.Minute) // idle past the TTL
	if _, err := st.GetContext(context.Background(), key); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an idle context must still be reclaimed")
	}
}

// A denial does not extend it: the TTL measures authorized activity, not
// attempts, or a denied loop would keep a revoked context alive indefinitely.
func TestADenialDoesNotExtendTheIdleTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	h, st, _ := setupClock(t, clock, time.Hour, time.Minute, 30*time.Minute)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key, store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: now}, 30*time.Minute)
	for i := 0; i < 3; i++ {
		now = now.Add(20 * time.Minute)
		h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=reload"))
	}
	if _, err := st.GetContext(context.Background(), key); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("denied commands extended the idle TTL")
	}
}

// The extension costs one store write per half TTL, not one per command. This
// is the test that fails if someone "simplifies" the half-TTL check away.
//
// Its ceiling is 24h for the same reason TestActivityExtendsTheIdleTTL's is:
// the clock runs out to 80 minutes, and at an hour's ceiling the last Handle
// would be a `context_stale` denial, which touches nothing — so the anti-clobber
// assertion below would pass without the extension ever having run.
func TestTheIdleTTLIsExtendedAtMostOncePerHalfTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	inner := memory.New(clock)
	st := &countingTouchStore{Store: inner}
	h := New(st, &Lab{SessionAttributes: []string{"priv-lvl=15"}}, decision.NewJSONLines(&bytes.Buffer{}),
		metrics.New(prometheus.NewRegistry()), clock, platform.Defaults(), 24*time.Hour, time.Minute, 30*time.Minute)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	inner.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: now, LastTouchedAt: now}, 30*time.Minute)
	for i := 0; i < 60; i++ { // one command a minute for an hour
		now = now.Add(time.Minute)
		if resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show")); resp.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("command %d denied: %+v", i, resp)
		}
	}
	if st.touches != 4 { // minutes 15, 30, 45, 60
		t.Fatalf("60 authorized commands cost %d store writes; the half-TTL rule is not being applied", st.touches)
	}
	// And a write that landed between two commands survives the extension. The
	// accounting annotation is the one a permitted command can be tested
	// against — a revocation would be denied before the extension is reached,
	// which is why the store-level proof lives in Task 2's
	// TestTouchContextExtendsWithoutClobbering.
	if err := inner.AnnotateContext(context.Background(), key,
		store.HashDiscriminator("14656"), store.AccountingStateOpen); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	if resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show")); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("the command that must extend the TTL was denied: %+v", resp)
	}
	if st.touches != 5 {
		t.Fatalf("the extension did not run, so the assertion below proves nothing: %d touches", st.touches)
	}
	got, _ := inner.GetContext(context.Background(), key)
	if len(got.SessionDiscriminators) != 1 || got.SessionDiscriminators[0] != store.HashDiscriminator("14656") {
		t.Fatalf("the extension discarded the accounting annotation: %+v", got)
	}
}

// TestTheDevicePrivLvlRaisedByOurOwnSessionReply is the measured sequence, and
// the reason `ctx.privilege` means the level port49 last GRANTED rather than
// the level the login START carried (spec §5.3, §7).
//
// Measured on vEOS (tests/lab/results/L1-arista_eos.md lines 62-63;
// L3-arista_eos.md lines 72-76), and the same shape on the other platforms:
//
//	AUTHOR REQUEST  priv_lvl=1  args=[service=shell cmd*]      <- session
//	AUTHOR RESPONSE status=PASS_ADD args=[priv-lvl=15 ...]     <- port49 grants 15
//	AUTHOR REQUEST  priv_lvl=15 args=[service=shell cmd=terminal ...]
//
// The device raises the session to the level port49's own reply granted, and
// every command after that arrives at 15. A context still holding the login
// START's 1 would deny every one of them `privilege_exceeded` — an operator who
// logs in successfully and can then run nothing. So the permitted session
// authorization records its granted level in place, same ctx_id.
func TestTheDevicePrivLvlRaisedByOurOwnSessionReply(t *testing.T) {
	h, st, _ := setup(t)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	// The context as a login START at priv_lvl=1 leaves it.
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)

	// The session authorization the device sends, and the priv-lvl=15 it gets.
	sess := req("alice", "vty4", "service=shell", "cmd=")
	sess.PrivLvl = 1
	resp := h.Handle(context.Background(), peer, sess)
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 1 || string(resp.Args[0]) != "priv-lvl=15" {
		t.Fatalf("the session authorization must be permitted and grant priv-lvl=15: %+v", resp)
	}
	c, err := st.GetContext(context.Background(), key)
	if err != nil || c.PrivLvl != 15 {
		t.Fatalf("the granted level must be recorded in the context: %+v %v", c, err)
	}
	if c.CtxID != "c" {
		t.Fatalf("recording the granted level must keep the same ctx_id (spec §7): %+v", c)
	}

	// The commands after it, at the level the device took from that reply.
	for _, cmd := range [][]string{
		{"service=shell", "cmd=terminal", "cmd-arg=length", "cmd-arg=0", "cmd-arg=<cr>"},
		{"service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"},
	} {
		r := req("alice", "vty4", cmd...)
		r.PrivLvl = 15
		if resp := h.Handle(context.Background(), peer, r); resp.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("a command at the level port49 granted must be permitted, got %+v for %v", resp, cmd)
		}
	}
}

// The half of the rule that still denies: what is recorded is what port49
// GRANTED, not what the device asks for. A session authorized at priv-lvl=1
// that is followed by a command claiming 15 is a device asserting a level
// port49 never gave it.
func TestACommandAboveTheGrantedLevelIsStillDenied(t *testing.T) {
	st := memory.New(time.Now)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)
	log := &bytes.Buffer{}
	h := New(st, &Lab{SessionAttributes: []string{"priv-lvl=1"}}, decision.NewJSONLines(log),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	sess := req("alice", "vty4", "service=shell", "cmd=")
	sess.PrivLvl = 1
	if resp := h.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	r := req("alice", "vty4", "service=shell", "cmd=configure", "cmd-arg=<cr>")
	r.PrivLvl = 15
	resp := h.Handle(context.Background(), peer, r)
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "privilege_exceeded" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
}

// A lower grant does not lower the context (spec §5.3). The context is keyed
// (nas, username) and covers every window of one operator: window B's session
// authorization answered priv-lvl=1 must not take away the 15 window A was
// granted, or A's next command is `privilege_exceeded` for no reason A can see.
// The REPLY still says 1 — that is policy's answer, and the stored level never
// feeds it.
func TestALowerGrantKeepsTheHeldLevel(t *testing.T) {
	st := memory.New(time.Now)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)
	h := New(st, &Lab{SessionAttributes: []string{"priv-lvl=1"}}, decision.NewJSONLines(&bytes.Buffer{}),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	sess := req("alice", "vty6", "service=shell", "cmd=")
	sess.PrivLvl = 1
	resp := h.Handle(context.Background(), peer, sess)
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 1 || string(resp.Args[0]) != "priv-lvl=1" {
		t.Fatalf("the reply is policy's answer and must still say 1: %+v", resp)
	}
	if c, _ := st.GetContext(context.Background(), key); c.PrivLvl != 15 {
		t.Fatalf("a lower grant must not lower the held level: %+v", c)
	}
	r := req("alice", "vty4", "service=shell", "cmd=configure", "cmd-arg=<cr>")
	r.PrivLvl = 15
	if resp := h.Handle(context.Background(), peer, r); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window A's command at the level it was granted must still be permitted: %+v", resp)
	}
}

// A DENIED session authorization grants nothing, so it records nothing: the
// reply carries no attributes at all, and a context whose level moved on a
// denial would be taking policy from a request that was refused. The context
// starts at 1 and the authorizer would grant 15, because stored privilege is
// raise-only (spec §5.3): a denial that recorded a level could only show up as
// a raise.
func TestADeniedSessionAuthorizationRecordsNoLevel(t *testing.T) {
	st := memory.New(time.Now)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)
	h := New(st, &Lab{SessionAttributes: []string{"priv-lvl=15"}}, decision.NewJSONLines(&bytes.Buffer{}),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	sess := req("alice", "vty4", "service=ppp", "protocol=ip") // service_unsupported: denied before the authorizer
	sess.PrivLvl = 1
	if resp := h.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusFail {
		t.Fatalf("%+v", resp)
	}
	if c, _ := st.GetContext(context.Background(), key); c.PrivLvl != 1 {
		t.Fatalf("a denied session authorization must not move the recorded level: %+v", c)
	}
}

// A command authorization never records a level, whatever it carries. Only a
// session authorization grants one; the reply to a command that happened to
// carry a priv-lvl attribute is not a grant, and treating it as one would let a
// per-command reply raise the session (spec §5.3).
func TestACommandReplyDoesNotRecordALevel(t *testing.T) {
	st := memory.New(time.Now)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)
	h := New(st, &Lab{CommandAttributes: []string{"priv-lvl=15"}}, decision.NewJSONLines(&bytes.Buffer{}),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	r := req("alice", "vty4", "service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>")
	r.PrivLvl = 1
	if resp := h.Handle(context.Background(), peer, r); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	if c, _ := st.GetContext(context.Background(), key); c.PrivLvl != 1 {
		t.Fatalf("a command reply must not move the recorded level: %+v", c)
	}
}

// A non-positive staleness ceiling means no staleness check. It is what the
// daemon passes until something refreshes `refreshed_at` (plan 2's broker-side
// Refresh, task 13): with a finite ceiling and a clock that only ever moves at
// login, an operator working steadily is denied "the broker is unreachable" at
// login plus the ceiling, with no broker to reach — the same failure the idle
// TTL was made extendable to avoid, wearing a worse message.
func TestAZeroStalenessCeilingDisablesTheCheck(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	for _, tt := range []struct {
		name    string
		ceiling time.Duration
		want    uint8
	}{
		{"zero", 0, wire.AuthorStatusPassAdd},
		{"negative", -time.Hour, wire.AuthorStatusPassAdd},
		{"positive", 12 * time.Hour, wire.AuthorStatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now = time.Unix(1_000_000, 0)
			h, st, log := setupClock(t, clock, tt.ceiling, time.Minute, 30*time.Minute)
			key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
			st.PutContext(context.Background(), key,
				store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: now}, 30*time.Minute)

			// A week of steady work: one command every ten minutes, which the
			// idle TTL keeps alive and no refresh ever touches.
			var resp wire.AuthorResponse
			for i := 0; i < 7*24*6; i++ {
				now = now.Add(10 * time.Minute)
				resp = h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
				if resp.Status != wire.AuthorStatusPassAdd {
					break
				}
			}
			if resp.Status != tt.want {
				t.Fatalf("ceiling %s: status %v, want %v (%v)", tt.ceiling, resp.Status, tt.want, lastRecord(t, log))
			}
			if tt.want == wire.AuthorStatusFail && lastRecord(t, log)["reason"] != "context_stale" {
				t.Fatalf("a positive ceiling must still deny context_stale: %v", lastRecord(t, log))
			}
		})
	}
}

// The granted level never exceeds the ceiling the token was minted with, which
// is the bound the enable path refuses above (`ceiling_exceeded`, spec §7).
func TestTheGrantedLevelIsClampedToMaxPrivilege(t *testing.T) {
	for _, tt := range []struct {
		name  string
		max   uint8
		grant string
		want  uint8
	}{
		{"above the ceiling records the ceiling", 7, "priv-lvl=15", 7},
		{"at the ceiling", 15, "priv-lvl=15", 15},
		{"below the ceiling is untouched", 15, "priv-lvl=1", 1},
		// A token minted with no ceiling — what a policy engine that never sets
		// the field produces (plan 4). Zero is "no ceiling", not "level 0
		// only": clamping to it would record 0 and deny every command of a
		// session just granted 15. The enable path reads the same helper and
		// refuses nothing on such a token
		// (authen.TestEnableCeilingRefusesOnlyWhatWasMinted).
		{"no ceiling minted", 0, "priv-lvl=15", 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := memory.New(time.Now)
			key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
			st.PutContext(context.Background(), key,
				store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: tt.max, RefreshedAt: time.Now()}, time.Hour)
			h := New(st, &Lab{SessionAttributes: []string{tt.grant}}, decision.NewJSONLines(&bytes.Buffer{}),
				metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

			sess := req("alice", "vty4", "service=shell", "cmd=")
			sess.PrivLvl = 1
			if resp := h.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
				t.Fatalf("%+v", resp)
			}
			if c, _ := st.GetContext(context.Background(), key); c.PrivLvl != tt.want {
				t.Fatalf("recorded level %d, want %d", c.PrivLvl, tt.want)
			}
		})
	}
}

// Both store writes on the permit path swallow their error and count it
// instead, so store_ops is the only place an operator sees a lost race. If
// nothing asserts the counter, the swallow is silent.
func TestTheSwallowedStoreWritesAreCounted(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	inner := memory.New(clock)
	st := &vanishingContextStore{Store: inner}
	m := metrics.New(prometheus.NewRegistry())
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	h := New(st, &Lab{SessionAttributes: []string{"priv-lvl=15"}}, decision.NewJSONLines(&bytes.Buffer{}),
		m, clock, platform.Defaults(), time.Hour, time.Minute, 30*time.Minute)

	// A session authorization that both grants a level and is due an
	// extension: LastTouchedAt is a full TTL old, so the half-TTL rule fires.
	inner.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, RefreshedAt: now}, 30*time.Minute)
	now = now.Add(20 * time.Minute)
	sess := req("alice", "vty4", "service=shell", "cmd=")
	sess.PrivLvl = 1
	if resp := h.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	for _, op := range []string{"set_privilege", "touch_context"} {
		if got := testutil.ToFloat64(m.StoreOps.WithLabelValues(op, "ok")); got != 1 {
			t.Fatalf("store_ops{op=%q,outcome=ok} = %v, want 1", op, got)
		}
	}

	// Now the context vanishes between the read and the writes, which is the
	// revocation or reclaim race both call sites deliberately swallow. The
	// reply is unchanged -- the next request is denied on its own terms -- so
	// the counter is the only signal there is.
	st.vanish = true
	now = now.Add(20 * time.Minute)
	if resp := h.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("a lost race must not change the reply: %+v", resp)
	}
	for _, op := range []string{"set_privilege", "touch_context"} {
		if got := testutil.ToFloat64(m.StoreOps.WithLabelValues(op, "not_found")); got != 1 {
			t.Fatalf("store_ops{op=%q,outcome=not_found} = %v, want 1", op, got)
		}
	}
}

// vanishingContextStore serves the context to GetContext and then loses it, so
// the writes that follow the read find nothing -- the shape of a revocation or
// an idle reclaim landing mid-request.
type vanishingContextStore struct {
	store.Store
	vanish bool
}

func (v *vanishingContextStore) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	if v.vanish {
		return store.ErrNotFound
	}
	return v.Store.SetPrivilege(ctx, k, level)
}

func (v *vanishingContextStore) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	if v.vanish {
		return store.ErrNotFound
	}
	return v.Store.TouchContext(ctx, k, ttl)
}

type countingTouchStore struct {
	store.Store
	touches int
}

func (c *countingTouchStore) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	c.touches++
	return c.Store.TouchContext(ctx, k, ttl)
}

// A typed secret is authorized like any command and never written: the
// record's raw pairs and vector carry «redacted» where it was, keep their
// shape, and say they were redacted (spec §5.7, §5.8). A redactor the daemon
// is given — the policy in force's — applies in place of the built-in one.
func TestASecretIsDecidedButNeverWritten(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=username",
		"cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2", "cmd-arg=<cr>"))
	if resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	if strings.Contains(log.String(), "Hunter2") {
		t.Fatalf("the secret reached the log: %s", log.String())
	}
	r := lastRecord(t, log)["request"].(map[string]any)
	raw, vec := r["raw"].([]any), r["vector"].([]any)
	if r["redacted"] != true || len(raw) != 6 || raw[4] != "cmd-arg="+platform.Redacted || raw[5] != "cmd-arg=<cr>" ||
		len(vec) != 4 || vec[3] != platform.Redacted || vec[2] != "secret" {
		t.Fatalf("%v", r)
	}
	// A command with nothing to redact says nothing about it.
	h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show", "cmd-arg=version"))
	if r := lastRecord(t, log)["request"].(map[string]any); r["redacted"] != nil {
		t.Fatalf("%v", r)
	}
	h.WithRedactor(func(string) []platform.Redaction {
		return []platform.Redaction{{Match: []string{"**"}, After: "psk"}}
	})
	h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=crypto", "cmd-arg=psk",
		"cmd-arg=s3cret"))
	if strings.Contains(log.String(), "s3cret") {
		t.Fatalf("the redactor the daemon was given did not apply: %s", log.String())
	}
}

// ruleAuthz denies every command on a rule whose text carries a literal
// secret, as the engine would report it.
type ruleAuthz struct{ *Lab }

func (ruleAuthz) Command(context.Context, Request) Decision {
	rule := []string{"username", "*", "secret", "Hunter2"}
	return Decision{Reason: decision.NoPermitDominatesDeny,
		ServerMsg: engine.DenyMsg("no_backdoor", strings.Join(rule, " ")),
		Policy: &decision.Policy{MatchedDeny: &decision.PolicyRule{Rule: rule, Specificity: []int{3, 0, 0},
			Role: "no_backdoor"}}}
}

// A rule written with a secret in it is echoed wherever the rule is — the
// denial's server_msg and the record's matched rules — so the echo is
// redacted as the command is: a policy literal is no safer in a log than a
// typed one (task 10 note).
func TestARuleLiteralSecretIsNeverEchoed(t *testing.T) {
	log := &bytes.Buffer{}
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15}, time.Hour)
	h := New(st, ruleAuthz{&Lab{}}, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now,
		platform.Defaults(), time.Hour, time.Minute, time.Hour)
	// The command carries no secret: the echo alone must be redacted, and
	// the record says so, since its matched rules are not the blob's.
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show",
		"cmd-arg=version"))
	if resp.Status != wire.AuthorStatusFail || strings.Contains(string(resp.ServerMsg), "Hunter2") ||
		!strings.Contains(string(resp.ServerMsg), "no_backdoor (username * secret <redacted>)") {
		t.Fatalf("server_msg %q", resp.ServerMsg)
	}
	for _, c := range resp.ServerMsg {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("server_msg is not printable ASCII: %q", resp.ServerMsg)
		}
	}
	if strings.Contains(log.String(), "Hunter2") {
		t.Fatalf("the rule's secret reached the log: %s", log.String())
	}
	m := lastRecord(t, log)
	deny := m["policy"].(map[string]any)["matched_deny"].(map[string]any)["rule"].([]any)
	if m["request"].(map[string]any)["redacted"] != true || deny[3] != platform.Redacted || deny[2] != "secret" {
		t.Fatalf("%v", m)
	}
}

// A juniper_junos variant arrives as junos-exec, as its base does; keyed by
// its own name it would get the fallback `shell` and be refused every
// session (spec §8; plan 6a).
func TestAVariantIsAuthorizedAsItsBase(t *testing.T) {
	h, log := setupOn(t, platform.Defaults())
	variant := authen.Peer{NAS: "leaf-01", NASAddr: "10.0.0.1", Platform: "srx_variant", WirePlatform: "juniper_junos"}
	resp := h.Handle(context.Background(), variant, req("alice", "", "service=junos-exec"))
	if resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("a variant's session was refused: %+v", resp)
	}
	if r := lastRecord(t, log); r["reason"] != "context_matched" {
		t.Fatalf("%v", r)
	}
}

// ---------------------------------------------------------------------------
// The session ceiling: the warning, the grace window, the blob's lifetime
// (spec §5.6; decision 33; plan 7b).
// ---------------------------------------------------------------------------

var aliceKey = store.ContextKey{NAS: "leaf-01", Username: "alice"}

// authorFixture is a Handler over a memory store whose clock the test moves,
// with a 10m grace window, a 24h idle TTL, no staleness ceiling, and a blob
// its contexts name. The Lab permits `show version`.
type authorFixture struct {
	h     *Handler
	st    *memory.Store
	clock *time.Time
	now   time.Time
	log   *bytes.Buffer
	reg   *prometheus.Registry
}

const fixtureBlob = "blob-alice"

func newAuthorFixture(t *testing.T) *authorFixture {
	t.Helper()
	now := time.Unix(2_000_000, 0)
	f := &authorFixture{clock: &now, now: now, log: &bytes.Buffer{}, reg: prometheus.NewRegistry()}
	clock := func() time.Time { return *f.clock }
	f.st = memory.New(clock)
	if err := f.st.PutBlob(context.Background(), fixtureBlob, []byte("{}"), time.Hour); err != nil {
		t.Fatal(err)
	}
	f.h = New(f.st, &Lab{DenyPrefixes: []string{"reload"}}, decision.NewJSONLines(f.log), metrics.New(f.reg), clock,
		platform.Defaults(), 0, 10*time.Minute, 24*time.Hour)
	return f
}

// putContext writes alice's context with this auth_time and session_expires,
// touched now.
func (f *authorFixture) putContext(t *testing.T, authTime, expires time.Time) {
	t.Helper()
	f.put(t, store.Context{AuthTime: authTime, SessionExpires: expires, LastTouchedAt: f.now})
}

func (f *authorFixture) put(t *testing.T, c store.Context) {
	t.Helper()
	c.CtxID, c.Username, c.PrivLvl, c.BlobHash = "ctx1", "alice", 15, fixtureBlob
	if err := f.st.PutContext(context.Background(), aliceKey, c, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

func (f *authorFixture) authorize(t *testing.T, args ...string) (wire.AuthorResponse, map[string]any) {
	t.Helper()
	resp := f.h.Handle(context.Background(), peer, req("alice", "vty0", append([]string{"service=shell"}, args...)...))
	return resp, lastRecord(t, f.log)
}

// blobLiveAt reports whether the fixture's blob is still in the store at at.
func (f *authorFixture) blobLiveAt(t *testing.T, at time.Time) bool {
	t.Helper()
	saved := *f.clock
	defer func() { *f.clock = saved }()
	*f.clock = at
	_, err := f.st.GetBlob(context.Background(), fixtureBlob)
	return err == nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Inside ceiling_warning, a permitted reply carries the warning in
// server_msg, and the record says so; outside it, nothing (spec §5.6;
// decision 33; L34).
func TestAPermitNearTheCeilingWarns(t *testing.T) {
	for _, tc := range []struct {
		left time.Duration
		want string
	}{{29*time.Minute + time.Second, "port49: session ends in 30m - run 'port49 refresh'"}, {31 * time.Minute, ""},
		{30 * time.Minute, "port49: session ends in 30m - run 'port49 refresh'"},
		{10 * time.Second, "port49: session ends in 1m - run 'port49 refresh'"}} {
		f := newAuthorFixture(t) // its peer is arista_eos
		f.h.WithCeilingWarning(30*time.Minute, []string{"arista_eos"})
		f.putContext(t, f.now.Add(-time.Hour), f.now.Add(tc.left))
		resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version")
		if resp.Status != wire.AuthorStatusPassAdd || string(resp.ServerMsg) != tc.want || rec["server_msg"] != nilIfEmpty(tc.want) {
			t.Errorf("%s left: %v %q %v", tc.left, resp.Status, resp.ServerMsg, rec["server_msg"])
		}
		want := 0.0
		if tc.want != "" {
			want = 1
		}
		if got := testutil.ToFloat64(f.h.metrics.CeilingWarnings); got != want {
			t.Errorf("%s left: port49_ceiling_warnings_total %v, want %v", tc.left, got, want)
		}
	}
}

// The session authorization's permit carries it too: it is the reply a
// device answers at login (spec §5.6).
func TestASessionPermitNearTheCeilingWarns(t *testing.T) {
	f := newAuthorFixture(t)
	f.h.WithCeilingWarning(30*time.Minute, []string{"arista_eos"})
	f.putContext(t, f.now.Add(-time.Hour), f.now.Add(5*time.Minute))
	if resp, _ := f.authorize(t); resp.Status != wire.AuthorStatusPassAdd ||
		string(resp.ServerMsg) != "port49: session ends in 5m - run 'port49 refresh'" {
		t.Fatalf("%v %q", resp.Status, resp.ServerMsg)
	}
}

// A denial never carries the warning: its server_msg says why it was denied.
// Nor does a context with no ceiling, nor a zero ceiling_warning.
func TestTheWarningRidesOnlyOnACeilingedPermit(t *testing.T) {
	f := newAuthorFixture(t)
	f.h.WithCeilingWarning(30*time.Minute, []string{"arista_eos"})
	f.putContext(t, f.now.Add(-time.Hour), f.now.Add(5*time.Minute))
	if resp, _ := f.authorize(t, "cmd=reload"); resp.Status != wire.AuthorStatusFail ||
		strings.Contains(string(resp.ServerMsg), "session ends") {
		t.Fatalf("a denial: %v %q", resp.Status, resp.ServerMsg)
	}
	f.put(t, store.Context{LastTouchedAt: f.now}) // never: no ceiling
	if resp, _ := f.authorize(t, "cmd=show"); resp.Status != wire.AuthorStatusPassAdd || len(resp.ServerMsg) != 0 {
		t.Fatalf("no ceiling: %v %q", resp.Status, resp.ServerMsg)
	}
	f.h.WithCeilingWarning(0, []string{"arista_eos"})
	f.putContext(t, f.now.Add(-time.Hour), f.now.Add(time.Minute))
	if resp, _ := f.authorize(t, "cmd=show"); resp.Status != wire.AuthorStatusPassAdd || len(resp.ServerMsg) != 0 {
		t.Fatalf("ceiling_warning 0s: %v %q", resp.Status, resp.ServerMsg)
	}
	if got := testutil.ToFloat64(f.h.metrics.CeilingWarnings); got != 0 {
		t.Fatalf("port49_ceiling_warnings_total %v", got)
	}
}

// A platform neither L34 nor the operator lists gets no server_msg on a
// permit, however close the ceiling (pre-flight M10).
func TestAnUnlistedPlatformGetsNoWarning(t *testing.T) {
	f := newAuthorFixture(t)
	f.h.WithCeilingWarning(30*time.Minute, nil)
	f.putContext(t, f.now.Add(-time.Hour), f.now.Add(time.Minute))
	if resp, _ := f.authorize(t, "cmd=show", "cmd-arg=version"); resp.Status != wire.AuthorStatusPassAdd || len(resp.ServerMsg) != 0 {
		t.Fatalf("%v %q", resp.Status, resp.ServerMsg)
	}
}

// Past the ceiling and inside the grace window: denied, the context kept,
// the message naming port49 refresh. Past the window: denied, the context
// deleted (teardown row 3).
func TestTheGraceWindowKeepsThenDeletes(t *testing.T) {
	f := newAuthorFixture(t) // grace window 10m
	f.putContext(t, f.now.Add(-2*time.Hour), f.now.Add(-5*time.Minute))
	resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version")
	if resp.Status != wire.AuthorStatusFail || !strings.Contains(string(resp.ServerMsg), "within 5m to resume") ||
		!strings.Contains(string(resp.ServerMsg), "port49 refresh") || !strings.Contains(string(resp.ServerMsg), "port49 login") ||
		rec["reason"] != "session_expired" {
		t.Fatalf("inside the window: %v %q %v", resp.Status, resp.ServerMsg, rec)
	}
	if _, err := f.st.GetContext(context.Background(), aliceKey); err != nil {
		t.Fatal("the context was not kept inside the window")
	}
	f.putContext(t, f.now.Add(-2*time.Hour), f.now.Add(-11*time.Minute))
	resp, rec = f.authorize(t, "cmd=show", "cmd-arg=version")
	if resp.Status != wire.AuthorStatusFail || !strings.Contains(string(resp.ServerMsg), "log in again") ||
		rec["reason"] != "session_expired" {
		t.Fatalf("past the window: %v %q %v", resp.Status, resp.ServerMsg, rec)
	}
	if _, err := f.st.GetContext(context.Background(), aliceKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the context outlived its grace window: %v", err)
	}
	if got := testutil.ToFloat64(f.h.metrics.StoreOps.WithLabelValues("delete_context", "ok")); got != 1 {
		t.Fatalf("delete_context ok %v", got)
	}
}

// A context with a ceiling and no auth_time is past nothing it can show, so
// the ceiling it carries still governs: it is denied at it like any other
// (a zero auth_time fails closed, plan 7b Task 2).
func TestACeilingWithNoAuthTimeStillExpires(t *testing.T) {
	f := newAuthorFixture(t)
	f.putContext(t, time.Time{}, f.now.Add(-time.Minute))
	if resp, rec := f.authorize(t, "cmd=show"); resp.Status != wire.AuthorStatusFail || rec["reason"] != "session_expired" {
		t.Fatalf("%v %v", resp.Status, rec)
	}
}

// deleteRaceStore replaces the context between the authorizer's read and its
// delete, as a login landing in that gap does.
type deleteRaceStore struct {
	*memory.Store
	replace func()
}

func (d *deleteRaceStore) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	d.replace()
	return d.Store.DeleteContextIf(ctx, k, rev)
}

// The delete past the window is bound to the revision read: a context a
// login or a refresh wrote since is not deleted with the one it replaced
// (pre-flight M4).
func TestTheGraceDeleteSparesAContextWrittenSince(t *testing.T) {
	f := newAuthorFixture(t)
	f.putContext(t, f.now.Add(-2*time.Hour), f.now.Add(-11*time.Minute))
	race := &deleteRaceStore{Store: f.st, replace: func() { f.putContext(t, f.now, f.now.Add(time.Hour)) }}
	f.h.store = race
	resp, _ := f.authorize(t, "cmd=show")
	if resp.Status != wire.AuthorStatusFail {
		t.Fatalf("%+v", resp)
	}
	c, err := f.st.GetContext(context.Background(), aliceKey)
	if err != nil || !c.SessionExpires.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("the sweep deleted the context a login wrote since: %v %+v", err, c)
	}
	if got := testutil.ToFloat64(f.h.metrics.StoreOps.WithLabelValues("delete_context", "conflict")); got != 1 {
		t.Fatalf("delete_context conflict %v", got)
	}
	if resp, _ := f.authorize(t, "cmd=show"); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("the new login's context was not usable: %+v", resp)
	}
}

// A permit that extends a context's idle TTL bumps its blob too, so a
// `never` session's blob outlives the TTL it was minted with (decision 19).
func TestATouchBumpsTheBlob(t *testing.T) {
	f := newAuthorFixture(t)
	f.put(t, store.Context{LastTouchedAt: f.now.Add(-13 * time.Hour)}) // older than half the idle TTL
	if resp, _ := f.authorize(t, "cmd=show", "cmd-arg=version"); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	if !f.blobLiveAt(t, f.now.Add(11*time.Hour)) {
		t.Fatal("the blob was not bumped with the context")
	}
}

// Every permit bumps the blob, not only one that touches the context: a
// refresh can write a blob with a shorter TTL than the context it stamps, and
// the next touch is half an idle TTL away, so a bump only on touch leaves the
// blob to expire under a live context (Task 3 review, M-2). A live context's
// blob never expires before it.
func TestEveryPermitBumpsTheBlob(t *testing.T) {
	f := newAuthorFixture(t)
	f.put(t, store.Context{LastTouchedAt: f.now}) // just touched: no TouchContext on this permit
	*f.clock = f.now.Add(30 * time.Minute)        // the blob has 30m left; the context, 23h30m
	if resp, _ := f.authorize(t, "cmd=show", "cmd-arg=version"); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	c, err := f.st.GetContext(context.Background(), aliceKey)
	if err != nil || !c.LastTouchedAt.Equal(f.now) {
		t.Fatalf("this permit touched the context, so it proves nothing: %v %+v", err, c)
	}
	// The context expires at f.now+24h; its blob must still be there just
	// before.
	if !f.blobLiveAt(t, f.now.Add(24*time.Hour-time.Second)) {
		t.Fatal("the blob expires before the live context that names it")
	}
	if got := testutil.ToFloat64(f.h.metrics.StoreOps.WithLabelValues("bump_blob", "ok")); got != 1 {
		t.Fatalf("bump_blob ok %v", got)
	}
}

// The bump is throttled per blob hash on each replica: permits within half an
// idle TTL of a successful bump write nothing more, and the first after it
// bumps again (Task 6 review, I-1). Blobs are shared by content hash, so an
// unthrottled bump is a write per command onto a few hot keys.
func TestTheBlobBumpIsThrottled(t *testing.T) {
	f := newAuthorFixture(t) // idle TTL 24h
	f.put(t, store.Context{LastTouchedAt: f.now})
	bumps := func() float64 { return testutil.ToFloat64(f.h.metrics.StoreOps.WithLabelValues("bump_blob", "ok")) }
	for i := 0; i < 50; i++ {
		*f.clock = f.now.Add(time.Duration(i) * 10 * time.Minute) // 50 permits across 8h10m
		if resp, _ := f.authorize(t, "cmd=show"); resp.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("permit %d: %+v", i, resp)
		}
	}
	if got := bumps(); got != 1 {
		t.Fatalf("50 permits within half the idle TTL cost %v bump_blob writes, want 1", got)
	}
	// The bump went to 1.5 idle TTLs, so a context touched at the last
	// moment before the next bump still has its blob.
	if !f.blobLiveAt(t, f.now.Add(36*time.Hour-time.Second)) {
		t.Fatal("the bump did not extend the blob to 1.5 idle TTLs")
	}
	*f.clock = f.now.Add(12 * time.Hour)
	f.authorize(t, "cmd=show")
	if got := bumps(); got != 2 {
		t.Fatalf("the first permit half an idle TTL after the bump did not bump again: %v", got)
	}
}

// A failed bump is not recorded, so the next permit tries again.
func TestAFailedBlobBumpIsRetried(t *testing.T) {
	f := newAuthorFixture(t)
	f.put(t, store.Context{LastTouchedAt: f.now})
	failing := &failingBumpStore{Store: f.st, fail: true}
	f.h.store = failing
	f.authorize(t, "cmd=show")
	failing.fail = false
	f.authorize(t, "cmd=show")
	if ok, bad := testutil.ToFloat64(f.h.metrics.StoreOps.WithLabelValues("bump_blob", "ok")),
		testutil.ToFloat64(f.h.metrics.StoreOps.WithLabelValues("bump_blob", "error")); ok != 1 || bad != 1 {
		t.Fatalf("bump_blob ok %v error %v", ok, bad)
	}
}

type failingBumpStore struct {
	*memory.Store
	fail bool
}

func (s *failingBumpStore) BumpBlob(ctx context.Context, hash string, ttl time.Duration) error {
	if s.fail {
		return errors.New("store down")
	}
	return s.Store.BumpBlob(ctx, hash, ttl)
}

// The throttle's memory is bounded: past blobBumpMax hashes an entry is
// dropped, which costs that hash one early bump and never a missed one.
func TestTheBlobBumpMemoryIsBounded(t *testing.T) {
	f := newAuthorFixture(t)
	for i := 0; i < blobBumpMax+10; i++ {
		hash := fmt.Sprintf("hash-%d", i)
		if err := f.st.PutBlob(context.Background(), hash, []byte("{}"), time.Hour); err != nil {
			t.Fatal(err)
		}
		f.h.bumpBlob(context.Background(), hash, f.now)
	}
	if got := testutil.ToFloat64(f.h.metrics.StoreOps.WithLabelValues("bump_blob", "ok")); got != blobBumpMax+10 {
		t.Fatalf("bump_blob ok %v: the bumps did not land, so the bound is untested", got)
	}
	if n := len(f.h.bumped); n > blobBumpMax {
		t.Fatalf("%d entries, bound %d", n, blobBumpMax)
	}
}

// A denial bumps nothing: the blob's lifetime follows authorized activity,
// as the context's does.
func TestADenialDoesNotBumpTheBlob(t *testing.T) {
	f := newAuthorFixture(t)
	f.put(t, store.Context{LastTouchedAt: f.now})
	if resp, _ := f.authorize(t, "cmd=reload"); resp.Status != wire.AuthorStatusFail {
		t.Fatalf("%+v", resp)
	}
	if f.blobLiveAt(t, f.now.Add(time.Hour+time.Second)) {
		t.Fatal("a denial bumped the blob")
	}
}

// With lab.deny_session the lab instrument fails the session authorization
// with its padded message: L2's truncation on a platform that never
// authorizes a command (pre-flight I12).
func TestTheLabCanDenyTheSession(t *testing.T) {
	lab := &Lab{DenySession: true, DenyMessageLength: 64}
	d := lab.Session(context.Background(), Request{})
	if d.Permit || len(d.ServerMsg) != 64 || d.Reason == "" {
		t.Fatalf("%+v", d)
	}
	if d := (&Lab{}).Session(context.Background(), Request{}); !d.Permit {
		t.Fatalf("without deny_session: %+v", d)
	}
}

// The lab's command denial is padded too, and left alone at zero.
func TestTheLabCommandDenialIsPadded(t *testing.T) {
	r := Request{Vector: []string{"show", "clock"}}
	d := (&Lab{DenyPrefixes: []string{"show clock"}, DenyMessageLength: 200}).Command(context.Background(), r)
	if d.Permit || len(d.ServerMsg) != 200 || !strings.HasPrefix(d.ServerMsg, "port49: denied by lab_deny (show clock)") {
		t.Fatalf("%q", d.ServerMsg)
	}
	d = (&Lab{DenyPrefixes: []string{"show clock"}}).Command(context.Background(), r)
	if d.ServerMsg != "port49: denied by lab_deny (show clock); see 'port49 explain'" {
		t.Fatalf("%q", d.ServerMsg)
	}
}

// The lab's deny message is padded to deny_message_length with a counting
// pattern, so the device's cut is readable (L2's truncation length).
func TestTheLabDenyMessageIsPadded(t *testing.T) {
	msg := padLabMessage("port49: denied by lab_deny (show clock)", 64)
	if len(msg) != 64 || !strings.HasPrefix(msg, "port49: denied by lab_deny (show clock) ") ||
		strings.IndexFunc(msg, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
		t.Fatalf("%q (%d)", msg, len(msg))
	}
	if got := padLabMessage("abc", 4); got != "abc" {
		t.Fatalf("%q", got)
	}
}

// A standing mark denies a context whatever its record says (plan 7d;
// Ruling 17; pre-flight C1, I12): an unrevoked record under a mark for its
// principal or its certificate (a record put back from before the
// revocation, or one a revocation never reached) is denied
// credential_revoked, and a lifted mark denies nothing.
func TestAStandingMarkDeniesAnUnrevokedContext(t *testing.T) {
	h, st, log := setup(t)
	marks := store.NewMarks()
	h.WithMarks(marks)
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), k, store.Context{CtxID: "c", Principal: "user:alice@example.com",
		Username: "alice", PrivLvl: 15, RefreshedAt: time.Now(),
		Credential: store.Credential{Issuer: "CN=Corp CA", Serial: "0a"}}, time.Hour)
	for _, mark := range []store.Revocation{
		{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Now().Add(-time.Minute)},
		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "0a"), At: time.Now().Add(-time.Minute)},
	} {
		marks.Set(mark, true)
		resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
		if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "credential_revoked" {
			t.Fatalf("%s mark: %+v %v", mark.Kind, resp, lastRecord(t, log))
		}
		marks.Set(mark, false)
	}
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status == wire.AuthorStatusFail && lastRecord(t, log)["reason"] == "credential_revoked" {
		t.Fatalf("a lifted mark still denied: %v", lastRecord(t, log))
	}
}

// authWith is a handler whose lab answers a session authorization with attrs.
func authWith(t *testing.T, ceiling uint8, attrs ...string) (*Handler, *memory.Store, store.ContextKey, *bytes.Buffer) {
	t.Helper()
	st := memory.New(time.Now)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: ceiling, RefreshedAt: time.Now()}, time.Hour)
	log := &bytes.Buffer{}
	h := New(st, &Lab{SessionAttributes: attrs}, decision.NewJSONLines(log),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)
	return h, st, key, log
}

// A session authorization above the context's level is permitted (spec §5.2).
// SR Linux 26.7.2 sends its login START at priv_lvl 0 and its session
// authorization at 1, above the 0 port49 holds (tests/lab/evidence/L76-nokia_srlinux/decisions.jsonl:
// every redeem has session.privilege 0, every authorize_session has
// session.privilege 1 and held_privilege 0); the reply's level is policy's, so
// the request is not compared. The context afterwards holds the reply's
// level, clamped to the ceiling, and never the request's: each case asks at 15
// from a context at 1, and a later command at 15 is permitted only where the
// reply granted it.
func TestSessionAuthorizationAboveTheContextLevelIsPermitted(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ceiling     uint8
		attrs       []string
		sess        string
		want        uint8
		commandPass bool
	}{
		{"reply 15", 15, []string{"priv-lvl=15"}, "cmd=", 15, true},
		{"reply 15 as cmd*", 15, []string{"priv-lvl=15"}, "cmd*", 15, true},
		{"clamped to ceiling", 7, []string{"priv-lvl=15"}, "cmd=", 7, false},
		{"reply 5", 15, []string{"priv-lvl=5"}, "cmd=", 5, false},
		{"reply without priv-lvl", 15, []string{"idletime=30"}, "cmd=", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, st, key, log := authWith(t, tc.ceiling, tc.attrs...)
			sess := req("alice", "vty0", "service=shell", tc.sess)
			sess.PrivLvl = 15
			resp := h.Handle(context.Background(), peer, sess)
			rec := lastRecord(t, log)
			if resp.Status != wire.AuthorStatusPassAdd || rec["verdict"] != "permit" || rec["event"] != "authorize_session" {
				t.Fatalf("%+v %v", resp, rec)
			}
			c, err := st.GetContext(context.Background(), key)
			if err != nil || c.PrivLvl != tc.want {
				t.Fatalf("the context holds the reply's level (clamped), not the request's 15: want %d, got %+v %v", tc.want, c, err)
			}
			cmd := req("alice", "vty0", "service=shell", "cmd=show")
			cmd.PrivLvl = 15
			resp = h.Handle(context.Background(), peer, cmd)
			if tc.commandPass {
				if resp.Status != wire.AuthorStatusPassAdd {
					t.Fatalf("a command at the granted 15 must be permitted: %+v", resp)
				}
			} else if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "privilege_exceeded" {
				t.Fatalf("a command at 15 above the granted %d must be privilege_exceeded: %+v %v", tc.want, resp, lastRecord(t, log))
			}
		})
	}
}

// The other checks still run on a session authorization above the context's
// level (spec §5.2): the ones before the moved line and the one after it.
func TestSessionAuthorizationAboveTheContextLevelStillMeetsTheOtherChecks(t *testing.T) {
	h, st, log := setup(t)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, RevokedAt: time.Now(), RefreshedAt: time.Now()}, time.Hour)
	sess := req("alice", "vty0", "service=shell", "cmd=")
	sess.PrivLvl = 15
	resp := h.Handle(context.Background(), peer, sess)
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "credential_revoked" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}

	h, st, log = setup(t)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, RefreshedAt: time.Now()}, time.Hour)
	sess = req("alice", "vty0", "service=bogus", "cmd=")
	sess.PrivLvl = 15
	resp = h.Handle(context.Background(), peer, sess)
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "service_unsupported" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
}

// session.held_privilege is the context's level when the request arrived, on
// every authorization record whose context was read, permits and denials, and
// present when it is 0. session.privilege stays the request header's level.
// No context was read on context_missing, so the field is absent there.
func TestHeldPrivilegeIsRecordedOnEveryAuthorizationRecordWithAContext(t *testing.T) {
	for _, tc := range []struct {
		name   string
		held   uint8
		lvl    uint8
		args   []string
		event  string
		reason string
	}{
		{"session permit", 1, 15, []string{"service=shell", "cmd="}, "authorize_session", "context_matched"},
		{"session permit held 0", 0, 15, []string{"service=shell", "cmd="}, "authorize_session", "context_matched"},
		{"session deny", 1, 15, []string{"service=bogus", "cmd="}, "authorize_session", "service_unsupported"},
		{"command permit", 15, 1, []string{"service=shell", "cmd=show"}, "authorize_command", "permit_dominates"},
		{"command permit held 0", 0, 0, []string{"service=shell", "cmd=show"}, "authorize_command", "permit_dominates"},
		{"command deny", 1, 15, []string{"service=shell", "cmd=show"}, "authorize_command", "privilege_exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, st, log := setup(t)
			st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
				store.Context{CtxID: "c", Username: "alice", PrivLvl: tc.held, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)
			r := req("alice", "vty0", tc.args...)
			r.PrivLvl = tc.lvl
			h.Handle(context.Background(), peer, r)
			rec := lastRecord(t, log)
			if rec["event"] != tc.event || rec["reason"] != tc.reason {
				t.Fatalf("the case does not exercise what it names: %v", rec)
			}
			sess := rec["session"].(map[string]any)
			got, ok := sess["held_privilege"]
			if !ok || got != float64(tc.held) {
				t.Fatalf("session.held_privilege: want %d present, got %v (present=%v) in %v", tc.held, got, ok, sess)
			}
			if sess["privilege"] != float64(tc.lvl) {
				t.Fatalf("session.privilege must stay the request header's level %d: %v", tc.lvl, sess)
			}
			if _, ok := rec["request"].(map[string]any)["priv_lvl"]; ok {
				t.Fatalf("request.priv_lvl duplicated session.privilege and is not recorded: %v", rec["request"])
			}
		})
	}

	t.Run("no context", func(t *testing.T) {
		h, _, log := setup(t)
		h.Handle(context.Background(), peer, req("nobody", "vty0", "service=shell", "cmd="))
		rec := lastRecord(t, log)
		if rec["reason"] != "context_missing" {
			t.Fatalf("%v", rec)
		}
		if _, ok := rec["session"].(map[string]any)["held_privilege"]; ok {
			t.Fatalf("no context was read, so held_privilege is absent: %v", rec["session"])
		}
	})
}

// A request is a session only when its final cmd is empty, it carries no
// cmd-arg and at most one cmd attribute (spec §5.2). `cmd*`, `cmd=` and a bare
// `cmd` alone are sessions; a command hidden behind an empty final cmd is
// command authorization, where the privilege check applies and an empty command
// matches nothing.
func TestSessionShapes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		session bool
	}{
		{"cmd=", []string{"service=shell", "cmd="}, true},
		{"cmd*", []string{"service=shell", "cmd*"}, true},
		{"bare cmd", []string{"service=shell", "cmd"}, true},
		{"cmd= with cmd-arg", []string{"service=shell", "cmd=", "cmd-arg=reload"}, false},
		{"cmd=reload then cmd=", []string{"service=shell", "cmd=reload", "cmd="}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, st, key, log := authWith(t, 15, "priv-lvl=15")
			r := req("alice", "vty0", tc.args...)
			r.PrivLvl = 15
			resp := h.Handle(context.Background(), peer, r)
			rec := lastRecord(t, log)
			c, _ := st.GetContext(context.Background(), key)
			if tc.session {
				if rec["event"] != "authorize_session" || resp.Status != wire.AuthorStatusPassAdd || c.PrivLvl != 15 {
					t.Fatalf("%+v %v %+v", resp, rec, c)
				}
				return
			}
			if rec["event"] != "authorize_command" || rec["reason"] != "privilege_exceeded" || resp.Status != wire.AuthorStatusFail || c.PrivLvl != 1 {
				t.Fatalf("a command shape above the context is privilege_exceeded and raises nothing: %+v %v %+v", resp, rec, c)
			}
			// At a level the context holds it still gets no session reply:
			// an empty command matches nothing.
			r.PrivLvl = 1
			resp = h.Handle(context.Background(), peer, r)
			rec = lastRecord(t, log)
			c, _ = st.GetContext(context.Background(), key)
			if rec["event"] != "authorize_command" || rec["reason"] != "no_rule_matched" || resp.Status != wire.AuthorStatusFail || len(resp.Args) != 0 || c.PrivLvl != 1 {
				t.Fatalf("%+v %v %+v", resp, rec, c)
			}
		})
	}
}
