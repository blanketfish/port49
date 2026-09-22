package author

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
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
	if d := l.Command(context.Background(), store.Context{}, []string{"show", "version"}, nil); d.Permit {
		t.Fatalf("expected \"show version\" to be denied by prefix \"show\": %+v", d)
	}
	if d := l.Command(context.Background(), store.Context{}, []string{"shower"}, nil); !d.Permit {
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
	if resp.Status != wire.AuthorStatusFail || string(resp.ServerMsg) != "port49: authorization store unavailable" {
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

	d := l.Command(context.Background(), store.Context{}, []string{"show", "version"}, nil)
	if !d.Permit {
		t.Fatalf("expected a permit for \"show version\": %+v", d)
	}
	if len(d.Attributes) != 1 || d.Attributes[0] != "p49-nonsense*1" {
		t.Fatalf("a permitted command reply should carry the configured command attributes, got %q", d.Attributes)
	}

	if d := l.Command(context.Background(), store.Context{}, []string{"reload"}, nil); d.Permit {
		t.Fatalf("expected \"reload\" to be denied: %+v", d)
	} else if len(d.Attributes) != 0 {
		t.Fatalf("a DENIED command reply must carry no attributes, got %q", d.Attributes)
	}

	// The two lists are separate: a session reply does not pick up command
	// attributes, which is what makes L18 able to vary one at a time.
	s := l.Session(context.Background(), store.Context{}, nil)
	if len(s.Attributes) != 1 || s.Attributes[0] != "priv-lvl=15" {
		t.Fatalf("the session reply should carry only the session attributes, got %q", s.Attributes)
	}

	// Unset is the shipped shape and must stay a bare permit.
	bare := &Lab{DenyPrefixes: []string{"reload"}}
	if d := bare.Command(context.Background(), store.Context{}, []string{"show", "version"}, nil); len(d.Attributes) != 0 {
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
}

// The name says what it asserts: the context is still there afterwards.
// `graceWindow` is carried but unread — nothing in this plan deletes a context
// on expiry, with or without a window — so this test would pass either way, and
// plan 7's author must not read it as evidence that the window is exercised.
func TestExpiredSessionDeniesAndDoesNotDeleteTheContext(t *testing.T) {
	h, st, log := setupClock(t, time.Now, time.Hour, 10*time.Minute, time.Hour)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, RefreshedAt: time.Now(), SessionExpires: time.Now().Add(-time.Minute)}, time.Hour)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "session_expired" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
	if _, err := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); err != nil {
		t.Fatal("context must be retained through the grace window so a late `port49 login` resumes it")
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
	c, _ := inner.GetContext(context.Background(), key)
	c.SessionDiscriminator = "14656"
	inner.PutContext(context.Background(), key, c, 30*time.Minute)
	now = now.Add(20 * time.Minute)
	if resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show")); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("the command that must extend the TTL was denied: %+v", resp)
	}
	if st.touches != 5 {
		t.Fatalf("the extension did not run, so the assertion below proves nothing: %d touches", st.touches)
	}
	if got, _ := inner.GetContext(context.Background(), key); got.SessionDiscriminator != "14656" {
		t.Fatalf("the extension discarded the accounting annotation: %+v", got)
	}
}

// TestTheDevicePrivLvlRaisedByOurOwnSessionReply pins the behaviour the §5.3
// privilege check produces against the sequence the lab actually measured, and
// it is here because that behaviour looks wrong and the decision is not this
// task's to make.
//
// Measured on vEOS (tests/lab/results/L1-arista_eos.md lines 62-63;
// L3-arista_eos.md lines 72-76), and the same shape on the other platforms:
//
//	AUTHOR REQUEST  priv_lvl=1  args=[service=shell cmd*]      <- session
//	AUTHOR RESPONSE status=PASS_ADD args=[priv-lvl=15 ...]     <- port49 grants 15
//	AUTHOR REQUEST  priv_lvl=15 args=[service=shell cmd=terminal ...]
//
// The device raises the session to the level port49's own reply granted, and
// every command after that arrives at 15. The login context's PrivLvl is still
// the 1 the login START carried — nothing writes the granted level back — so
// `req.PrivLvl > c.PrivLvl` denies every one of those commands
// `privilege_exceeded`. That is an operator logged in successfully and then
// unable to run anything, which is the 3am failure.
//
// The check is spec §5.3 as written, and the plan's Task 10 brief specifies it
// verbatim, so it ships as specified. What is unresolved is which value is
// "the session's granted level" (§5.7): ctx.privilege, as §5.3's pseudocode
// says, or what the session authorization reply granted, which is what the
// device believes and acts on. Resolving it means either the session
// authorization writes the granted level into the context, or the check reads
// ctx.max_privilege. Both are owner decisions with a lab test behind them.
//
// This test asserts today's behaviour so the break is discoverable rather than
// latent. When the rule is settled, this test changes with a lab citation.
func TestTheDevicePrivLvlRaisedByOurOwnSessionReply(t *testing.T) {
	h, st, log := setup(t)
	// The context as a login START at priv_lvl=1 leaves it.
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)

	// The session authorization the device sends, and the priv-lvl=15 it gets.
	sess := req("alice", "vty4", "service=shell", "cmd=")
	sess.PrivLvl = 1
	resp := h.Handle(context.Background(), peer, sess)
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 1 || string(resp.Args[0]) != "priv-lvl=15" {
		t.Fatalf("the session authorization must still be permitted and grant priv-lvl=15: %+v", resp)
	}

	// The first command after it, at the level the device took from that reply.
	cmd := req("alice", "vty4", "service=shell", "cmd=terminal", "cmd-arg=length", "cmd-arg=0", "cmd-arg=<cr>")
	cmd.PrivLvl = 15
	resp = h.Handle(context.Background(), peer, cmd)
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "privilege_exceeded" {
		t.Fatalf("this test records a known break; if it now permits, the rule was settled "+
			"and this test must be rewritten with the lab citation: %+v %v", resp, lastRecord(t, log))
	}
}

type countingTouchStore struct {
	store.Store
	touches int
}

func (c *countingTouchStore) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	c.touches++
	return c.Store.TouchContext(ctx, k, ttl)
}
