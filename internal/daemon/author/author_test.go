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

func setup(t *testing.T) (*Handler, *memory.Store, *bytes.Buffer) {
	t.Helper()
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Port: "ssh", PrivLvl: 15}, time.Hour)
	log := &bytes.Buffer{}
	lab := &Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload", "copy running-config tftp:"}}
	return New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults()), st, log
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
			h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults())
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
		}},
		{"lab_deny", func(t *testing.T) wire.AuthorResponse {
			h, _, _ := setup(t)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=reload", "cmd-arg=<cr>"))
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
	h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults())

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
	return New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now, services), log
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
			metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults())

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
