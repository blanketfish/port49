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
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

var peer = authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}

func setup(t *testing.T) (*Handler, *memory.Store, *bytes.Buffer) {
	t.Helper()
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"},
		store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15}, time.Hour)
	log := &bytes.Buffer{}
	lab := &Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload", "copy running-config tftp:"}}
	return New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now), st, log
}

func req(user, port string, args ...string) wire.AuthorRequest {
	r := wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte(port)}
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

func TestNoContextIsDistinct(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("alice", "vty9", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "context_missing" || len(resp.ServerMsg) == 0 {
		t.Fatalf("%+v", resp)
	}
}

func TestUsernameMismatchInvalidates(t *testing.T) {
	h, st, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("bob", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "username_mismatch" {
		t.Fatalf("%+v", resp)
	}
	if _, err := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"}); err == nil {
		t.Fatal("context must be invalidated")
	}
}

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
			return h.Handle(context.Background(), peer, req("alice", "vty9", "service=shell", "cmd=show"))
		}},
		{"username_mismatch", func(t *testing.T) wire.AuthorResponse {
			h, _, _ := setup(t)
			return h.Handle(context.Background(), peer, req("bob", "vty0", "service=shell", "cmd=show"))
		}},
		{"service_unsupported", func(t *testing.T) wire.AuthorResponse {
			h, _, _ := setup(t)
			return h.Handle(context.Background(), peer, req("alice", "vty0", "service=ppp\x1b[31m", "protocol=ip"))
		}},
		{"store_unavailable", func(t *testing.T) wire.AuthorResponse {
			st := &errGetContextStore{Store: memory.New(time.Now), err: errors.New("store: connection refused")}
			log := &bytes.Buffer{}
			lab := &Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload"}}
			h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now)
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
	h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now)

	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || string(resp.ServerMsg) != "port49: authorization store unavailable" {
		t.Fatalf("%+v", resp)
	}
	r := lastRecord(t, log)
	if r["reason"] != "store_unavailable" {
		t.Fatalf("%v", r)
	}
}
