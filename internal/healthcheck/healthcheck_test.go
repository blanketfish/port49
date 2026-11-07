package healthcheck

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func serve(t *testing.T, h http.HandlerFunc) (listen string) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestRunProbesThePath(t *testing.T) {
	listen := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
		case "/readyz":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("waiting for the store\nsecond line"))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("bad\x1b[31m\x07 news"))
		}
	})
	var out bytes.Buffer
	if got := Run(context.Background(), listen, "/healthz", &out); got != 0 || out.Len() != 0 {
		t.Fatalf("/healthz 200: exit %d, output %q; want 0 and nothing", got, out.String())
	}
	out.Reset()
	if got := Run(context.Background(), listen, "/readyz", &out); got != 1 {
		t.Fatalf("/readyz 503: exit %d, want 1", got)
	}
	if want := "healthcheck: /readyz answered 503: waiting for the store\n"; out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
	out.Reset()
	if got := Run(context.Background(), listen, "/other", &out); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	if strings.ContainsAny(out.String()[:len(out.String())-1], "\x1b\x07\n") {
		t.Fatalf("a control character reached the output: %q", out.String())
	}
	if !strings.Contains(out.String(), "bad?[31m? news") {
		t.Fatalf("control characters not escaped by printsafe: %q", out.String())
	}
}

func TestRunSaysTheDialError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	var out bytes.Buffer
	if got := Run(context.Background(), addr, "/healthz", &out); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	if !strings.HasPrefix(out.String(), "healthcheck: ") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("output %q: want one line starting healthcheck: ", out.String())
	}
}

func TestRunDialsLoopbackForAWildcard(t *testing.T) {
	for in, want := range map[string]string{
		":9049":         "127.0.0.1:9049",
		"0.0.0.0:9049":  "127.0.0.1:9049",
		"[::]:9049":     "127.0.0.1:9049",
		"10.1.2.3:9049": "10.1.2.3:9049",
	} {
		got, err := DialAddr(in)
		if err != nil || got != want {
			t.Errorf("DialAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := DialAddr("nonsense"); err == nil {
		t.Error("DialAddr(nonsense) did not fail")
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnEmptyMetricsListenTakesTheRoleDefault(t *testing.T) {
	empty := writeConfig(t, "store:\n  kind: memory\n")
	for def, want := range map[string]string{":9049": ":9049", ":9050": ":9050"} {
		got, err := MetricsListen(empty, def)
		if err != nil || got != want {
			t.Errorf("empty key, default %s: %q, %v", def, got, err)
		}
	}
	named := writeConfig(t, "metrics_listen: \"127.0.0.1:7000\"\n")
	if got, err := MetricsListen(named, ":9049"); err != nil || got != "127.0.0.1:7000" {
		t.Errorf("named key: %q, %v", got, err)
	}
	if _, err := MetricsListen(filepath.Join(t.TempDir(), "missing.yaml"), ":9049"); err == nil {
		t.Error("a missing file did not fail")
	}
}

// seen records the paths a server was asked for.
type seen struct {
	mu    sync.Mutex
	paths []string
}

func (s *seen) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
}

func (s *seen) got() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.paths, ",")
}

func TestTheDefaultProbesHealthz(t *testing.T) {
	var s seen
	listen := serve(t, s.handler)
	cfg := writeConfig(t, "metrics_listen: \""+listen+"\"\n")
	var out bytes.Buffer
	if got := Command("port49d", "/nonexistent.yaml", ":9049", []string{"--config", cfg}, &out); got != 0 {
		t.Fatalf("exit %d: %s", got, out.String())
	}
	if s.got() != "/healthz" {
		t.Fatalf("requested %q, want /healthz", s.got())
	}
}

func TestReadyProbesReadyz(t *testing.T) {
	var s seen
	listen := serve(t, s.handler)
	cfg := writeConfig(t, "metrics_listen: \""+listen+"\"\n")
	var out bytes.Buffer
	if got := Command("port49d", "/nonexistent.yaml", ":9049", []string{"--ready", "--config", cfg}, &out); got != 0 {
		t.Fatalf("exit %d: %s", got, out.String())
	}
	if s.got() != "/readyz" {
		t.Fatalf("requested %q, want /readyz", s.got())
	}
	out.Reset()
	if got := Command("port49d", "/nonexistent.yaml", ":9049", []string{"--live", "--config", cfg}, &out); got != 1 {
		t.Fatalf("--live: exit %d, want 1 (unknown flag)", got)
	}
	if s.got() != "/readyz" {
		t.Fatalf("--live reached the server: %q", s.got())
	}
}

func TestAHealthcheckNeverExitsTwo(t *testing.T) {
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "u.yaml")
	if err := os.WriteFile(unreadable, []byte("x: 1\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	bad := writeConfig(t, "metrics_listen: [unterminated\n")
	for name, args := range map[string][]string{
		"unknown flag":   {"--bogus"},
		"positional":     {"extra"},
		"missing config": {"--config", filepath.Join(dir, "missing.yaml")},
		"unreadable":     {"--config", unreadable},
		"bad yaml":       {"--config", bad},
	} {
		var out bytes.Buffer
		if got := Command("port49d", "/nonexistent.yaml", ":9049", args, &out); got != 1 {
			t.Errorf("%s: exit %d, want 1 (output %q)", name, got, out.String())
		}
		if !strings.HasPrefix(out.String(), "healthcheck: ") {
			t.Errorf("%s: output %q does not start with healthcheck: ", name, out.String())
		}
	}
}
