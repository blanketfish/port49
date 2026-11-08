package port49d

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The healthcheck subcommand of both mains reads metrics_listen from the file alone and probes
// /healthz by default, /readyz with --ready.
func TestHealthcheckSubcommandsProbeTheirOwnPaths(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(cfg, []byte("metrics_listen: \""+strings.TrimPrefix(srv.URL, "http://")+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		binary string
		run    func([]string) int
	}{{"port49d", Main}, {"port49-broker", BrokerMain}} {
		for _, c := range []struct {
			args []string
			want string
		}{
			{[]string{"healthcheck", "--config", cfg}, "/healthz"},
			{[]string{"healthcheck", "--ready", "--config", cfg}, "/readyz"},
		} {
			mu.Lock()
			paths = nil
			mu.Unlock()
			if code := tc.run(c.args); code != 0 {
				t.Errorf("%s %v: exit %d, want 0", tc.binary, c.args, code)
			}
			mu.Lock()
			got := strings.Join(paths, ",")
			mu.Unlock()
			if got != c.want {
				t.Errorf("%s %v requested %q, want %q", tc.binary, c.args, got, c.want)
			}
		}
		if code := tc.run([]string{"healthcheck", "--bogus"}); code != 1 {
			t.Errorf("%s healthcheck --bogus: exit %d, want 1", tc.binary, code)
		}
	}
}

func TestTheSubcommandTablesListHealthcheck(t *testing.T) {
	if !slices.Contains(DaemonSubcommands(), "healthcheck") {
		t.Error("DaemonSubcommands does not list healthcheck")
	}
	if !slices.Contains(BrokerSubcommands(), "healthcheck") {
		t.Error("BrokerSubcommands does not list healthcheck")
	}
}
