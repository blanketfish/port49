// Package oxidized holds the Oxidized example's test: the wrapper run against
// a fake port49 and a fake Oxidized REST API (plan 8, Task 12). The real
// Oxidized is lab L49's (tests/lab).
package oxidized

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeOxidized struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeOxidized) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	_, _ = w.Write([]byte("{}"))
}

// run runs the wrapper with a fake port49 that writes tsv to --out and exits
// with exit, against a fake Oxidized; it returns the exit code, stderr, the
// REST calls and the router.db path.
func run(t *testing.T, tsv string, exit int, oldDB string) (int, string, []string, string) {
	t.Helper()
	return runWith(t, tsv, exit, oldDB, true)
}

// runWith is run, where write false is a fake port49 that never touches --out
// (its output could not be written, exit 75).
func runWith(t *testing.T, tsv string, exit int, oldDB string, write bool) (int, string, []string, string) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed: the wrapper needs it", tool)
		}
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "port49")
	script := `#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do [ "$1" = --out ] && out=$2; shift; done
if [ "$FAKE_WRITE" = 1 ]; then printf '%s' "$FAKE_TSV" > "$out"; fi
exit $FAKE_EXIT
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "router.db")
	if oldDB != "" {
		if err := os.WriteFile(db, []byte(oldDB), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nodes := filepath.Join(dir, "nodes")
	if err := os.WriteFile(nodes, []byte("leaf1\nvjunos1\nfw7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeOxidized{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	fakeWrite := "0"
	if write {
		fakeWrite = "1"
	}
	cmd := exec.Command("bash", "port49-oxidized-run")
	cmd.Env = append(os.Environ(), "PORT49_BIN="+fake, "PORT49_BROKER=https://broker.example:8443",
		"PORT49_BROKER_CA=/ca.pem", "PORT49_CERT=/w.pem", "PORT49_KEY=/w-key.pem", "OXIDIZED_NODES="+nodes,
		"OXIDIZED_ROUTER_DB="+db, "OXIDIZED_REST="+srv.URL, "FAKE_TSV="+tsv, "FAKE_EXIT="+strconv.Itoa(exit),
		"FAKE_WRITE="+fakeWrite)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return code, stderr.String(), append([]string(nil), f.calls...), db
}

const minted = "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n" +
	"vjunos1\t10.0.0.21\tjuniper_junos\tsvc-oxidized\tTOKENJUNOS1\t2026-10-08T03:00:00Z\n" +
	"fw7\t10.0.0.77\tpaloalto_panos\tsvc-oxidized\tTOKENFW7\t2026-10-08T03:00:00Z\n"

func TestTheRunWritesRouterDBAndQueuesEachNode(t *testing.T) {
	code, stderr, calls, db := run(t, minted, 0, "")
	raw, err := os.ReadFile(db)
	want := "leaf1\t10.0.0.11\teos\tsvc-oxidized\tTOKENLEAF1\nvjunos1\t10.0.0.21\tjunos\tsvc-oxidized\tTOKENJUNOS1\n"
	if code != 0 || err != nil || string(raw) != want {
		t.Fatalf("exit %d router.db %q stderr %s", code, raw, stderr)
	}
	if fi, err := os.Stat(db); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("router.db mode: %v %v", fi, err)
	}
	if !strings.Contains(stderr, "fw7: platform paloalto_panos has no Oxidized model in this script; skipped") {
		t.Fatalf("stderr %s", stderr)
	}
	if strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1,PUT /node/next/vjunos1" {
		t.Fatalf("calls %v", calls)
	}
	if strings.Contains(stderr, "TOKEN") {
		t.Fatalf("a token on stderr: %s", stderr)
	}
}

// 75 from port49: nothing was minted, so Oxidized keeps its last router.db
// and is not reloaded, and the run exits 75 for cron.
func TestATemporaryFailureLeavesOxidizedAlone(t *testing.T) {
	code, stderr, calls, db := run(t, "", 75, "old\tdb\n")
	raw, _ := os.ReadFile(db)
	if code != 75 || string(raw) != "old\tdb\n" || len(calls) != 0 ||
		!strings.Contains(stderr, "no tokens minted (port49 workload token exited 75); Oxidized keeps its last router.db and was not reloaded") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// 75 because the output could not be written: the fake port49 leaves --out
// empty, so the wrapper's fresh file holds nothing and it takes its
// nothing-minted path; the last router.db stands and nothing is reloaded.
func TestAnUnwritableOutputLeavesOxidizedAlone(t *testing.T) {
	code, stderr, calls, db := runWith(t, minted, 75, "old\tdb\n", false)
	raw, _ := os.ReadFile(db)
	if code != 75 || string(raw) != "old\tdb\n" || len(calls) != 0 ||
		!strings.Contains(stderr, "no tokens minted (port49 workload token exited 75); Oxidized keeps its last router.db and was not reloaded") ||
		strings.Contains(stderr, "TOKEN") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// 1 from port49: one device was not permitted; the rest are queued, and the
// run exits 1.
func TestADeniedNodeStillQueuesTheRest(t *testing.T) {
	code, _, calls, _ := run(t, "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n", 1, "")
	if code != 1 || strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" {
		t.Fatalf("exit %d calls %v", code, calls)
	}
}

// 77 from port49 (the certificate expired while the CA was down, a revoked
// principal, every node denied): nothing was minted, so Oxidized keeps its
// last router.db and is not reloaded, never an empty one (pre-flight I-1).
func TestAnExpiredCertificateLeavesOxidizedAlone(t *testing.T) {
	code, stderr, calls, db := run(t, "", 77, "old\tdb\n")
	raw, _ := os.ReadFile(db)
	if code != 77 || string(raw) != "old\tdb\n" || len(calls) != 0 ||
		!strings.Contains(stderr, "no tokens minted (port49 workload token exited 77); Oxidized keeps its last router.db and was not reloaded") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// 75 with a page minted before the deadline: the minted nodes are written
// and queued, the run says not every node was, and exits 75 (pre-flight M-7).
func TestAPartialRunQueuesWhatWasMinted(t *testing.T) {
	code, stderr, calls, db := run(t, "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n", 75,
		"old\tdb\n")
	raw, _ := os.ReadFile(db)
	if code != 75 || string(raw) != "leaf1\t10.0.0.11\teos\tsvc-oxidized\tTOKENLEAF1\n" ||
		strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" ||
		!strings.Contains(stderr, "not every node was minted (port49 workload token exited 75") ||
		strings.Contains(stderr, "no tokens minted") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// A node name goes into a REST path: one outside A-Z a-z 0-9 . _ - is
// skipped with a line, never put in a path (pre-flight M-13).
func TestANodeNameOutsideTheSafeSetIsSkipped(t *testing.T) {
	code, stderr, calls, _ := run(t, "core/sw#1\t10.0.0.9\tarista_eos\tsvc-oxidized\tTOKENBAD\t2026-10-08T03:00:00Z\n"+
		"leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n", 0, "")
	if code != 0 || strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" ||
		!strings.Contains(stderr, "core/sw#1: a node name outside A-Z a-z 0-9 . _ - is never put in a REST path; skipped") ||
		strings.Contains(stderr, "TOKEN") {
		t.Fatalf("exit %d calls %v stderr %s", code, calls, stderr)
	}
}
