// Package oxidized holds the Oxidized example's test: the wrapper run against
// a fake port49 and a fake Oxidized REST API (plan 8, Task 12). The real
// Oxidized is lab L49's (tests/lab).
package oxidized

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeOxidized struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool // "METHOD /path" answered 500
}

func (f *fakeOxidized) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	f.mu.Lock()
	f.calls = append(f.calls, key)
	failed := f.fail[key]
	f.mu.Unlock()
	if failed {
		http.Error(w, "no", http.StatusInternalServerError)
		return
	}
	// oxidized-web 0.18.1 parses a PUT's body as JSON (webapp.rb:126), and an
	// empty one raises: a 500 (lab L49, first EOS run).
	if r.Method == http.MethodPut {
		var opt map[string]any
		if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
			http.Error(w, "JSON::ParserError", http.StatusInternalServerError)
			return
		}
	}
	_, _ = w.Write([]byte("{}"))
}

// scenario is one run of the wrapper.
type scenario struct {
	tsv     string
	exit    int
	oldDB   string
	noWrite bool            // the fake port49 never touches --out
	fail    map[string]bool // REST calls the fake Oxidized answers 500
	hold    bool            // another run holds the lock beside router.db
	noDir   bool            // router.db's directory does not exist
	scope   string          // PORT49_SCOPE, when set
	// known_hosts: the addresses it lists before the run, what the fake ssh does with
	// an unknown one, and where runCase puts what it saw
	seed      []string
	sshNoSave bool
	sshSleep  string // seconds the fake ssh sleeps, as sleep takes it
	jobs      int    // OXIDIZED_HOSTKEY_JOBS, when set
	budget    int    // OXIDIZED_HOSTKEY_BUDGET seconds, when set
	sshBin    string // OXIDIZED_SSH, when set (the fake otherwise)
	khPath    string // OXIDIZED_KNOWN_HOSTS, when set
	tsv2      string // what the fake port49 writes from its second call on, when set
	res       *sshResult
}

// sshResult is what the fake ssh and known_hosts held after a run.
type sshResult struct {
	calls      [][]string // one slice of arguments per ssh call
	knownHosts string
	khPath     string
	order      []string // "mint" and "ssh", in the order the fakes ran
	maxConc    int      // the most ssh calls running at once
}

// run runs the wrapper with a fake port49 that writes tsv to --out and exits
// with exit, against a fake Oxidized; it returns the exit code, stderr, the
// REST calls and the router.db path.
func run(t *testing.T, tsv string, exit int, oldDB string) (int, string, []string, string) {
	t.Helper()
	return runCase(t, scenario{tsv: tsv, exit: exit, oldDB: oldDB})
}

// runWith is run, where write false is a fake port49 that never touches --out
// (its output could not be written, exit 75).
func runWith(t *testing.T, tsv string, exit int, oldDB string, write bool) (int, string, []string, string) {
	t.Helper()
	return runCase(t, scenario{tsv: tsv, exit: exit, oldDB: oldDB, noWrite: !write})
}

func runCase(t *testing.T, c scenario) (int, string, []string, string) {
	t.Helper()
	tsv, exit, oldDB, write := c.tsv, c.exit, c.oldDB, !c.noWrite
	for _, tool := range []string{"bash", "curl", "awk", "flock", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed: the wrapper needs it", tool)
		}
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "port49")
	script := `#!/usr/bin/env bash
echo mint >> "$FAKE_ORDER"
printf '%s\n' "$@" > "$FAKE_ARGS"
out=""
while [ $# -gt 0 ]; do [ "$1" = --out ] && out=$2; shift; done
body=$FAKE_TSV
if [ -n "$FAKE_TSV2" ] && [ "$(grep -c mint "$FAKE_ORDER")" -ge 2 ]; then body=$FAKE_TSV2; fi
if [ "$FAKE_WRITE" = 1 ]; then printf '%s' "$body" > "$out"; fi
exit $FAKE_EXIT
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// a fake ssh: it records its arguments and, like OpenSSH under accept-new, saves the
	// host key it was pointed at into UserKnownHostsFile (unless the scenario says it cannot)
	keyBase := filepath.Join(dir, "hostkey")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyBase).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	pub, rerr := os.ReadFile(keyBase + ".pub")
	if rerr != nil {
		t.Fatal(rerr)
	}
	keyFields := strings.Join(strings.Fields(string(pub))[:2], " ")
	khPath := filepath.Join(dir, "known_hosts")
	var seeded strings.Builder
	for _, a := range c.seed {
		seeded.WriteString(a + " " + keyFields + "\n")
	}
	if err := os.WriteFile(khPath, []byte(seeded.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	sshLog := filepath.Join(dir, "ssh-calls")
	conc := filepath.Join(dir, "conc")
	if err := os.MkdirAll(conc, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeSSH := filepath.Join(dir, "ssh")
	sshScript := `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_SSH_LOG"
echo ssh >> "$FAKE_ORDER"
touch "$FAKE_CONC/$$"
ls "$FAKE_CONC" | wc -l >> "$FAKE_CONC.max"
sleep "${FAKE_SSH_SLEEP:-0}"
rm -f "$FAKE_CONC/$$"
kh=""
for a in "$@"; do case $a in UserKnownHostsFile=*) kh=${a#UserKnownHostsFile=} ;; esac; done
addr=${@: -2:1}
if [ "$FAKE_SSH_SAVE" = 1 ]; then printf '%s %s\n' "$addr" "$FAKE_KEY" >> "$kh"; fi
exit 255
`
	if err := os.WriteFile(fakeSSH, []byte(sshScript), 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "router.db")
	if c.noDir {
		db = filepath.Join(dir, "missing", "router.db")
	}
	if oldDB != "" {
		if err := os.WriteFile(db, []byte(oldDB), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.hold {
		lock, err := os.OpenFile(db+".lock", os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lock.Close() })
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
	}
	nodes := filepath.Join(dir, "nodes")
	if err := os.WriteFile(nodes, []byte("leaf1\nvjunos1\nfw7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeOxidized{fail: c.fail}
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
		"FAKE_WRITE="+fakeWrite, "FAKE_ARGS="+filepath.Join(dir, "args"), "OXIDIZED_SSH="+firstNonEmpty(c.sshBin, fakeSSH),
		"OXIDIZED_KNOWN_HOSTS="+firstNonEmpty(c.khPath, khPath), "FAKE_TSV2="+c.tsv2, "FAKE_SSH_LOG="+sshLog, "FAKE_ORDER="+filepath.Join(dir, "order"), "FAKE_CONC="+conc, "FAKE_SSH_SLEEP="+c.sshSleep, "FAKE_KEY="+keyFields, "FAKE_SSH_SAVE="+map[bool]string{true: "0", false: "1"}[c.sshNoSave])
	if c.scope != "" {
		cmd.Env = append(cmd.Env, "PORT49_SCOPE="+c.scope)
	}
	if c.jobs > 0 {
		cmd.Env = append(cmd.Env, "OXIDIZED_HOSTKEY_JOBS="+strconv.Itoa(c.jobs))
	}
	if c.budget > 0 {
		cmd.Env = append(cmd.Env, "OXIDIZED_HOSTKEY_BUDGET="+strconv.Itoa(c.budget))
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if c.res != nil {
		raw, _ := os.ReadFile(sshLog)
		for _, ln := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if ln != "" {
				c.res.calls = append(c.res.calls, strings.Fields(ln))
			}
		}
		kh, _ := os.ReadFile(khPath)
		c.res.knownHosts = string(kh)
		c.res.khPath = khPath
		ord, _ := os.ReadFile(filepath.Join(dir, "order"))
		c.res.order = strings.Fields(string(ord))
		mx, _ := os.ReadFile(conc + ".max")
		for _, f := range strings.Fields(string(mx)) {
			if n, err := strconv.Atoi(f); err == nil && n > c.res.maxConc {
				c.res.maxConc = n
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return code, stderr.String(), append([]string(nil), f.calls...), db
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

const minted = "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n" +
	"vjunos1\t10.0.0.21\tjuniper_junos\tsvc-oxidized\tTOKENJUNOS1\t2026-10-08T03:00:00Z\n" +
	"fw7\t10.0.0.77\tpaloalto_panos\tsvc-oxidized\tTOKENFW7\t2026-10-08T03:00:00Z\n"

func TestTheRunWritesRouterDBAndQueuesEachNode(t *testing.T) {
	code, stderr, calls, db := run(t, minted, 0, "")
	raw, err := os.ReadFile(db)
	want := "leaf1\t10.0.0.11\teos\tsvc-oxidized\tTOKENLEAF1\nvjunos1\t10.0.0.21\tjunos\tsvc-oxidized\tTOKENJUNOS1\n"
	if code != 1 || err != nil || string(raw) != want { // fw7 was skipped: exit 1
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
	if code != 1 || strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" ||
		!strings.Contains(stderr, "core/sw#1: a node name outside A-Z a-z 0-9 . _ - is never put in a REST path; skipped") ||
		strings.Contains(stderr, "TOKEN") {
		t.Fatalf("exit %d calls %v stderr %s", code, calls, stderr)
	}
}

const leafAndJunos = "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n" +
	"vjunos1\t10.0.0.21\tjuniper_junos\tsvc-oxidized\tTOKENJUNOS1\t2026-10-08T03:00:00Z\n"

// Every minted node is skipped: nothing replaces the last router.db, nothing
// is reloaded, and the run exits 1.
func TestEveryNodeSkippedLeavesOxidizedAlone(t *testing.T) {
	code, stderr, calls, db := run(t, "fw7\t10.0.0.77\tpaloalto_panos\tsvc-oxidized\tTOKENFW7\t2026-10-08T03:00:00Z\n", 0, "old\tdb\n")
	raw, _ := os.ReadFile(db)
	if code != 1 || string(raw) != "old\tdb\n" || len(calls) != 0 ||
		!strings.Contains(stderr, "no minted node has a name and a model this script can use") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// One node Oxidized refuses must not stop the nodes after it; the run says
// which and exits 75.
func TestARestFailureOnOneNodeStillQueuesTheRest(t *testing.T) {
	code, stderr, calls, _ := runCase(t, scenario{tsv: leafAndJunos, fail: map[string]bool{"PUT /node/next/leaf1": true}})
	if code != 75 || strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1,PUT /node/next/vjunos1" ||
		!strings.Contains(stderr, "leaf1: Oxidized refused the queue request") || strings.Contains(stderr, "TOKEN") {
		t.Fatalf("exit %d calls %v stderr %s", code, calls, stderr)
	}
}

// A failed reload: router.db was replaced, Oxidized was not told; say so and
// exit 75.
func TestAFailedReloadIsSaidAndExits75(t *testing.T) {
	code, stderr, calls, db := runCase(t, scenario{tsv: leafAndJunos, fail: map[string]bool{"GET /reload": true}})
	raw, _ := os.ReadFile(db)
	if code != 75 || !strings.HasPrefix(string(raw), "leaf1\t") || strings.Join(calls, ",") != "GET /reload" ||
		!strings.Contains(stderr, "router.db was replaced but Oxidized was not reloaded") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// Another run holds the lock: this one says so and changes nothing.
func TestAHeldLockStopsTheRun(t *testing.T) {
	code, stderr, calls, db := runCase(t, scenario{tsv: leafAndJunos, oldDB: "old\tdb\n", hold: true})
	raw, _ := os.ReadFile(db)
	if code != 75 || string(raw) != "old\tdb\n" || len(calls) != 0 ||
		!strings.Contains(stderr, "another run holds the lock") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// PORT49_SCOPE replaces the node list: port49 is asked for the scope's
// devices, and the nodes file is not read (decision 42 ruling 5).
func TestAScopeReplacesTheNodeList(t *testing.T) {
	code, stderr, calls, db := runCase(t, scenario{tsv: minted, exit: 0, scope: "backup_targets"})
	args, err := os.ReadFile(filepath.Join(filepath.Dir(db), "args"))
	if err != nil || !strings.Contains(string(args), "--scope\nbackup_targets\n") ||
		strings.Contains(string(args), "--devices-file") {
		t.Fatalf("exit %d args %q stderr %s", code, args, stderr)
	}
	if len(calls) == 0 || calls[0] != "GET /reload" {
		t.Fatalf("calls %v", calls)
	}
}

// Exit 1 on a scope sweep may be a sweep a final answer cut short: the nodes
// minted are queued, and the run says router.db may be short.
func TestAScopeSweepAtExit1SaysItMayBeShort(t *testing.T) {
	code, stderr, calls, _ := runCase(t, scenario{tsv: minted, exit: 1, scope: "backup_targets"})
	if code != 1 || len(calls) == 0 || calls[0] != "GET /reload" ||
		!strings.Contains(stderr, "port49 workload token exited 1 for scope backup_targets: the sweep may have stopped early") {
		t.Fatalf("exit %d calls %v stderr %s", code, calls, stderr)
	}
	code, stderr, _, _ = runCase(t, scenario{tsv: minted, exit: 1})
	if code != 1 || strings.Contains(stderr, "the sweep may have stopped early") {
		t.Fatalf("a node list: exit %d stderr %s", code, stderr)
	}
}

// router.db's directory is missing: files cannot be made beside it, which is
// temporary (75), not the 1 of "a node not permitted".
func TestAMissingRouterDBDirectoryExits75(t *testing.T) {
	code, stderr, calls, _ := runCase(t, scenario{tsv: leafAndJunos, noDir: true})
	if code != 75 || len(calls) != 0 || !strings.Contains(stderr, "cannot make files beside") {
		t.Fatalf("exit %d calls %v stderr %s", code, calls, stderr)
	}
}

// Ruling 9 (L90): Oxidized with secure: true refuses a host key not in known_hosts and sends no
// token (cell a); one OpenSSH's accept-new wrote it reads (cells c, c2). The wrapper writes that
// entry for each node absent from known_hosts, with a line that sends no credential and no
// signature, and never for a node already there and never with StrictHostKeyChecking=no.
func TestTheWrapperPrepopulatesUnknownNodes(t *testing.T) {
	res := &sshResult{}
	code, stderr, calls, _ := runCase(t, scenario{tsv: minted, oldDB: "", seed: []string{"10.0.0.11"}, res: res})
	khFile := res.khPath
	if code != 1 { // fw7 skipped
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if len(res.calls) != 1 {
		t.Fatalf("want one ssh call, for the one node absent from known_hosts: %v", res.calls)
	}
	// the measured line (lab L90 c), whole: the operator's ssh config is not read, the key is saved
	// at key exchange, and nothing that could send a credential or a signature is on
	want := []string{"-F", "/dev/null", "-o", "UserKnownHostsFile=" + khFile, "-o", "StrictHostKeyChecking=accept-new",
		"-o", "BatchMode=yes", "-o", "PreferredAuthentications=none", "-o", "PubkeyAuthentication=no",
		"-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=15", "--", "10.0.0.21", "exit"}
	if strings.Join(res.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("the line is not the measured one:\n got %v\nwant %v", res.calls[0], want)
	}
	if !strings.Contains(res.knownHosts, "10.0.0.21 ") {
		t.Errorf("known_hosts lacks the saved entry: %q", res.knownHosts)
	}
	if strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1,PUT /node/next/vjunos1" {
		t.Errorf("calls %v", calls)
	}
	if strings.Contains(stderr, "TOKEN") {
		t.Errorf("a token on stderr: %s", stderr)
	}
}

func TestTheWrapperLeavesAKnownNodeAlone(t *testing.T) {
	res := &sshResult{}
	code, stderr, _, _ := runCase(t, scenario{tsv: minted, seed: []string{"10.0.0.11", "10.0.0.21"}, res: res})
	if code != 1 || len(res.calls) != 0 {
		t.Fatalf("exit %d, ssh calls %v, stderr %s", code, res.calls, stderr)
	}
}

// An entry that was not saved means Oxidized will refuse the node: the run says so and exits 1.
func TestAnEntryThatWasNotSavedIsSaid(t *testing.T) {
	res := &sshResult{}
	code, stderr, calls, _ := runCase(t, scenario{tsv: minted[:strings.Index(minted, "vjunos1")], sshNoSave: true, res: res})
	if code != 1 || !strings.Contains(stderr, "leaf1: no host key for 10.0.0.11 was saved to ") ||
		!strings.Contains(stderr, "Oxidized will refuse the node") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" {
		t.Fatalf("the node is still queued: %v", calls)
	}
}

// nodes returns n minted eos lines, n01 at 10.1.0.1 and on.
func nodes(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		b.WriteString("n" + strconv.Itoa(i) + "\t10.1.0." + strconv.Itoa(i) + "\tarista_eos\tsvc-oxidized\tTOKEN" + strconv.Itoa(i) + "\t2026-10-08T03:00:00Z\n")
	}
	return b.String()
}

// The visits run in parallel, up to OXIDIZED_HOSTKEY_JOBS at once.
func TestTheHostKeyVisitsRunInParallelUpToTheCap(t *testing.T) {
	res := &sshResult{}
	code, stderr, _, _ := runCase(t, scenario{tsv: nodes(6), sshSleep: "0.4", jobs: 2, res: res})
	if code != 0 || len(res.calls) != 6 {
		t.Fatalf("exit %d, %d ssh calls, stderr %s", code, len(res.calls), stderr)
	}
	if res.maxConc != 2 {
		t.Fatalf("at most 2 at once and 2 reached, got %d", res.maxConc)
	}
}

// No visit starts after the budget; each node not reached is named, the run exits 1, and every
// node is still queued (its own backup fails at the host key, with no token sent).
func TestTheHostKeyBudgetStopsTheSweepAndNamesTheRest(t *testing.T) {
	res := &sshResult{}
	start := time.Now()
	code, stderr, calls, _ := runCase(t, scenario{tsv: nodes(6), sshSleep: "0.8", jobs: 1, budget: 1, res: res})
	if took := time.Since(start); took > 6*time.Second {
		t.Fatalf("the run took %s with a 1s budget", took)
	}
	if code != 1 || len(res.calls) == 0 || len(res.calls) >= 6 {
		t.Fatalf("exit %d, %d ssh calls (want some, not all), stderr %s", code, len(res.calls), stderr)
	}
	if !strings.Contains(stderr, "n6: not reached within the 1s host-key budget; no key saved, retried at the next window") {
		t.Fatalf("n6 is not named: %s", stderr)
	}
	if len(calls) != 7 { // reload, then six queue requests
		t.Fatalf("calls %v", calls)
	}
}

// The addresses come from the mint, so the sweep follows one; a run that visited a node mints again
// after it, so the tokens it queues did not age through the sweep. A run with nothing to visit mints once.
func TestTheMintFollowsTheSweep(t *testing.T) {
	res := &sshResult{}
	if code, stderr, _, _ := runCase(t, scenario{tsv: nodes(2), sshSleep: "0.1", res: res}); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if got := strings.Join(res.order, ","); got != "mint,ssh,ssh,mint" {
		t.Fatalf("order %s, want mint,ssh,ssh,mint", got)
	}
	res = &sshResult{}
	runCase(t, scenario{tsv: nodes(2), seed: []string{"10.1.0.1", "10.1.0.2"}, res: res})
	if got := strings.Join(res.order, ","); got != "mint" {
		t.Fatalf("order %s, want one mint and no ssh", got)
	}
}

// An address that is not an IP literal never reaches ssh (it could be taken for an option).
func TestAnAddressThatIsNotAnIPLiteralIsNeverVisited(t *testing.T) {
	res := &sshResult{}
	tsv := "n1\t-oProxyCommand=x\tarista_eos\tsvc-oxidized\tTOKEN1\t2026-10-08T03:00:00Z\n"
	code, stderr, _, _ := runCase(t, scenario{tsv: tsv, res: res})
	if code != 1 || len(res.calls) != 0 || !strings.Contains(stderr, "n1: the address is not an IP literal") {
		t.Fatalf("exit %d, ssh calls %v, stderr %s", code, res.calls, stderr)
	}
}

// A missing ssh is named, the run exits 2 and Oxidized is left as it was (no router.db, no reload).
func TestAMissingSSHLeavesOxidizedAlone(t *testing.T) {
	code, stderr, calls, db := runCase(t, scenario{tsv: nodes(2), sshBin: "/nonexistent/ssh"})
	if code != 2 || !strings.Contains(stderr, "/nonexistent/ssh is not installed: the host-key step needs it; nothing changed") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if _, err := os.Stat(db); err == nil || len(calls) != 0 {
		t.Fatalf("router.db written (%v) or Oxidized called: %v", err, calls)
	}
}

// A known_hosts directory that cannot be made is the cannot-make-files exit.
func TestAnUnmakeableKnownHostsDirectoryExits75(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stderr, calls, db := runCase(t, scenario{tsv: nodes(2), khPath: filepath.Join(file, "sub", "known_hosts")})
	if code != 75 || !strings.Contains(stderr, "cannot make the directory of") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if _, err := os.Stat(db); err == nil || len(calls) != 0 {
		t.Fatalf("router.db written (%v) or Oxidized called: %v", err, calls)
	}
}

// A scope that grew between the two mints: its new node is visited too, without a third mint.
func TestANodeFirstSeenInTheSecondMintIsVisited(t *testing.T) {
	res := &sshResult{}
	code, stderr, _, _ := runCase(t, scenario{tsv: nodes(2), tsv2: nodes(3), res: res})
	if code != 0 || len(res.calls) != 3 {
		t.Fatalf("exit %d, %d ssh calls, stderr %s", code, len(res.calls), stderr)
	}
	if got := strings.Join(res.order, ","); got != "mint,ssh,ssh,mint,ssh" {
		t.Fatalf("order %s", got)
	}
}
