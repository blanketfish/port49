//go:build lab

package lab

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
)

func TestRegionNetworkCommands(t *testing.T) {
	up := regionNetUp()
	joined := make([]string, len(up))
	for i, c := range up {
		joined[i] = strings.Join(c, " ")
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		"ip link add p49rbr0 type bridge",
		"ip addr add 10.149.0.1/24 dev p49rbr0",
		"ip netns add p49r3",
		"ip netns exec p49r2 ip addr add 10.149.0.12/24 dev p49r2n",
		"ip netns exec p49r1 tc qdisc add dev p49r1n root netem delay 20ms",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the network lacks %q", want)
		}
	}
	cut := regionCut(3, true)
	if len(cut) != 4 || strings.Join(cut[0], " ") != "ip netns exec p49r3 iptables -I OUTPUT -d 10.149.0.11 -j DROP" {
		t.Fatalf("%v", cut)
	}
	if heal := regionCut(3, false); strings.Join(heal[1], " ") != "ip netns exec p49r3 iptables -D INPUT -s 10.149.0.11 -j DROP" {
		t.Fatalf("%v", heal)
	}
}

func TestInNSRunsAsTheUserWithItsEnvironment(t *testing.T) {
	t.Setenv("USER", "labuser")
	got := strings.Join(inNS("p49r2", []string{"A=1"}, "/bin/etcd", "--name", "d2"), " ")
	if got != "sudo -n ip netns exec p49r2 sudo -n -u labuser -- env A=1 /bin/etcd --name d2" {
		t.Fatalf("%s", got)
	}
}

// The configs the harness writes load as port49d's and port49-broker's
// stores: two stores, the directory across the three regions; port49d's
// waits for the directory with no deadline (L74 f).
func TestRegionConfigsNameTwoStores(t *testing.T) {
	dir := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := &regionPKI{ca: file("ca.pem"), daemon: file("d.pem"), daemonKey: file("d-key.pem"), broker: file("b.pem"),
		brokerKey: file("b-key.pem")}
	for _, role := range []string{"daemon", "broker"} {
		body := regionStoresYAML(p, role, regionSessionClient)
		s, err := config.StoresBlocks([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v\n%s", role, err, body)
		}
		if s.Shared || len(s.Directory.Etcd.Endpoints) != 3 || s.Session.Etcd.Endpoints[0] != "https://127.0.0.1:2479" {
			t.Fatalf("%s: %+v", role, s)
		}
		if role == "daemon" && s.Directory.Etcd.StartTimeout != 0 {
			t.Fatalf("port49d's directory start_timeout is %v, want 0 (wait)", s.Directory.Etcd.StartTimeout)
		}
	}
}

func TestApplyRolesSplitsTheSections(t *testing.T) {
	out := "# port49 roles for the directory store (stores.directory): keyspace /port49/. Run these as THAT cluster's root user,\n" +
		"etcdctl role add port49_daemon\n" +
		"# then, if auth is not enabled yet: etcdctl user add root --no-password &&\n" +
		"#   etcdctl user grant-role root root && etcdctl auth enable\n\n" +
		"# port49 roles for the session store (stores.session): keyspace /port49/. Run these as THAT cluster's root user,\n" +
		"etcdctl role add port49_broker\n"
	ran := map[string][]string{}
	ctl := func(target string) func(...string) (string, error) {
		return func(args ...string) (string, error) {
			ran[target] = append(ran[target], strings.Join(args, " "))
			return "OK", nil
		}
	}
	applyRoles(t, out, map[string]func(...string) (string, error){"directory": ctl("directory"), "session": ctl("session")})
	if strings.Join(ran["directory"], "|") != "role add port49_daemon|user add root --no-password|user grant-role root root|auth enable" ||
		strings.Join(ran["session"], "|") != "role add port49_broker" {
		t.Fatalf("%v", ran)
	}
	ran = map[string][]string{}
	applyRoles(t, out, map[string]func(...string) (string, error){"session": ctl("session")})
	if len(ran["directory"]) != 0 || len(ran["session"]) != 1 {
		t.Fatalf("a section with no cluster ran: %v", ran)
	}
}

func TestStatusNames(t *testing.T) {
	if regionAuthenStatus(wire.AuthenStatusPass) != "pass" || regionAuthenStatus(wire.AuthenStatusFail) != "fail" ||
		regionAuthorStatus(wire.AuthorStatusPassAdd) != "permit" || regionAuthorStatus(wire.AuthorStatusFail) != "deny" {
		t.Fatal("status names")
	}
}

func TestRegionNoteShape(t *testing.T) {
	note := regionNote("L74", "port49 on the lab host, three simulated regions", "etcd 3.6.15", "commit abc",
		"spec §15 L74, cell by cell.", []regionRow{{ID: "a", Claim: "c", Observed: "o | p", Agrees: true}}, []string{"x"})
	for _, want := range []string{"# L74 — three simulated regions", "- **Platform:** port49 on the lab host, three simulated regions",
		"- **Capture:** tests/lab/evidence/L74-regions/", "| a | c | o \\| p | yes |", "**Not measured here:**", "- x"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the note lacks %q:\n%s", want, note)
		}
	}
}

// A member or process is started so its real PID is recorded: the wrapper
// writes $$ to the pidfile, sources the env file (when there is one) and execs
// the program, so the PID is the program's and the keys are never on argv.
func TestPidWrapRunsAndRecordsTheExecedPID(t *testing.T) {
	dir := t.TempDir()
	pidfile, envfile, out := filepath.Join(dir, "p.pid"), filepath.Join(dir, "run.env"), filepath.Join(dir, "out")
	if err := os.WriteFile(envfile, []byte("L74_ENC_KEY=abc123\nPORT49_KEY_L74=def456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := pidWrap(pidfile, envfile, []string{"sh", "-c", `printf '%s %s' "$L74_ENC_KEY" "$PORT49_KEY_L74" > "$0"; sleep 30`, out})
	cmd := exec.Command(a[0], a[1:]...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	var got []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if raw, err := os.ReadFile(out); err == nil && len(raw) > 0 {
			got = raw
			break
		}
	}
	if string(got) != "abc123 def456" {
		t.Fatal("the program did not see the env file's two variables")
	}
	raw, err := os.ReadFile(pidfile)
	if err != nil || strings.TrimSpace(string(raw)) != strconv.Itoa(cmd.Process.Pid) {
		t.Fatalf("the pidfile does not hold the exec'd process's PID %d (read err %v)", cmd.Process.Pid, err)
	}
	// With no env file, argv still runs.
	b := pidWrap(filepath.Join(dir, "q.pid"), "", []string{"true"})
	if err := exec.Command(b[0], b[1:]...).Run(); err != nil {
		t.Fatalf("no env file: %v", err)
	}
}

// The run's keys travel in a 0600 file in the run directory; the built argv
// holds the file's path and no key value (sudo logs argv, /proc shows it).
func TestRegionProcArgvHoldsNoKeyValue(t *testing.T) {
	dir := t.TempDir()
	enc, tac := "ENCKEYVALUE0123", "TACKEYVALUE0123"
	envfile, err := writeRegionEnv(dir, enc, tac)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(envfile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the env file is not a 0600 file: %v", err)
	}
	body, _ := os.ReadFile(envfile)
	if !strings.Contains(string(body), "L74_ENC_KEY="+shellQuote(enc)) || !strings.Contains(string(body), "PORT49_KEY_L74="+shellQuote(tac)) {
		t.Fatal("the env file lacks a key")
	}
	for _, ns := range []string{"p49r1", ""} {
		p := &regionProc{name: "x", ns: ns, bin: "/bin/port49d", cfg: filepath.Join(dir, "c.yaml"), envFile: envfile}
		argv := strings.Join(p.argv(), " ")
		if strings.Contains(argv, enc) {
			t.Errorf("ns %q: argv holds the encryption key", ns)
		}
		if strings.Contains(argv, tac) {
			t.Errorf("ns %q: argv holds the TACACS+ key", ns)
		}
		if !strings.Contains(argv, envfile) {
			t.Errorf("ns %q: argv does not name the env file", ns)
		}
	}
}

// Stopping: SIGTERM to the checked, recorded PID (no sudo: the program runs as
// this user), SIGKILL past the grace period, and every wait bounded.
func TestStopRecordedTermsThenKillsAndNeverHangs(t *testing.T) {
	defer func(g, b time.Duration) { stopGrace, stopBound = g, b }(stopGrace, stopBound)
	stopGrace, stopBound = 600*time.Millisecond, 600*time.Millisecond
	dir := t.TempDir()
	start := func(script string) (*exec.Cmd, chan struct{}, string) {
		pidfile := filepath.Join(dir, strconv.Itoa(time.Now().Nanosecond())+".pid")
		a := pidWrap(pidfile, "", []string{"sh", "-c", script, "x", "--config", pidfile})
		cmd := exec.Command(a[0], a[1:]...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if raw, err := os.ReadFile(pidfile); err == nil && len(raw) > 1 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond) // the trap is set before the loop
		return cmd, done, pidfile
	}
	ended := func(done chan struct{}) bool {
		select {
		case <-done:
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	}
	// A program that ends on SIGTERM is not killed: it exits at once.
	cmd, done, pidfile := start(`while :; do sleep 0.1; done`)
	t0 := time.Now()
	stopRecorded("t", done, pidfile, "--config", pidfile)
	if !ended(done) || time.Since(t0) > stopGrace {
		t.Fatalf("a TERM-able program was not ended by SIGTERM within the grace (took %v)", time.Since(t0))
	}
	_ = cmd
	// One that ignores SIGTERM is killed after the grace period.
	_, done, pidfile = start(`trap "" TERM; while :; do sleep 0.1; done`)
	stopRecorded("t", done, pidfile, "--config", pidfile)
	if !ended(done) {
		t.Fatal("a TERM-ignoring program was not killed after the grace period")
	}
	// A mismatch kills nothing and returns within the bound.
	cmd, done, pidfile = start(`while :; do sleep 0.1; done`)
	t0 = time.Now()
	stopRecorded("t", done, pidfile, "--config", "/no/such/config")
	if took := time.Since(t0); took > 3*stopBound {
		t.Fatalf("a declined stop waited %v", took)
	}
	select {
	case <-done:
		t.Fatal("a mismatching cmdline still ended the process")
	default:
	}
	_ = cmd.Process.Kill()
	<-done
}

func TestRegionNetDownRemovesTheHostVeths(t *testing.T) {
	var all []string
	for _, c := range regionNetDown() {
		all = append(all, strings.Join(c, " "))
	}
	got := strings.Join(all, "\n")
	for _, want := range []string{"ip netns del p49r2", "ip link del p49r1h", "ip link del p49r3h", "ip link del p49rbr0"} {
		if !strings.Contains(got, want) {
			t.Errorf("the teardown lacks %q", want)
		}
	}
}

// The forced stop signals a recorded PID only after /proc/<pid>/cmdline still
// holds the expected argument pair; a mismatch (a reused PID, a missing file)
// logs and skips. It never pattern-kills.
func TestKillRecordedChecksTheCmdline(t *testing.T) {
	proc, dir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(proc, "4242"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmdline := "/bin/etcd\x00--name\x00d1\x00--data-dir\x00/tmp/x/d1.etcd\x00"
	if err := os.WriteFile(filepath.Join(proc, "4242", "cmdline"), []byte(cmdline), 0o600); err != nil {
		t.Fatal(err)
	}
	pidfile := filepath.Join(dir, "d1.etcd.pid")
	if err := os.WriteFile(pidfile, []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var killed []int
	kill := func(pid int) error { killed = append(killed, pid); return nil }

	if why := killRecorded(proc, pidfile, []string{"--data-dir", "/tmp/x/d1.etcd"}, kill); why != "" || len(killed) != 1 || killed[0] != 4242 {
		t.Fatalf("a matching cmdline: why %q, killed %v", why, killed)
	}
	killed = nil
	// A different data directory is another process: skipped, with a reason.
	if why := killRecorded(proc, pidfile, []string{"--data-dir", "/tmp/x/d2.etcd"}, kill); why == "" || len(killed) != 0 {
		t.Fatalf("a mismatching cmdline: why %q, killed %v", why, killed)
	}
	// The pair must be adjacent, and a prefix of a value is not the value.
	if why := killRecorded(proc, pidfile, []string{"--data-dir", "/tmp/x/d1"}, kill); why == "" || len(killed) != 0 {
		t.Fatalf("a prefix: why %q, killed %v", why, killed)
	}
	// No pidfile, an unreadable PID, and a PID with no /proc entry are skipped.
	for name, body := range map[string]string{"absent": "", "junk": "not a pid\n", "gone": "9999\n"} {
		p := filepath.Join(dir, name+".pid")
		if body != "" {
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if why := killRecorded(proc, p, []string{"--data-dir", "/tmp/x/d1.etcd"}, kill); why == "" || len(killed) != 0 {
			t.Fatalf("%s: why %q, killed %v", name, why, killed)
		}
	}
}

// A value the env file holds is data to the shell that sources it: a dollar
// sign, a backtick, a quote or a semicolon is neither expanded nor run.
func TestRegionEnvValuesAreShellInert(t *testing.T) {
	dir := t.TempDir()
	enc, tac := "a$HOME`id`'b", "x;touch "+filepath.Join(dir, "ran")+";y"
	envfile, err := writeRegionEnv(dir, enc, tac)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	a := pidWrap(filepath.Join(dir, "p.pid"), envfile, []string{"sh", "-c", `printf '%s|%s' "$L74_ENC_KEY" "$PORT49_KEY_L74" > "$0"`, out})
	if err := exec.Command(a[0], a[1:]...).Run(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != enc+"|"+tac {
		t.Error("a key value did not reach the program as written")
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
		t.Error("a key value was run as a command")
	}
}

func TestDisagreeingCellsNamesTheRowsThatDisagree(t *testing.T) {
	rows := []regionRow{{ID: "a"}, {ID: "b", Agrees: true}, {ID: "c"}, {ID: "g", Agrees: true}, {ID: "i"}}
	if got := strings.Join(disagreeingCells(rows), ","); got != "a,c,i" {
		t.Fatalf("got %q", got)
	}
	if len(disagreeingCells(nil)) != 0 || len(disagreeingCells(rows[1:2])) != 0 {
		t.Fatal("agreeing rows were named")
	}
}

// The build runs in the repository root and the note and evidence are written
// under it, whatever directory the test binary runs in (go test runs it in
// tests/lab).
func TestRegionPathsResolveUnderTheRepoRoot(t *testing.T) {
	repo := t.TempDir()
	cmd := regionBuildCmd(repo, "/run/bin")
	if cmd.Dir != repo {
		t.Errorf("the build runs in %q, want the repo root", cmd.Dir)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"go build", "-o /run/bin/", "./cmd/port49d", "./cmd/port49-broker", "./cmd/port49"} {
		if !strings.Contains(args, want) {
			t.Errorf("the build lacks %q: %s", want, args)
		}
	}
	if got := regionNotePath(repo, "L74"); got != filepath.Join(repo, "tests", "lab", "results", "L74-regions.md") {
		t.Errorf("note path %q", got)
	}
	if got := regionEvidenceDir(repo, "L74"); got != filepath.Join(repo, "tests", "lab", "evidence", "L74-regions") {
		t.Errorf("evidence dir %q", got)
	}
	// Under the repo root's own checkout, repoRoot answers a directory with go.mod.
	r, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r, "go.mod")); err != nil {
		t.Errorf("repoRoot %q holds no go.mod", r)
	}
}

// L75's broker config loads as port49-broker's, in both identities: the
// password one for (a) to (f), the provider one for (g).
func TestL75BrokerConfigLoads(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("L74_ENC_KEY", labEncKeyDefault)
	t.Setenv("LAB_DIRECTORY_BIND_PASSWORD", "unit-test-bind-password")
	x := l67TestDir(t, platOpenLDAP)
	p := newRegionPKI(t)
	for _, files := range []string{"ca.pem", "users-ca.pem", "issuer-ca.pem"} {
		if err := os.WriteFile(filepath.Join(dir, files),
			[]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, provider := range []bool{false, true} {
		o := l75Opts{i: 2, dir: dir, x: x, pki: p, session: "127.0.0.1:2579", usersCA: filepath.Join(dir, "users-ca.pem"),
			issuer: "https://127.0.0.1:9", issuerCA: filepath.Join(dir, "issuer-ca.pem"), provider: provider}
		path := filepath.Join(dir, fmt.Sprintf("b2-%v.yaml", provider))
		if err := os.WriteFile(path, []byte(l75BrokerYAML(o)), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.LoadBroker(path)
		if err != nil {
			t.Fatalf("provider %v: %v\n%s", provider, err, l75BrokerYAML(o))
		}
		if cfg.Stores.Shared || cfg.Broker.Directory == nil {
			t.Fatalf("provider %v: a split with a directory, got shared %v", provider, cfg.Stores.Shared)
		}
		if got := cfg.Broker.Identity.PasswordSignIn != nil; got == provider {
			t.Fatalf("provider %v: password sign-in %v", provider, got)
		}
		// Provider mode has no issuer, so a person's ID token is a mint bearer
		// (decision 39), as row (g) states; the password mode needs one.
		if got := cfg.Broker.Identity.Issuance != nil; got == provider {
			t.Fatalf("provider %v: issuance %v", provider, got)
		}
	}
}

// A logout token names the provider, the client, the session and the
// back-channel event, as Keycloak's does (L45).
func TestL75LogoutTokenClaims(t *testing.T) {
	c := l75LogoutClaims("https://idp.example", "port49-cli", "s-1", "jti-1", time.Unix(1000, 0))
	if c["iss"] != "https://idp.example" || c["aud"] != "port49-cli" || c["sid"] != "s-1" || c["jti"] != "jti-1" {
		t.Fatalf("%v", c)
	}
	if _, ok := c["events"].(map[string]any)[oidc.BackchannelLogoutEvent]; !ok {
		t.Fatalf("no back-channel event: %v", c)
	}
}

// The config names the bind password and the keys by environment variable and
// holds none of them; through the proxies the directory endpoints are b3's own.
func TestL75BrokerYAMLHoldsNoSecret(t *testing.T) {
	x := l67TestDir(t, platOpenLDAP)
	o := l75Opts{i: 3, dir: t.TempDir(), x: x, pki: newRegionPKI(t), session: "127.0.0.1:2579", usersCA: "/u.pem",
		directory: []string{"127.0.0.1:7001", "127.0.0.1:7002", "127.0.0.1:7003"}}
	y := l75BrokerYAML(o)
	if strings.Contains(y, x.d.password) {
		t.Error("the config holds the directory bind password")
	}
	if !strings.Contains(y, "password_secret_ref: env:LAB_DIRECTORY_BIND_PASSWORD") || !strings.Contains(y, "secret_ref: env:L74_ENC_KEY") {
		t.Error("the config does not name the secrets by environment variable")
	}
	if !strings.Contains(y, "https://127.0.0.1:7002") || strings.Contains(y, regionIP(1)+":2379") {
		t.Error("b3's directory endpoints are not the proxies'")
	}
}

// The env file takes any pairs, quoted, in a 0600 file; the L75 file holds the
// bind password the config names.
func TestWriteEnvFileQuotesAndRestricts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.env")
	if err := writeEnvFile(path, [2]string{"A", "it's $x"}, [2]string{"B", "plain"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("not a 0600 file: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "A='it'\\''s $x'\nB='plain'\n" {
		t.Fatal("the env file is not the quoted pairs")
	}
}

// No cell passes for want of its positive control: each judge refuses a
// control that failed, whatever the negative reads.
func TestL75JudgesRequireTheirControls(t *testing.T) {
	ok, bad := 200, 500
	// (a) the replay at b2 is refused, and b2 accepts a fresh code.
	if !l75JudgeA(ok, 401, ok) || l75JudgeA(bad, 401, ok) || l75JudgeA(ok, 401, bad) || l75JudgeA(ok, ok, ok) {
		t.Error("judge a")
	}
	// (c) locked for real (a valid code refused with 429 before the unlock), unlocked, judged afresh.
	if !l75JudgeC(3, 429, 0, ok) || l75JudgeC(-1, 429, 0, ok) || l75JudgeC(3, ok, 0, ok) || l75JudgeC(3, 429, 1, ok) || l75JudgeC(3, 429, 0, 429) {
		t.Error("judge c")
	}
	// (d) with no unlock between, each broker takes its own count: the
	// threshold's failures, then the refusal. A shared count (n = 1 at the
	// second and third), a broker that never locked (-1 or 0), and counts
	// that differ are each a no.
	if !l75JudgeD([]int{6, 6, 6}, 5) || l75JudgeD([]int{6, 1, 1}, 5) || l75JudgeD([]int{6, -1, 6}, 5) ||
		l75JudgeD([]int{6, 0, 6}, 5) || l75JudgeD([]int{6, 5, 6}, 5) || l75JudgeD([]int{3, 3, 3}, 5) || l75JudgeD(nil, 5) {
		t.Error("judge d")
	}
	// (e) the cut took (store status exit 3), the sign-in answered 503
	// store_unavailable, unlock and reset were refused with the store's own
	// words, and the heal took.
	did := "broker: resetting x failed: the store did not answer, so nothing changed: run it again"
	if !l75JudgeE(3, 503, "store_unavailable", 1, did, 1, did, true) ||
		l75JudgeE(0, 503, "store_unavailable", 1, did, 1, did, true) ||
		l75JudgeE(3, 503, "other", 1, did, 1, did, true) ||
		l75JudgeE(3, 503, "store_unavailable", 0, did, 1, did, true) ||
		l75JudgeE(3, 503, "store_unavailable", 1, did, 0, did, true) ||
		l75JudgeE(3, 503, "store_unavailable", 1, "no such socket", 1, did, true) ||
		l75JudgeE(3, 503, "store_unavailable", 1, did, 1, "bad flag", true) ||
		l75JudgeE(3, 503, "store_unavailable", 1, did, 1, did, false) {
		t.Error("judge e")
	}
	// (g) mint before, logout accepted, the runner line seen, then credential_revoked.
	if !l75JudgeG(ok, ok, "credential_revoked", true) || l75JudgeG(bad, ok, "credential_revoked", true) ||
		l75JudgeG(ok, ok, "not refused", true) || l75JudgeG(ok, ok, "credential_revoked", false) {
		t.Error("judge g")
	}
}

// (b) counts a pair only when the two sign-ins really raced one code: one won
// and the other was refused for the code. A locked-out broker's 429 is no race.
func TestL75RacedPair(t *testing.T) {
	for _, tc := range []struct {
		a, b int
		want bool
	}{{200, 401, true}, {401, 200, true}, {200, 429, false}, {429, 200, false}, {401, 401, false}, {200, 200, false}, {429, 429, false}} {
		if l75RacedPair(tc.a, tc.b) != tc.want {
			t.Errorf("pair %d/%d", tc.a, tc.b)
		}
	}
}

// Two requests are one race only when both leave inside one TOTP step.
func TestL75SameStep(t *testing.T) {
	base := time.Unix(30*1000, 0)
	if !l75SameStep(base, base.Add(29*time.Second)) || l75SameStep(base, base.Add(30*time.Second)) ||
		l75SameStep(base.Add(-time.Second), base) {
		t.Error("same step")
	}
}

// etcdctl v3.6.15 refuses --count-only with -w json, and the harness read
// that refusal as a count of 0 (the first run of L74, INVALID at the snapshot
// wait). The fixture is `get --prefix --keys-only -w json`'s shape, with fake
// keys and no values.
func TestEtcdCountReadsKeysOnlyJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "etcd-get-keys-only.json"))
	if err != nil {
		t.Fatal(err)
	}
	if n := etcdCount(string(raw)); n != 2 {
		t.Fatalf("etcdCount = %d, want 2", n)
	}
	if n := etcdCount("Error: --count-only is only for `--write-out=fields`"); n != 0 {
		t.Fatalf("etcdCount of an error text = %d, want 0", n)
	}
}

func TestSnapshotCountArgsAreAcceptedWithJSON(t *testing.T) {
	args := strings.Join(snapshotCountArgs(), " ")
	if strings.Contains(args, "--count-only") {
		t.Fatalf("%q: etcdctl refuses --count-only with -w json", args)
	}
	for _, want := range []string{"--keys-only", "-w json", "--prefix /port49/v1/ds/m/"} {
		if !strings.Contains(args, want) {
			t.Errorf("%q lacks %q", args, want)
		}
	}
}

// The broker loads l75's policy with the directory on, which refuses a human
// subject's username (decision 38); the first full run found that in the lab.
func TestL75PolicyLoadsWithTheDirectoryOn(t *testing.T) {
	if _, err := policy.Parse([]byte(l75Policy()), policy.Env{Directory: policy.DirectoryOn}); err != nil {
		t.Fatal(err)
	}
}

// Cell (i) lifts only once broker 3's marks feed has stopped; without the
// line it is INVALID, not a measurement of a lift that arrived as an event.
func TestL74FeedStoppedWaitsForTheLine(t *testing.T) {
	log := filepath.Join(t.TempDir(), "b3.log")
	p := &regionProc{name: "port49-broker r3", log: log}
	if err := os.WriteFile(log, []byte("port49-broker: directory store: not answering\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := feedStopped(p, 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "did not stop the marks feed") ||
		!strings.Contains(err.Error(), "a port49 finding if the cut held") {
		t.Fatalf("a log without the line: %v, want the INVALID error", err)
	}
	p.mark()
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString("port49-broker: directory store: the marks feed stopped (store: unavailable)\n")
	if err := feedStopped(p, 300*time.Millisecond); err != nil {
		t.Fatalf("a log with the line after the mark: %v", err)
	}
}

// A broker's addresses are read once at its start; a later mark empties
// what said() returns, and must not empty the address (L75 (f), (g)).
func TestL75AddrsComeFromTheStartNotTheMarkedLog(t *testing.T) {
	log := "port49-broker: metrics on 127.0.0.1:41000\nport49-broker: listening on 127.0.0.1:42000\n"
	api, metrics := l75Addrs(log)
	if api != "127.0.0.1:42000" || metrics != "127.0.0.1:41000" {
		t.Fatalf("l75Addrs = %q, %q", api, metrics)
	}
	if api, metrics := l75Addrs("port49-broker: listening on 127.0.0.1:42001, metrics on 127.0.0.1:41001\n"); api != "127.0.0.1:42001" || metrics != "127.0.0.1:41001" {
		t.Fatalf("the combined line: %q, %q", api, metrics)
	}
	if api, _ := l75Addrs(""); api != "" {
		t.Fatalf("an empty log named %q", api)
	}
	lf := filepath.Join(t.TempDir(), "b.log")
	if err := os.WriteFile(lf, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &l75Broker{proc: &regionProc{log: lf}}
	b.api, b.metrics = l75Addrs(b.proc.said())
	b.proc.mark()
	if b.proc.said() != "" || b.addr() != "127.0.0.1:42000" {
		t.Fatalf("after a mark: said %q, addr %q", b.proc.said(), b.addr())
	}
}

func l75MetricsServer(t *testing.T, value func() string) *l75Broker {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "port49_directory_enrollment_store_ok %s\n", value())
	}))
	t.Cleanup(srv.Close)
	return &l75Broker{proc: &regionProc{name: "port49-broker l75 bX"}, metrics: strings.TrimPrefix(srv.URL, "http://")}
}

// (a) runs only after the brokers that started before init-enrollments read
// the store as ok; a broker that never does is INVALID, not a "no" for (a).
func TestL75EnrollmentStoreSeenWaitsAndGivesUp(t *testing.T) {
	var n atomic.Int32
	late := l75MetricsServer(t, func() string {
		if n.Add(1) < 3 {
			return "0"
		}
		return "1"
	})
	if _, err := l75EnrollmentStoreSeen([]*l75Broker{late}, 10*time.Second); err != nil {
		t.Fatalf("a broker that reads 1 on its third scrape: %v", err)
	}
	if n.Load() < 3 {
		t.Fatalf("it did not wait for the metric: %d scrape(s)", n.Load())
	}
	never := l75MetricsServer(t, func() string { return "0" })
	if _, err := l75EnrollmentStoreSeen([]*l75Broker{never}, 1500*time.Millisecond); err == nil ||
		!strings.Contains(err.Error(), "did not read port49_directory_enrollment_store_ok 1") ||
		!strings.Contains(err.Error(), "a port49 finding if the store was initialised") {
		t.Fatalf("a broker that never reads 1: %v, want the INVALID error", err)
	}
}

// l75Poll reports the last read and whether it was accepted.
func TestL75PollReturnsTheLastReadAtTheLimit(t *testing.T) {
	reads := 0
	got, _, ok := l75Poll(func() string { reads++; return fmt.Sprint("read ", reads) },
		func(s string) bool { return s == "never" }, 300*time.Millisecond, 100*time.Millisecond)
	if ok || got != fmt.Sprint("read ", reads) || reads < 2 {
		t.Fatalf("got %q ok %v after %d reads", got, ok, reads)
	}
}

// The pending count matches exactly: 11 is not 1.
func TestL75OnePendingIsExact(t *testing.T) {
	for status, want := range map[string]bool{
		"directory  etcd  1 logouts pending": true,
		"1 logouts pending":                  true,
		"11 logouts pending":                 false,
		"21 logouts pending":                 false,
		"0 logouts pending":                  false,
	} {
		if got := l75OnePending(status); got != want {
			t.Errorf("l75OnePending(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestL74MarkRevisionOfReadsTheKeysModRevision(t *testing.T) {
	js := `{"kvs":[{"key":"` + base64.StdEncoding.EncodeToString([]byte("/port49/v1/rv/p/user:bob@example.com")) +
		`","mod_revision":7},{"key":"` + base64.StdEncoding.EncodeToString([]byte("/port49/v1/rv/p/user:alice@example.com")) +
		`","mod_revision":9}]}`
	if got := markRevisionOf(js, "alice@example.com"); got != 9 {
		t.Fatalf("alice's mark revision = %d, want 9", got)
	}
	if markRevisionOf(js, "carol") != 0 || markRevisionOf("not json", "alice") != 0 {
		t.Fatal("an absent key or unreadable answer must read 0")
	}
}

// Compacting at the lift's own revision keeps its event: the cell is INVALID
// unless the compaction is above the revocation plus the lift.
func TestL74CompactedPastTheLift(t *testing.T) {
	if err := compactedPastTheLift(11, 13); err != nil {
		t.Fatalf("revoked 11, compacted 13 (a write after the lift): %v", err)
	}
	if compactedPastTheLift(11, 12) == nil {
		t.Fatal("compacting at the lift's own revision was accepted")
	}
	if compactedPastTheLift(0, 20) == nil {
		t.Fatal("an unread revocation revision was accepted")
	}
}

func TestL74LabeledMetricReadsTheMarksFeed(t *testing.T) {
	text := "port49_store_feed_rescans_total{feed=\"contexts\"} 4\nport49_store_feed_rescans_total{feed=\"marks\"} 2\n"
	if got := labeledMetric(text, "port49_store_feed_rescans_total", `feed="marks"`); got != 2 {
		t.Fatalf("marks rescans = %v, want 2", got)
	}
	if got := labeledMetric(text, "port49_store_feed_rescans_total", `feed="pins"`); got != -1 {
		t.Fatalf("an absent series = %v, want -1", got)
	}
}

// Cell (i) needs the marks feed to rescan after the heal: the counter rising
// is the evidence, since the feed does not say a compaction while it is failing.
func TestL74FeedRescannedWaitsForTheCounterToRise(t *testing.T) {
	n := 0
	rising := func() string {
		n++
		v := 2
		if n >= 3 {
			v = 3
		}
		return fmt.Sprintf("port49_store_feed_rescans_total{feed=\"marks\"} %d\n", v)
	}
	after, err := feedRescanned(rising, 2, 10*time.Second, 10*time.Millisecond)
	if err != nil || after != 3 {
		t.Fatalf("a counter that rises on the third scrape: %v, %v", after, err)
	}
	flat := func() string { return "port49_store_feed_rescans_total{feed=\"marks\"} 2\n" }
	if _, err := feedRescanned(flat, 2, 200*time.Millisecond, 20*time.Millisecond); err == nil ||
		!strings.Contains(err.Error(), "a port49 finding") || !strings.Contains(err.Error(), "did not increase") {
		t.Fatalf("a counter that never rises: %v, want the INVALID error", err)
	}
}

func TestL75AnsweringAgainWaitsForTheLine(t *testing.T) {
	log := filepath.Join(t.TempDir(), "b3.log")
	p := &regionProc{name: "port49-broker l75 b3", log: log}
	if err := os.WriteFile(log, []byte("port49-broker: directory store: not answering\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l75AnsweringAgain(p, 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "a port49 finding") {
		t.Fatalf("a log without the line: %v, want the INVALID error", err)
	}
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString("port49-broker: directory store: answering again; the cache was 2.0s old\n")
	if err := l75AnsweringAgain(p, 300*time.Millisecond); err != nil {
		t.Fatalf("a log with the line: %v", err)
	}
}

func appendLog(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(text)
}

// (g) runs after each restarted broker's takeover: the keyspace held, then
// the bundle recorded as judged; either missing is INVALID.
func TestL75TookOverNeedsBothLines(t *testing.T) {
	log := filepath.Join(t.TempDir(), "b2.log")
	p := &regionProc{name: "port49-broker l75 b2", log: log}
	appendLog(t, log, "port49-broker: runner: took keyspace /port49/ (\"x\")\n")
	appendLog(t, log, "port49-broker: runner: not recording bundle sha256:ab as judged: the store did not answer\n")
	if err := l75TookOver(p, 400*time.Millisecond); err == nil || !strings.Contains(err.Error(), "a port49 finding if the keyspace was free") {
		t.Fatalf("the keyspace held but no judged line: %v, want the INVALID error", err)
	}
	appendLog(t, log, "port49-broker: runner: recorded bundle sha256:ab as judged (the takeover's carry left nothing owed)\n")
	if err := l75TookOver(p, 400*time.Millisecond); err != nil {
		t.Fatalf("both lines said: %v", err)
	}
	q := &regionProc{name: "port49-broker l75 b3", log: filepath.Join(t.TempDir(), "none.log")}
	if l75TookOver(q, 300*time.Millisecond) == nil {
		t.Fatal("a broker that said nothing was taken as having taken over")
	}
}

// (g) accepts the follow path's line only, once the takeover has finished:
// the takeover's "standing logout(s) reached here" means the logout was not
// followed.
func TestL75RunnerLineAcceptsOnlyTheFollowPath(t *testing.T) {
	dir := t.TempDir()
	follow := &regionProc{name: "b2", log: filepath.Join(dir, "f.log")}
	appendLog(t, follow.log, "port49-broker: runner: a logout made elsewhere reached 1 session(s)\n")
	if _, via, err := l75RunnerLine(follow, 300*time.Millisecond); err != nil || !strings.HasPrefix(via, "followed") {
		t.Fatalf("follow path: %q %v", via, err)
	}
	take := &regionProc{name: "b2", log: filepath.Join(dir, "t.log")}
	appendLog(t, take.log, "port49-broker: runner: 1 standing logout(s) reached here: 2 token key(s)\n")
	if _, _, err := l75RunnerLine(take, 300*time.Millisecond); err == nil {
		t.Fatal("the takeover's line was accepted as the follow path")
	}
}

// Cell (i) reads broker 3's rescan counter, not port49d's: each has its own
// marks feed, so port49d's rising proves nothing of the put-back. The address
// the harness scrapes must be the one brokerYAML makes the broker listen on.
func TestL74BrokerMetricsAreTheBrokersPort(t *testing.T) {
	dir := t.TempDir()
	w := &regionWorld{dir: dir, pki: newRegionPKI(t)}
	if !strings.Contains(w.brokerYAML(3), `metrics_listen: "`+regionBrokerMetrics(3)+`"`) {
		t.Fatalf("broker 3 does not listen for metrics on %s", regionBrokerMetrics(3))
	}
	if !strings.Contains(w.daemonYAML(3), `metrics_listen: "`+regionDaemonMetrics(3)+`"`) {
		t.Fatalf("port49d 3 does not listen for metrics on %s", regionDaemonMetrics(3))
	}
	if regionBrokerMetrics(3) == regionDaemonMetrics(3) {
		t.Fatal("the broker's and port49d's metrics share an address")
	}
}

// The region broker's config is one the real loader accepts with the on-call's
// touch roots in it: the x509 anchor moves to broker.identity.humans beside
// per_login_mfa, and the policy's oncall subject holds the rights the API
// guards.
func TestL74BrokerConfigNamesTheTouchRoots(t *testing.T) {
	t.Setenv("L74_ENC_KEY", labEncKeyDefault)
	dir := t.TempDir()
	w := &regionWorld{dir: dir, pki: newRegionPKI(t)}
	p := filepath.Join(dir, "r1-port49-broker.yaml")
	if err := os.WriteFile(p, []byte(w.brokerYAML(1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBroker(p)
	if err != nil {
		t.Fatalf("the region broker's config does not load: %v\n%s", err, w.brokerYAML(1))
	}
	want := filepath.Join(dir, adminRolesFile)
	if m := cfg.Broker.Identity.PerLoginMFA; m == nil || m.AttestationRootsFile != want {
		t.Fatalf("per_login_mfa is %+v, want the roots at %s", m, want)
	}
	if cfg.Broker.ClientCAFile != filepath.Join(w.pki.lab, testpki.LabCA) {
		t.Fatalf("the x509 anchor is %q", cfg.Broker.ClientCAFile)
	}
	if !strings.Contains(regionPolicy(), "api: [revoke_others, lift_revocations]") {
		t.Fatal("the region policy gives the on-call no api rights")
	}
}

// A region log goes into the evidence with its token and credential hashes
// redacted, the array form a mint record writes included.
func TestL74RegionEvidenceLogRedactsTheHashes(t *testing.T) {
	h := strings.Repeat("ab12", 16)
	raw := `{"credential_sha256":"` + h + `","x":1}` + "\n" +
		`{"event":"mint","token_sha256":["` + h + `","` + h + `"]}` + "\n" +
		`{"token_sha256":"` + h + `"}` + "\n" +
		`{"bundle_sha256":"` + h + `"}` + "\n" +
		"secret line\n"
	got := regionEvidenceLog(raw, func(l string) bool { return strings.HasPrefix(l, "secret") })
	if strings.Count(got, h) != 1 || !strings.Contains(got, `"bundle_sha256":"`+h+`"`) {
		t.Fatalf("only the bundle hash may survive:\n%s", got)
	}
	if strings.Contains(got, "secret line") || strings.Count(got, `"<redacted sha256>`) < 3 {
		t.Fatalf("leaky line kept or field lost:\n%s", got)
	}
}

// L79 is its own row on L74's harness: its cells heal at 20 s, inside TCP's
// retransmission window (about 15 minutes at tcp_retries2=15), through regionCut.
func TestL79CellsAreTheirOwnRow(t *testing.T) {
	for _, c := range l79Cells {
		if c.Row != "L79" || c.Heal != 20*time.Second || c.Cut != "iptables" {
			t.Fatalf("%+v: L79's cells heal at 20s inside TCP's retransmission window, through regionCut", c)
		}
	}
	if len(l79Cells) != 2 || l79Cells[0].ID != "j" || l79Cells[1].ID != "k" {
		t.Fatal("cells j and k")
	}
	// The cut is iptables DROP, never REJECT, so the kernel keeps retransmitting.
	for _, c := range regionCut(3, true) {
		if !strings.Contains(strings.Join(c, " "), "-j DROP") {
			t.Fatalf("%v: the cut must DROP", c)
		}
	}
}

// A late lift is a lift that lands after the CLI said it could not; a mark that
// is back is the runner's or a late revoke's, and either way it is there.
func TestL79MarkStates(t *testing.T) {
	keys := "/port49/v1/rv/user:alice@example.com\n"
	if l79MarkIn(keys, "alice@example.com") != true || l79MarkIn("", "alice@example.com") {
		t.Fatal("a mark is in the directory when its key is listed")
	}
	if got := l79Timeline(true, []bool{true, true, false, false}, time.Second); !strings.Contains(got, "gone after 2s") {
		t.Fatalf("a deleted mark: %q", got)
	}
	if got := l79Timeline(true, []bool{true, true}, time.Second); !strings.Contains(got, "still there") {
		t.Fatalf("a standing mark: %q", got)
	}
	if got := l79Timeline(false, []bool{false, true}, time.Second); !strings.Contains(got, "back after 1s") {
		t.Fatalf("a mark that reappeared: %q", got)
	}
	if got := l79Timeline(false, []bool{false, false}, time.Second); !strings.Contains(got, "never came back") {
		t.Fatalf("a mark that stayed lifted: %q", got)
	}
}

// Cell k agrees only when the mark came back after a failed revoke and
// every line an operator needs was said: the revoke's "may not have been
// recorded", broker 3's own-write clause, region 1's before-the-lift line,
// and the flag in region 1's revoke --list (post-11b, I8).
func TestL79CellKNeedsEveryLandedLine(t *testing.T) {
	cli := "port49 revoke: broker: " + l79Unrecorded + " when the directory answers again"
	b3 := "port49-broker: broker: a revocation of user:alice@example.com made at T0 before the lift at T1 landed after " +
		"it: a copy sent while its writer was cut off; it stands everywhere; " + l79Own
	b1 := "port49-broker: broker: a revocation of user:alice@example.com made at T0 before the lift at T1 landed after " +
		"it: a copy sent while its writer was cut off; it stands everywhere"
	list := "principal user:alice@example.com since T0 (offline uid 0); landed after the lift at T1 (revision 8)"
	if !l79KAgrees(1, true, cli, b3, b1, list) {
		t.Fatal("every line said, and the mark back: cell k agrees")
	}
	after := "port49-broker: broker: a revocation of user:alice@example.com made at T2 (offline uid 0) after the " +
		"lift at T1, by a writer whose marks feed had not yet shown the lift; it stands everywhere"
	for name, c := range map[string][]any{
		"revoke exited 0":         {0, true, cli, b3, b1, list},
		"mark never back":         {1, false, cli, b3, b1, list},
		"old CLI text":            {1, true, "port49 revoke: broker: the revocation could not be recorded", b3, b1, list},
		"broker 3 says elsewhere": {1, true, cli, "a revocation of user:alice@example.com made elsewhere reached", b1, list},
		"region 1 silent":         {1, true, cli, b3, "", list},
		"region 1 after form":     {1, true, cli, b3, after, list},
		"list unflagged":          {1, true, cli, b3, b1, "principal user:alice@example.com since T0 (offline uid 0)"},
	} {
		if l79KAgrees(c[0].(int), c[1].(bool), c[2].(string), c[3].(string), c[4].(string), c[5].(string)) {
			t.Errorf("%s: cell k agreed", name)
		}
	}
}

// PORT49_LAB_REGIONS_ONLY names the one row a run covers; empty covers every row.
func TestRegionRowWantedFollowsTheOnlySelector(t *testing.T) {
	if !regionRowWanted("", "L74") || !regionRowWanted("", "L79") {
		t.Fatal("with no selector every row runs")
	}
	if regionRowWanted("L79", "L74") || regionRowWanted("L79", "L75") || !regionRowWanted("L79", "L79") {
		t.Fatal("a selector runs its own row alone")
	}
}

// Cell (i)'s agreement needs every broker to say the put-back form for
// alice's mark, and none the cut-off form (task 2 review I1).
func TestL74CellINeedsThePutBackFormOnEveryBroker(t *testing.T) {
	put := "port49-broker: broker: a revocation of user:alice@example.com made at T0 was put back after the lift at " +
		"T1 by a port49-broker runner from its broker.state_dir/marks.json: its watch had not delivered the lift"
	cut := "port49-broker: broker: a revocation of user:alice@example.com made at T0 before the lift at T1 landed " +
		"after it: a copy sent while its writer was cut off; it stands everywhere"
	every := [3]string{put, put, put}
	if !l74IAgrees(true, 1, every) {
		t.Fatal("put back, one mark, every broker said the put-back form: cell (i) agrees")
	}
	for name, c := range map[string]struct {
		putBack bool
		n       int
		said    [3]string
	}{
		"no put-back line":   {false, 1, every},
		"no mark":            {true, 0, every},
		"broker 1 silent":    {true, 1, [3]string{"", put, put}},
		"broker 2 cut form":  {true, 1, [3]string{put, cut, put}},
		"cut form alongside": {true, 1, [3]string{put + "\n" + cut, put, put}},
		"another key's line": {true, 1, [3]string{strings.ReplaceAll(put, "alice", "bob"), put, put}},
	} {
		if l74IAgrees(c.putBack, c.n, c.said) {
			t.Errorf("%s: cell (i) agreed", name)
		}
	}
}

// Cell k's region 1 line must be one line naming alice that holds both
// fragments, never two lines or two keys (task 2 review M4).
func TestL79CellKNeedsOneLineNamingAlice(t *testing.T) {
	cli := "port49 revoke: broker: " + l79Unrecorded + " when the directory answers again"
	b3 := "port49-broker: broker: a revocation of user:alice@example.com made at T0 before the lift at T1 landed after " +
		"it: a copy sent while its writer was cut off; it stands everywhere; " + l79Own
	list := "principal user:alice@example.com since T0 (offline uid 0); landed after the lift at T1 (revision 8)"
	split := "port49-broker: broker: a revocation of user:bob@example.com made at T0 before the lift at T1 landed\n" +
		"port49-broker: broker: a revocation of user:alice@example.com made at T2 (x) after the lift at T1: a copy " +
		"sent " + l79Before
	if l79KAgrees(1, true, cli, b3, split, list) {
		t.Fatal("two lines' fragments satisfied region 1's line")
	}
	if l79KAgrees(1, true, cli, "a revocation of user:bob@example.com "+l79Own, b3, list) {
		t.Fatal("another key's own line satisfied broker 3's")
	}
}

// Broker 3 is held away from etcd across the heal and always let back: on the
// happy path, when the heal fails, when etcd-3 never applies the compaction,
// and when the hold itself failed (it may have added some rules).
func TestL74FreezeAcrossRestoresOnEveryPath(t *testing.T) {
	cases := []struct {
		name        string
		holdErr     error
		healErr     error
		compacted   func() bool
		wantErr     string
		wantRelease int
		wantHeal    int
	}{
		{"applies at once", nil, nil, func() bool { return true }, "", 1, 1},
		{"heal fails", nil, errors.New("boom"), func() bool { return true }, "the heal", 1, 1},
		{"never compacted", nil, nil, func() bool { return false }, "had not applied the compaction", 1, 1},
		{"hold fails", errors.New("no iptables"), nil, func() bool { return true }, "holding broker 3", 1, 0},
	}
	for _, c := range cases {
		releases, heals := 0, 0
		err := freezeAcross(
			func() error { return c.holdErr },
			func() error { releases++; return nil },
			func() error { heals++; return c.healErr },
			c.compacted, 100*time.Millisecond, 10*time.Millisecond)
		if (c.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
		}
		if releases != c.wantRelease || heals != c.wantHeal {
			t.Errorf("%s: restored %d times, healed %d; want %d, %d", c.name, releases, heals, c.wantRelease, c.wantHeal)
		}
	}
}

// A restore that fails is reported, also when the cell had already failed, and
// a poll that never succeeds stops at the cap rather than waiting on.
func TestL74FreezeAcrossReportsAFailedRestoreAndStopsAtTheCap(t *testing.T) {
	ok := func() error { return nil }
	badRestore := func() error { return errors.New("iptables: no such rule") }
	err := freezeAcross(ok, badRestore, ok, func() bool { return true }, time.Second, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "restoring broker 3") {
		t.Fatalf("a failed restore after a good cell: %v", err)
	}
	err = freezeAcross(ok, badRestore, func() error { return errors.New("boom") },
		func() bool { return true }, time.Second, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "the heal") || !strings.Contains(err.Error(), "restoring broker 3") {
		t.Fatalf("a failed restore after a failed cell must report both: %v", err)
	}
	start := time.Now()
	freezeAcross(ok, ok, ok, func() bool { return false }, 150*time.Millisecond, 10*time.Millisecond)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the poll ran %v past a 150ms cap", took)
	}
}

// The hold drops region 3's own clients' traffic to each directory member's
// client port, and the release deletes the same rules; peers (2380) and the
// host's reads of etcd-3 (INPUT) are untouched.
func TestRegionHoldDropsOnlyTheClientPortOutput(t *testing.T) {
	add, del := regionHold(3, true), regionHold(3, false)
	if len(add) != 3 || len(del) != 3 {
		t.Fatalf("rules: %d add, %d delete, want 3 each", len(add), len(del))
	}
	for j := range add {
		a, d := strings.Join(add[j], " "), strings.Join(del[j], " ")
		want := "ip netns exec p49r3 iptables -I OUTPUT -p tcp -d " + regionIP(j+1) + " --dport 2379 -j DROP"
		if a != want || d != strings.Replace(want, "-I", "-D", 1) {
			t.Errorf("rule %d: add %q, delete %q", j+1, a, d)
		}
	}
}

// The compaction probe must not run in the held namespace: etcdctl there
// dials regionIP(3):2379 from inside p49r3, which regionHold drops, so the
// probe could never see the compaction and the cell would always fail.
func TestL74CompactedProbeRunsOnTheHostNotInTheHeldNamespace(t *testing.T) {
	e := &regionEtcd{ns: regionNS(3), bin: "/opt/etcd", pki: &regionPKI{ca: "ca.pem", root: "root.pem", rootKey: "root-key.pem"}}
	argv := strings.Join(e.hostArgv("https://"+regionIP(3)+":2379", "get", "/l74/after-lift", "--rev", "41"), " ")
	for _, held := range []string{"netns", regionNS(3), "sudo"} {
		if strings.Contains(argv, held) {
			t.Errorf("the probe %q runs in or through %q", argv, held)
		}
	}
	if !strings.Contains(argv, "--endpoints https://"+regionIP(3)+":2379") || !strings.Contains(argv, "--rev 41") {
		t.Errorf("the probe %q lost its endpoint or revision", argv)
	}
	// The member's own ctl still runs in its namespace.
	if in := strings.Join(e.argvIn(e.ns, "x"), " "); !strings.Contains(in, "netns exec "+regionNS(3)) {
		t.Errorf("ctl no longer runs in the member's namespace: %q", in)
	}
}

// The release attempts every delete and joins the failures: a transient
// failure on the first rule must not leave the other two in place.
func TestRunAllAttemptsEveryCommandAndJoinsTheErrors(t *testing.T) {
	cmds := regionHold(3, false)
	var tried []string
	err := runAll(cmds, func(c []string) error {
		tried = append(tried, strings.Join(c, " "))
		switch len(tried) {
		case 2:
			return errors.New("rule 2 busy")
		case 3:
			return errors.New("rule 3 gone")
		}
		return nil
	})
	if len(tried) != 3 {
		t.Fatalf("attempted %d of 3 deletes", len(tried))
	}
	if err == nil || !strings.Contains(err.Error(), "rule 2 busy") || !strings.Contains(err.Error(), "rule 3 gone") {
		t.Fatalf("both failures must be reported: %v", err)
	}
	if runAll(cmds, func([]string) error { return nil }) != nil {
		t.Fatal("no failures, no error")
	}
}

// A cut is the broker's own once it says so: store status pings live and says
// "cut" up to one freshness check before the mint path knows. A line from an
// earlier cut (before the mark) is not this cut's.
func TestL75NotAnsweringWaitsForTheLineAfterTheMark(t *testing.T) {
	log := filepath.Join(t.TempDir(), "b3.log")
	p := &regionProc{name: "port49-broker l75 b3", log: log}
	line := "port49-broker: directory store: not answering; serving from the cache confirmed 1.4s ago\n"
	if err := os.WriteFile(log, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	p.mark()
	if err := l75NotAnswering(p, 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "directory store: not answering") {
		t.Fatalf("only an earlier cut's line: %v, want the INVALID error naming the line", err)
	}
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	go func() {
		time.Sleep(150 * time.Millisecond)
		f.WriteString(line)
	}()
	start := time.Now()
	if err := l75NotAnswering(p, 5*time.Second); err != nil {
		t.Fatalf("a line written after the mark: %v", err)
	}
	if took := time.Since(start); took < 100*time.Millisecond || took > 3*time.Second {
		t.Fatalf("returned after %v: it must wait for the line, and stop when it comes", took)
	}
}
