//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/tacacs/wire"
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
	if err := os.WriteFile(envfile, []byte("L74_ENC_KEY=abc123\nL74_TACACS_KEY=def456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := pidWrap(pidfile, envfile, []string{"sh", "-c", `printf '%s %s' "$L74_ENC_KEY" "$L74_TACACS_KEY" > "$0"; sleep 30`, out})
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
	if !strings.Contains(string(body), "L74_ENC_KEY="+shellQuote(enc)) || !strings.Contains(string(body), "L74_TACACS_KEY="+shellQuote(tac)) {
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
	a := pidWrap(filepath.Join(dir, "p.pid"), envfile, []string{"sh", "-c", `printf '%s|%s' "$L74_ENC_KEY" "$L74_TACACS_KEY" > "$0"`, out})
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
	if !strings.Contains(y, "password_env: LAB_DIRECTORY_BIND_PASSWORD") || !strings.Contains(y, "secret_env: L74_ENC_KEY") {
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
