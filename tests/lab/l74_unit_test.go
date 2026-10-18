//go:build lab

package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
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
	if !strings.Contains(string(body), "L74_ENC_KEY="+enc) || !strings.Contains(string(body), "L74_TACACS_KEY="+tac) {
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
