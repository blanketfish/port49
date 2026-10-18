//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// A member or process is started so its real PID is recorded: the namespaced
// command writes $$ to the pidfile and execs the program, so the PID is the
// program's, not sudo's.
func TestPidWrapRecordsTheExecedPID(t *testing.T) {
	got := pidWrap("/tmp/x/d1.etcd.pid", []string{"/bin/etcd", "--name", "d1"})
	want := []string{"sh", "-c", `echo $$ > "$0"; exec "$@"`, "/tmp/x/d1.etcd.pid", "/bin/etcd", "--name", "d1"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%q", got)
	}
	ns := strings.Join(inNS("p49r1", []string{"A=1"}, got...), " ")
	if !strings.Contains(ns, "-- env A=1 sh -c") {
		t.Fatalf("%s", ns)
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
