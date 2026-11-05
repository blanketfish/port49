//go:build systemdhost

package systemd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/kind/kindtest"
	"github.com/blanketfish/port49/tests/shapes/l84"
	"github.com/blanketfish/port49/tests/systemd/sdtest"
)

// TestL84Host is spec §15 L84's cells (a) and (c) on the machine's own systemd, which is the
// GitHub-hosted runner: ubuntu-24.04 with a real systemd as PID 1, root through sudo. The Debian
// container of TestL84Credentials renders no credentials (run 41912096808), so these two cells
// decide whether a README may name LoadCredential= for a device key. It adds cells "a-host" and
// "c-host" to the JSON file named by PORT49_L84_CELLS_OUT (merging with what the container test
// wrote there), which `make lab-l84` merges into the note.
//
// a-host: a transient unit with the shipped port49d.service's [Service] properties (User=port49d,
// the hardening) and LoadCredential=tacacs_v1:<root 0600 file>; the command is hostprobe, which
// calls port49d's fence.ReadSecret on $CREDENTIALS_DIRECTORY/tacacs_v1 within that directory (what
// livekeys.go does with key_secret_refs.file_dir). PASS iff it reads on two starts.
// c-host: a long-running unit with one credential, a second LoadCredential= added by `systemctl
// set-property` and then by a drop-in and daemon-reload, no restart. PASS iff the running unit's own
// credentials directory then holds the second file with the same main PID.
//
// The keys are generated here and written through stdin; nothing prints them.
func TestL84Host(t *testing.T) {
	if !sdtest.HostedRunner(os.Getenv) {
		t.Fatal("INVALID: TestL84Host changes the machine's users and units; it runs only on a GitHub-hosted runner")
	}
	out := os.Getenv("PORT49_L84_CELLS_OUT")
	if out == "" {
		t.Fatal("INVALID: PORT49_L84_CELLS_OUT names the JSON file the cells are added to")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Fatal("INVALID: no systemd-run on this machine")
	}
	root := kindtest.Root()
	const keyDir = "/etc/l84host"
	const probe = "/usr/local/bin/l84-hostprobe"

	run := func(stdin string, argv ...string) (string, string, error) {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = root
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		return strings.TrimSpace(so.String()), strings.TrimSpace(se.String()), err
	}
	sudo := func(stdin string, argv ...string) (string, string, error) {
		return run(stdin, append([]string{"sudo", "-n"}, argv...)...)
	}
	must := func(stdin string, argv ...string) string {
		t.Helper()
		so, se, err := sudo(stdin, argv...)
		if err != nil {
			t.Fatalf("%s: %v\n%s", argv[0], err, se)
		}
		return so
	}
	oneLine := func(s string) string { return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ; ")), " ") }
	// systemd-run's own stderr lines, less the ones that differ every run
	quiet := func(se string) string {
		var keep []string
		for _, l := range strings.Split(se, "\n") {
			for _, drop := range []string{"Running as unit", "Service runtime", "CPU time", "Memory peak", "Memory swap", "IP traffic", "IO bytes", "Finished with result"} {
				if strings.HasPrefix(l, drop) {
					l = ""
				}
			}
			if strings.TrimSpace(l) != "" {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}

	// the machine
	osr, _, _ := run("", "sh", "-c", ". /etc/os-release; echo $PRETTY_NAME")
	ver, _, _ := run("", "systemctl", "--version")
	kern, _, _ := run("", "uname", "-r")
	pid1, _, _ := run("", "ps", "-p", "1", "-o", "comm=")
	machine := l84.Row{Case: "the machine", Observation: fmt.Sprintf("%s; %s; kernel %s; PID 1 is %s", osr, strings.SplitN(ver, "\n", 2)[0], kern, pid1)}

	// the user, the keys and the probe program
	if _, _, err := run("", "id", "port49d"); err != nil {
		must("", "useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", "port49d")
	}
	must("", "install", "-d", "-m", "0700", "-o", "root", "-g", "root", keyDir)
	for _, name := range []string{"tacacs_v1", "tacacs_v2"} {
		k, err := testpki.RandomSecret(32)
		if err != nil {
			t.Fatal(err)
		}
		must(string(k), "sh", "-c", "umask 077; cat > "+keyDir+"/"+name)
	}
	bin := filepath.Join(t.TempDir(), "hostprobe")
	if _, se, err := run("", "go", "build", "-o", bin, "./tests/systemd/hostprobe"); err != nil {
		t.Fatalf("building hostprobe: %v\n%s", err, se)
	}
	must("", "install", "-m", "0755", bin, probe)

	unit, err := os.ReadFile(filepath.Join(root, "deploy", "systemd", "port49d.service"))
	if err != nil {
		t.Fatal(err)
	}
	var props []string
	for _, p := range sdtest.UnitProperties(string(unit)) {
		props = append(props, "-p", p)
	}
	cred := func(name string) string { return "LoadCredential=" + name + ":" + keyDir + "/" + name }

	// a-host
	a := l84.Cell{ID: "a-host", Verdict: l84.Fail, Rows: []l84.Row{machine,
		{Case: "properties applied", Observation: fmt.Sprintf("%d [Service] properties of the shipped port49d.service (User=, Group=, the hardening), less ExecStart, ExecReload, Restart, RestartSec, Type; plus %s", len(props)/2, strings.Split(cred("tacacs_v1"), ":")[0])}}}
	start := func(extra ...string) (string, bool) {
		args := append([]string{"systemd-run", "--wait", "--pipe", "--collect", "-p", cred("tacacs_v1")}, extra...)
		so, se, err := sudo("", append(args, probe, "read", "tacacs_v1")...)
		text := oneLine(so)
		if q := quiet(se); q != "" {
			text += " ; systemd-run: " + oneLine(q)
		}
		if err != nil {
			text += " ; exit: " + err.Error()
		}
		return text, err == nil && strings.Contains(so, "read: ok")
	}
	bareText, _ := start("-p", "User=port49d", "-p", "Group=port49d")
	a.Rows = append(a.Rows, l84.Row{Case: "reference: User=port49d, no hardening", Observation: bareText})
	first, ok1 := start(props...)
	second, ok2 := start(props...)
	a.Rows = append(a.Rows,
		l84.Row{Case: "first start, the shipped unit's shape", Observation: first},
		l84.Row{Case: "second start", Observation: second})
	if ok1 && ok2 {
		a.Verdict = l84.Pass
	}

	// c-host
	c := l84.Cell{ID: "c-host", Verdict: l84.Fail}
	const long = "l84-long"
	longDir := "/run/credentials/" + long + ".service"
	defer func() {
		sudo("", "systemctl", "stop", long+".service")
		sudo("", "rm", "-rf", "/etc/systemd/system/"+long+".service.d")
	}()
	must("", append(append([]string{"systemd-run", "--collect", "--unit", long, "-p", cred("tacacs_v1")}, props...), "/usr/bin/sleep", "900")...)
	show := func(p string) string {
		so, _, _ := sudo("", "systemctl", "show", long+".service", "-p", p, "--value")
		return so
	}
	for deadline := time.Now().Add(30 * time.Second); show("ActiveState") != "active" && time.Now().Before(deadline); time.Sleep(time.Second) {
	}
	pid, started := show("MainPID"), show("ExecMainStartTimestamp")
	has := func(names ...string) string {
		so, se, err := sudo("", append([]string{"nsenter", "-t", show("MainPID"), "-m", "env", "CREDENTIALS_DIRECTORY=" + longDir, probe, "has"}, names...)...)
		if err != nil {
			return "not readable from the unit's namespace: " + oneLine(se)
		}
		return oneLine(so)
	}
	c.Rows = append(c.Rows, machine, l84.Row{Case: "the long-running unit, one credential", Observation: "active; in its credentials directory: " + has("tacacs_v1", "tacacs_v2")})
	// the property, then the drop-in
	_, setErr, err := sudo("", "systemctl", "set-property", long+".service", cred("tacacs_v2"))
	setObs := "accepted"
	if err != nil {
		var ee *exec.ExitError
		setObs = "refused by systemctl: " + oneLine(setErr)
		if errors.As(err, &ee) {
			setObs += fmt.Sprintf(" (exit %d)", ee.ExitCode())
		}
	}
	c.Rows = append(c.Rows, l84.Row{Case: "systemctl set-property LoadCredential= (the second credential)", Observation: setObs})
	must("", "install", "-d", "/etc/systemd/system/"+long+".service.d")
	must("[Service]\n"+cred("tacacs_v2")+"\n", "sh", "-c", "cat > /etc/systemd/system/"+long+".service.d/v2.conf")
	must("", "systemctl", "daemon-reload")
	configured := strings.Contains(show("LoadCredential"), "tacacs_v2")
	appeared := false
	begin := time.Now()
	for time.Since(begin) < 30*time.Second && !appeared {
		appeared = strings.Contains(has("tacacs_v1", "tacacs_v2"), "tacacs_v2: present")
		if !appeared {
			time.Sleep(2 * time.Second)
		}
	}
	pidAfter, startedAfter := show("MainPID"), show("ExecMainStartTimestamp")
	unchanged := pid != "" && pid != "0" && pid == pidAfter && started == startedAfter
	c.Rows = append(c.Rows,
		l84.Row{Case: "after the drop-in and daemon-reload, no restart: the manager's LoadCredential= for the unit names the second credential", Observation: yes2(configured)},
		l84.Row{Case: "the second file in the running unit's credentials directory within 30 s", Observation: yes2(appeared) + "; now: " + has("tacacs_v1", "tacacs_v2")},
		l84.Row{Case: "main PID and ExecMainStartTimestamp", Observation: fmt.Sprintf("before %s %s, after %s %s; unchanged: %s", pid, started, pidAfter, startedAfter, yes2(unchanged))})
	must("", "systemctl", "restart", long+".service")
	for deadline := time.Now().Add(30 * time.Second); show("ActiveState") != "active" && time.Now().Before(deadline); time.Sleep(time.Second) {
	}
	c.Rows = append(c.Rows, l84.Row{Case: "after systemctl restart (the way a credential is added)", Observation: has("tacacs_v1", "tacacs_v2")})
	if appeared && unchanged {
		c.Verdict = l84.Pass
	}

	cells, err := l84.Load(out)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := l84.Save(out, l84.Merge(cells, []l84.Cell{a, c})); err != nil {
		t.Fatal(err)
	}
}

func yes2(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}
