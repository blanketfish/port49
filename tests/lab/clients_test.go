//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/config"
)

// L15, the half nobody had driven: **what the clients an operator actually
// runs cost in TACACS+ authentications.**
//
// `transport_test.go` drives an HTTP client with `DisableKeepAlives` and no
// cookie jar, presenting Basic credentials on a fresh connection every call.
// That is the most expensive way to use either API and the notes wrote its
// result up as a property of the transport. It is not: it is a property of
// that client. This test runs the real ones — pyeapi, NAPALM, Ansible over
// `httpapi` and `network_cli`, Nornir with ten worker threads — and counts.
//
// Three columns per client, and each is measured rather than assumed:
//
//  1. **how many TACACS+ authentications a ten-task job costs.** Counted from
//     `redeem` records in the window, which is port49's own log and not an
//     inference.
//  2. **whether a single-use token survives the job.** A token is spent by its
//     first redemption; every later call is answered out of the receipt
//     (`receipt_replayed`) until the receipt's sliding `receipt_idle_ttl` runs
//     out or its `receipt_max_age` cap is reached. So "survives" means the job
//     completed, and the note reports the mix of `token_redeemed` and
//     `receipt_replayed` that carried it — which is the receipt-window question
//     decision 15 turns on, arriving from the client side.
//  3. **what the client puts on the wire.** This one is *inferred*, and the
//     note says so in those words: the capture filter is `tcp port 49`, so the
//     HTTPS and SSH bytes are not in evidence. One authentication for ten
//     tasks means the credential was presented once — a cookie, a session or
//     one persistent connection; ten means it was presented ten times. The
//     inference is from the count, and it is labelled.
//
// The Nornir case is the one with a second question attached. Ten worker
// threads against one device as one user means **ten concurrent logins sharing
// one `(nas, username)` login context**, which is the accepted cost of
// decision 15 stated as a workload. What port49 logs for that, and whether any
// session is refused, is the thing to read here — yesterday an unexplained
// double-login refusal was seen once on IOS-XE.
func TestClientAuthenticationCost(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		specs, ok := clientSpecs[l.p.name]
		if !ok {
			t.Skipf("no real-client matrix for %s yet", l.p.name)
		}
		if _, err := os.Stat(venvPython); err != nil {
			t.Skipf("no client venv at %s: %v. Create it with `python3 -m venv ~/lab-venv` and "+
				"install pyeapi, napalm, ansible-core, nornir, nornir-napalm, nornir-netmiko, netmiko, or point PORT49_LAB_VENV_PYTHON at a venv's python.", venvPython, err)
		}
		stop := l.capture(t, "clients")
		defer stop()

		var b strings.Builder
		b.WriteString(clientsPreamble)

		results := make([]clientResult, 0, len(specs))
		for _, s := range specs {
			r := l.runClient(t, s)
			results = append(results, r)
			b.WriteString(r.render())
		}
		b.WriteString(clientTable(results))

		l.result(t, "L15-clients", clientsClaim, b.String())

		// A client whose job produced no successful task and no authentication
		// measured nothing. Some failing is a finding — NAPALM's NX-API driver
		// failing half its tasks past the receipt boundary is the most
		// valuable row in the table — but all of them failing to even reach
		// port49 is a harness fault.
		ran := 0
		for _, r := range results {
			if r.redeems > 0 {
				ran++
			}
		}
		if ran == 0 {
			t.Fatalf("not one of the %d clients reached port49 at all, so no authentication cost was "+
				"measured on %s. Each client's output is in the note.", len(results), l.p.name)
		}
	})
}

// venvPython is the lab's client venv interpreter: PORT49_LAB_VENV_PYTHON, or ~/lab-venv/bin/python.
var venvPython = func() string {
	if p := os.Getenv("PORT49_LAB_VENV_PYTHON"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// No home directory and no PORT49_LAB_VENV_PYTHON: a path that cannot exist, so the lab tests
		// skip with a message naming the variable rather than looking in the working directory.
		return filepath.Join(os.TempDir(), "no-home-set-PORT49_LAB_VENV_PYTHON", "python")
	}
	return filepath.Join(home, "lab-venv", "bin", "python")
}()

const clientsClaim = "How many TACACS+ authentication exchanges a ten-task job costs for each client an " +
	"operator actually runs — pyeapi, NAPALM, Ansible over `httpapi` and `network_cli`, Nornir with ten " +
	"worker threads — whether a single-use token survives the job, and what that implies the client put " +
	"on the wire. Also, for Nornir: what port49 logs when ten concurrent logins share one " +
	"`(nas, username)` login context, and whether any session is refused."

const clientsPreamble = "Each client below runs a **ten-task job** against one device as one seeded user, " +
	"with one single-use token. The counts come from port49's decision log, not from the client.\n\n" +
	"**What the client put on the wire is INFERRED, not measured.** The capture filter is `tcp port 49`, " +
	"so the HTTPS and SSH bytes are not in evidence here. One authentication for ten tasks means the " +
	"credential reached the device once — a cookie, a session, or one persistent connection; ten means it " +
	"reached it ten times. That inference is from the authentication count and is labelled as an inference " +
	"in every row.\n"

// clientSpec is one client and the ten-task job it runs. script is Python run
// by the venv interpreter with the device address, username and token in the
// environment, so no credential is ever an argv element a `ps` would show.
type clientSpec struct {
	name    string
	what    string // what this client is, for the note
	script  string
	env     map[string]string
	timeout time.Duration
}

func (s clientSpec) budget() time.Duration {
	if s.timeout == 0 {
		return 5 * time.Minute
	}
	return s.timeout
}

// clientResult is one client's evidence.
type clientResult struct {
	spec      clientSpec
	ok        bool
	out       string
	redeems   int
	fresh     int // token_redeemed
	replayed  int // receipt_replayed
	denied    int
	denials   []string
	sessAuthz int
	cmdAuthz  int
	ctxIDs    map[string]bool
	elapsed   time.Duration

	// tasksOK and tasksFailed are counted from the client's own output. They
	// exist because `ok` is the process exit status and a script that catches
	// its exceptions exits 0 with half its tasks failed -- which is exactly
	// what NAPALM's nxos driver did on the first run, and the table called it
	// "the job completed".
	tasksOK, tasksFailed int

	// firstFresh is when the token was spent and firstDenial when the first
	// call after it was refused. The gap between them is the receipt window
	// measured from the client side, which is the boundary decision 15 turns
	// on and which no test had driven.
	firstFresh, firstDenial time.Time
}

// labReceiptIdleTTL and labReceiptMaxAge are the receipt bounds in force for
// the lab. tests/lab/port49d-lab.yaml sets neither, so these are
// internal/config's defaults, and TestLabReceiptBoundsMatchTheLabConfig keeps
// them from drifting apart by loading the real config rather than by reading
// the yaml for a key.
//
// They replaced a single `receipt_ttl` when the receipt became a sliding
// window (spec §13, decision 15): the idle bound is pushed out by every
// presentation the receipt answers, and the cap is measured from the first
// redemption and never moves. Every client note below quotes both.
const (
	labReceiptIdleTTL = 15 * time.Minute
	labReceiptMaxAge  = 2 * time.Hour
)

func (r clientResult) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s\n\n%s\n\n", r.spec.name, r.spec.what)
	state := "**the client exited non-zero**"
	if r.ok {
		state = "the client exited 0"
	}
	fmt.Fprintf(&b, "Ten tasks in %s; %s. **%d task(s) succeeded and %d failed**, counted from the "+
		"client's own output — the exit status is not the measurement, because a script that catches its "+
		"exceptions exits 0 with half its tasks refused.\n\n",
		r.elapsed.Round(time.Millisecond), state, r.tasksOK, r.tasksFailed)
	fmt.Fprintf(&b, "port49's own counts for the window:\n\n```\nredeem records        %d  (token_redeemed %d, receipt_replayed %d, denied %d)\n"+
		"authorize_session     %d\nauthorize_command     %d\ndistinct ctx_id       %d\n```\n\n",
		r.redeems, r.fresh, r.replayed, r.denied, r.sessAuthz, r.cmdAuthz, len(r.ctxIDs))
	if len(r.denials) > 0 {
		fmt.Fprintf(&b, "Denials, verbatim from the log:\n\n```\n%s\n```\n\n", strings.Join(r.denials, "\n"))
	}
	b.WriteString(r.receiptWindow())
	fmt.Fprintf(&b, "**Inferred** from the authentication count, not measured — the capture holds no HTTPS or "+
		"SSH bytes: %s\n\n", clientWireInference(r))
	fmt.Fprintf(&b, "What the client printed:\n\n```\n%s\n```\n\n", strings.TrimRight(clientTail(r.out), "\n"))
	return b.String()
}

// countTasks reads how many of a job's tasks succeeded out of the client's own
// output. Two shapes, because the clients print two:
//
//   - the Python scripts print one `task <n> ok` or `task <n> FAILED` line
//     each;
//   - ansible-playbook prints a PLAY RECAP, `leaf1 : ok=10 ... failed=0 ...`,
//     and no per-task line at all.
//
// The first version knew only the first shape, so every Ansible row in the
// table read `0/0` about a play that had run all ten tasks. A column saying
// nothing succeeded, about a job that succeeded, is worse than no column.
func countTasks(out string) (ok, failed int) {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "task ") && strings.Contains(t, "FAILED"):
			failed++
		case strings.HasPrefix(t, "task ") && strings.Contains(t, " ok"):
			ok++
		case strings.Contains(t, "ok=") && strings.Contains(t, "failed="):
			// An ansible PLAY RECAP line: `leaf1 : ok=10 changed=0 ... failed=0`.
			for _, f := range strings.Fields(t) {
				k, v, found := strings.Cut(f, "=")
				if !found {
					continue
				}
				n := 0
				fmt.Sscanf(v, "%d", &n)
				switch k {
				case "ok":
					ok += n
				case "failed", "unreachable":
					failed += n
				}
			}
		}
	}
	return ok, failed
}

// receiptWindow reports the gap between the token being spent and the first
// call that was refused, which is the receipt boundary seen from the client
// side. Decision 15 names that boundary as the thing it actually turns on, and
// until this run no test had driven a job past it.
func (r clientResult) receiptWindow() string {
	if r.firstDenial.IsZero() {
		return fmt.Sprintf("No call in this job was refused, so it did not reach the receipt boundary. "+
			"The job took %s against a `receipt_idle_ttl` of %s and a `receipt_max_age` of %s.\n\n",
			r.elapsed.Round(time.Millisecond), labReceiptIdleTTL, labReceiptMaxAge)
	}
	if r.firstFresh.IsZero() {
		return "Calls were refused but no fresh redemption was recorded, so this job cannot be read as a " +
			"receipt-expiry measurement; see the denials above for what it was.\n\n"
	}
	gap := r.firstDenial.Sub(r.firstFresh)
	return fmt.Sprintf("**The receipt boundary, measured.** The token was spent at the first redemption "+
		"and the first refusal came **%s later**, against a configured `receipt_idle_ttl` of %s and a "+
		"`receipt_max_age` of %s. Every call "+
		"in between was served `receipt_replayed` out of the receipt rather than out of the store. "+
		"Past it, the same credential in the same script against the same device is `token_not_found` "+
		"— nothing in the operator's hand changed. This is the boundary spec §13 decision 15 says any "+
		"argument about reusable tokens has to be made about.\n\n",
		gap.Round(100*time.Millisecond), labReceiptIdleTTL, labReceiptMaxAge)
}

// clientWireInference is the sentence the note prints for the wire column. It
// is written from the count and says which count it came from, so a reader can
// disagree with the inference while keeping the measurement.
func clientWireInference(r clientResult) string {
	switch {
	case r.redeems == 0:
		return "no authentication reached port49 at all across ten tasks, so either the client never " +
			"connected or it reached the device by a path that does not consult TACACS+ (a key-based " +
			"SSH session, a cached session, or a failure before the first connection)."
	case r.redeems == 1:
		return "one authentication for ten tasks: the credential reached the device **once**. That is a " +
			"cookie, an API session, or a single persistent connection carrying all ten."
	case r.redeems >= 10:
		return fmt.Sprintf("%d authentications for ten tasks: the credential reached the device **on "+
			"every task**. That is Basic (or a password prompt) presented per call, on a connection "+
			"that is not being reused for AAA purposes.", r.redeems)
	default:
		return fmt.Sprintf("%d authentications for ten tasks, which is neither once nor per-task: the "+
			"client is reusing something part of the time. The per-record detail above is what says "+
			"what; this row does not guess.", r.redeems)
	}
}

// clientTail keeps the note readable when a client is chatty, and never drops
// the end, which is where a traceback is.
func clientTail(s string) string {
	const max = 2500
	if len(s) <= max {
		return s
	}
	return "... (" + fmt.Sprint(len(s)-max) + " earlier bytes elided) ...\n" + s[len(s)-max:]
}

func clientTable(rs []clientResult) string {
	var b strings.Builder
	b.WriteString("\n## Every client side by side\n\n")
	b.WriteString("| client | tasks ok | TACACS+ authentications per 10 tasks | fresh / replayed / denied | " +
		"single-use token survived the job | wire, inferred |\n|---|---|---|---|---|---|\n")
	for _, r := range rs {
		done := fmt.Sprintf("%d/%d", r.tasksOK, r.tasksOK+r.tasksFailed)
		survived := "**yes**"
		switch {
		case r.tasksFailed > 0 && r.denied > 0:
			survived = fmt.Sprintf("**no** — %d task(s) refused after the receipt expired", r.tasksFailed)
		case r.tasksFailed > 0:
			survived = fmt.Sprintf("**no** — %d task(s) failed", r.tasksFailed)
		case !r.ok:
			survived = "**unclear** — the client exited non-zero"
		}
		wire := "once"
		switch {
		case r.redeems == 0:
			wire = "never reached port49"
		case r.redeems >= 10:
			wire = "per task"
		case r.redeems > 1:
			wire = "partly reused"
		}
		fmt.Fprintf(&b, "| %s | %s | **%d** | %d / %d / %d | %s | %s |\n",
			r.spec.name, done, r.redeems, r.fresh, r.replayed, r.denied, survived, wire)
	}
	return b.String()
}

// runClient runs one client's job and reads port49's log around it.
func (l *lab) runClient(t *testing.T, s clientSpec) clientResult {
	t.Helper()
	r := clientResult{spec: s, ctxIDs: map[string]bool{}}
	user, secret := l.nextLogin(t)

	dir := filepath.Join(root, "tests", "lab", "logs", "clients")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("client script directory: %v", err)
	}
	path := filepath.Join(dir, l16Slug(s.name)+".py")
	if err := os.WriteFile(path, []byte(s.script), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	off := l.mark()
	start := time.Now()
	cmd := exec.Command(venvPython, path)
	// The token goes in the environment, never in argv: argv is world-readable
	// through /proc on this host and a `ps` during a run would print it.
	cmd.Env = append(os.Environ(),
		"P49_HOST="+l.p.addr,
		"P49_USER="+user,
		"P49_PASS="+secret,
		"P49_TASKS=10",
		"ANSIBLE_HOST_KEY_CHECKING=False",
	)
	for k, v := range s.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { defer close(done); out, err = cmd.CombinedOutput() }()
	select {
	case <-done:
	case <-time.After(s.budget()):
		_ = cmd.Process.Kill()
		<-done
		err = fmt.Errorf("the client did not finish within %s and was killed", s.budget())
	}
	r.elapsed = time.Since(start)
	r.out = string(out)
	if err != nil {
		r.out += "\n\n" + err.Error()
	}
	r.ok = err == nil

	r.tasksOK, r.tasksFailed = countTasks(r.out)

	for _, rec := range l.drainRecords(off, 10*time.Second) {
		sess := sub(rec, "session")
		if id := str(sess, "ctx_id"); id != "" {
			r.ctxIDs[id] = true
		}
		switch str(rec, "event") {
		case "redeem":
			r.redeems++
			ts, _ := recTime(rec)
			switch str(rec, "reason") {
			case "token_redeemed":
				r.fresh++
				if r.firstFresh.IsZero() {
					r.firstFresh = ts
				}
			case "receipt_replayed":
				r.replayed++
			}
			if str(rec, "verdict") == "deny" {
				r.denied++
				if r.firstDenial.IsZero() {
					r.firstDenial = ts
				}
				r.denials = append(r.denials, fmt.Sprintf("redeem deny %s user=%s port=%s",
					str(rec, "reason"), str(sess, "username"), str(sess, "port")))
			}
		case "authorize_session":
			r.sessAuthz++
			if str(rec, "verdict") == "deny" {
				r.denials = append(r.denials, fmt.Sprintf("authorize_session deny %s port=%s",
					str(rec, "reason"), str(sess, "port")))
			}
		case "authorize_command":
			r.cmdAuthz++
		}
	}
	t.Logf("%s / %s: %d redeems (%d fresh, %d replayed, %d denied) in %s, ok=%v",
		l.p.name, s.name, r.redeems, r.fresh, r.replayed, r.denied, r.elapsed.Round(time.Millisecond), r.ok)
	return r
}

// The scripts. Each does ten operations and prints one line per operation, so
// a partial run is visible in the note rather than being a bare traceback.
// None of them reads a credential from argv.
const pyPreamble = `
import os, sys, ssl, warnings
warnings.filterwarnings("ignore")
ssl._create_default_https_context = ssl._create_unverified_context
HOST = os.environ["P49_HOST"]; USER = os.environ["P49_USER"]; PASS = os.environ["P49_PASS"]
N = int(os.environ.get("P49_TASKS", "10"))
`

var clientSpecs = map[string][]clientSpec{
	"arista_eos": {
		{
			name: "pyeapi (eAPI over HTTPS)",
			what: "Arista's own Python client. It builds one `requests`-style connection and reuses it, " +
				"which is the shape `transport_test.go` deliberately does not drive.",
			script: pyPreamble + `
import pyeapi
node = pyeapi.connect(transport="https", host=HOST, username=USER, password=PASS, return_node=True)
for i in range(N):
    try:
        r = node.enable("show hostname")
        print("task", i, "ok", str(r)[:80])
    except Exception as e:
        print("task", i, "FAILED", type(e).__name__, str(e)[:200])
`,
		},
		{
			name: "NAPALM eos (eAPI)",
			what: "NAPALM's `eos` driver, which sits on pyeapi. One `open()` then ten getters.",
			script: pyPreamble + `
from napalm import get_network_driver
d = get_network_driver("eos")(hostname=HOST, username=USER, password=PASS,
                              optional_args={"transport": "https", "port": 443})
d.open()
for i in range(N):
    try:
        print("task", i, "ok", str(d.get_facts().get("hostname"))[:60])
    except Exception as e:
        print("task", i, "FAILED", type(e).__name__, str(e)[:200])
d.close()
`,
		},
		{
			name: "netmiko arista_eos (one persistent SSH)",
			what: "One SSH session held open for all ten commands — the shape an interactive operator has, " +
				"and the one Nornir's netmiko plugin uses.",
			script: pyPreamble + `
from netmiko import ConnectHandler
c = ConnectHandler(device_type="arista_eos", host=HOST, username=USER, password=PASS, fast_cli=False)
for i in range(N):
    try:
        print("task", i, "ok", c.send_command("show hostname").strip()[:60])
    except Exception as e:
        print("task", i, "FAILED", type(e).__name__, str(e)[:200])
c.disconnect()
`,
		},
		{
			name: "Nornir + netmiko, 10 workers, one device, one user",
			what: "Ten worker threads opening ten sessions to one device as one user **at the same " +
				"time**. This is the `(nas, username)` login-context key under its accepted worst case: " +
				"ten concurrent logins sharing one context (spec §13, decision 15). What port49 logs, " +
				"and whether any session is refused, is the finding.\n\nThe inventory holds ten host " +
				"entries that all point at the same device, and the job is ONE `nr.run` over them. The " +
				"first version ran ten sequential `nr.run` calls against one host, and netmiko served " +
				"them all from a single reused connection: one authentication, one ctx_id, 3.6 seconds " +
				"and **no concurrency whatsoever**. It measured the opposite of what it claimed, and the " +
				"count it produced looked perfectly reasonable, which is why it is called out here.",
			timeout: 8 * time.Minute,
			script: pyPreamble + `
from nornir import InitNornir
from nornir_netmiko.tasks import netmiko_send_command
import yaml, tempfile, os
# N host entries, every one of them the same device and the same user, so the
# threaded runner opens N sessions at once instead of reusing one.
hosts = {}
for i in range(N):
    hosts["leaf1-%02d" % i] = {"hostname": HOST, "username": USER, "password": PASS,
                               "platform": "arista_eos",
                               "connection_options": {"netmiko": {"extras": {"fast_cli": False}}}}
d = tempfile.mkdtemp()
open(os.path.join(d, "hosts.yaml"), "w").write(yaml.safe_dump(hosts))
open(os.path.join(d, "groups.yaml"), "w").write("{}\n")
nr = InitNornir(runner={"plugin": "threaded", "options": {"num_workers": N}},
                inventory={"plugin": "SimpleInventory",
                           "options": {"host_file": os.path.join(d, "hosts.yaml"),
                                       "group_file": os.path.join(d, "groups.yaml")}},
                logging={"enabled": False})
res = nr.run(task=netmiko_send_command, command_string="show hostname")
for i, (h, r) in enumerate(sorted(res.items())):
    print("task", i, h, "FAILED" if r.failed else "ok", str(r.exception or r.result)[:120])
`,
		},
		{
			name:    "Ansible arista.eos over httpapi",
			what:    "`ansible.netcommon.httpapi` against eAPI, ten tasks in one play.",
			timeout: 8 * time.Minute,
			script: pyPreamble + `
import subprocess, tempfile, os, json
d = tempfile.mkdtemp()
inv = {"all": {"hosts": {"leaf1": {
    "ansible_host": HOST, "ansible_user": USER, "ansible_password": PASS,
    "ansible_connection": "ansible.netcommon.httpapi",
    "ansible_network_os": "arista.eos.eos",
    "ansible_httpapi_use_ssl": True, "ansible_httpapi_validate_certs": False,
    "ansible_httpapi_port": 443}}}}
open(os.path.join(d, "inv.json"), "w").write(json.dumps(inv))
tasks = "\n".join(
  "    - name: task %d\n      arista.eos.eos_command:\n        commands: [show hostname]\n" % i
  for i in range(N))
open(os.path.join(d, "play.yml"), "w").write(
  "- hosts: all\n  gather_facts: false\n  tasks:\n" + tasks)
env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING="False", ANSIBLE_PERSISTENT_COMMAND_TIMEOUT="60")
p = subprocess.run([os.path.join(os.path.dirname(sys.executable), "ansible-playbook"),
                    "-i", os.path.join(d, "inv.json"), os.path.join(d, "play.yml")],
                   capture_output=True, text=True, env=env)
print(p.stdout[-4000:]); print(p.stderr[-2000:]); sys.exit(p.returncode)
`,
		},
		{
			name: "Ansible arista.eos over network_cli",
			what: "The same ten tasks over `ansible.netcommon.network_cli`, which holds one persistent SSH " +
				"connection through a control-socket process.",
			timeout: 8 * time.Minute,
			script: pyPreamble + `
import subprocess, tempfile, os, json
d = tempfile.mkdtemp()
inv = {"all": {"hosts": {"leaf1": {
    "ansible_host": HOST, "ansible_user": USER, "ansible_password": PASS,
    "ansible_connection": "ansible.netcommon.network_cli",
    "ansible_network_os": "arista.eos.eos"}}}}
open(os.path.join(d, "inv.json"), "w").write(json.dumps(inv))
tasks = "\n".join(
  "    - name: task %d\n      arista.eos.eos_command:\n        commands: [show hostname]\n" % i
  for i in range(N))
open(os.path.join(d, "play.yml"), "w").write(
  "- hosts: all\n  gather_facts: false\n  tasks:\n" + tasks)
env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING="False", ANSIBLE_PERSISTENT_COMMAND_TIMEOUT="60")
p = subprocess.run([os.path.join(os.path.dirname(sys.executable), "ansible-playbook"),
                    "-i", os.path.join(d, "inv.json"), os.path.join(d, "play.yml")],
                   capture_output=True, text=True, env=env)
print(p.stdout[-4000:]); print(p.stderr[-2000:]); sys.exit(p.returncode)
`,
		},
	},
	"cisco_nxos": {
		{
			name: "NAPALM nxos (NX-API over HTTPS)",
			what: "NAPALM's `nxos` driver, which speaks NX-API. One `open()` then ten getters.",
			script: pyPreamble + `
from napalm import get_network_driver
d = get_network_driver("nxos")(hostname=HOST, username=USER, password=PASS,
                               optional_args={"port": 443, "transport": "https"})
d.open()
for i in range(N):
    try:
        print("task", i, "ok", str(d.get_facts().get("hostname"))[:60])
    except Exception as e:
        print("task", i, "FAILED", type(e).__name__, str(e)[:200])
d.close()
`,
		},
		{
			name: "NAPALM nxos_ssh",
			what: "The same driver family over SSH rather than NX-API — one persistent session.",
			script: pyPreamble + `
from napalm import get_network_driver
d = get_network_driver("nxos_ssh")(hostname=HOST, username=USER, password=PASS)
d.open()
for i in range(N):
    try:
        print("task", i, "ok", str(d.get_facts().get("hostname"))[:60])
    except Exception as e:
        print("task", i, "FAILED", type(e).__name__, str(e)[:200])
d.close()
`,
		},
		{
			name: "netmiko cisco_nxos (one persistent SSH)",
			what: "One SSH session held open for ten commands.",
			script: pyPreamble + `
from netmiko import ConnectHandler
c = ConnectHandler(device_type="cisco_nxos", host=HOST, username=USER, password=PASS, fast_cli=False)
for i in range(N):
    try:
        print("task", i, "ok", c.send_command("show hostname").strip()[:60])
    except Exception as e:
        print("task", i, "FAILED", type(e).__name__, str(e)[:200])
c.disconnect()
`,
		},
		{
			name:    "Ansible cisco.nxos over httpapi",
			what:    "`ansible.netcommon.httpapi` against NX-API, ten tasks in one play.",
			timeout: 8 * time.Minute,
			script: pyPreamble + `
import subprocess, tempfile, os, json
d = tempfile.mkdtemp()
inv = {"all": {"hosts": {"nx1": {
    "ansible_host": HOST, "ansible_user": USER, "ansible_password": PASS,
    "ansible_connection": "ansible.netcommon.httpapi",
    "ansible_network_os": "cisco.nxos.nxos",
    "ansible_httpapi_use_ssl": True, "ansible_httpapi_validate_certs": False,
    "ansible_httpapi_port": 443}}}}
open(os.path.join(d, "inv.json"), "w").write(json.dumps(inv))
tasks = "\n".join(
  "    - name: task %d\n      cisco.nxos.nxos_command:\n        commands: [show hostname]\n" % i
  for i in range(N))
open(os.path.join(d, "play.yml"), "w").write(
  "- hosts: all\n  gather_facts: false\n  tasks:\n" + tasks)
env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING="False", ANSIBLE_PERSISTENT_COMMAND_TIMEOUT="60")
p = subprocess.run([os.path.join(os.path.dirname(sys.executable), "ansible-playbook"),
                    "-i", os.path.join(d, "inv.json"), os.path.join(d, "play.yml")],
                   capture_output=True, text=True, env=env)
print(p.stdout[-4000:]); print(p.stderr[-2000:]); sys.exit(p.returncode)
`,
		},
		{
			name:    "Ansible cisco.nxos over network_cli",
			what:    "The same ten tasks over one persistent SSH connection.",
			timeout: 8 * time.Minute,
			script: pyPreamble + `
import subprocess, tempfile, os, json
d = tempfile.mkdtemp()
inv = {"all": {"hosts": {"nx1": {
    "ansible_host": HOST, "ansible_user": USER, "ansible_password": PASS,
    "ansible_connection": "ansible.netcommon.network_cli",
    "ansible_network_os": "cisco.nxos.nxos"}}}}
open(os.path.join(d, "inv.json"), "w").write(json.dumps(inv))
tasks = "\n".join(
  "    - name: task %d\n      cisco.nxos.nxos_command:\n        commands: [show hostname]\n" % i
  for i in range(N))
open(os.path.join(d, "play.yml"), "w").write(
  "- hosts: all\n  gather_facts: false\n  tasks:\n" + tasks)
env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING="False", ANSIBLE_PERSISTENT_COMMAND_TIMEOUT="60")
p = subprocess.run([os.path.join(os.path.dirname(sys.executable), "ansible-playbook"),
                    "-i", os.path.join(d, "inv.json"), os.path.join(d, "play.yml")],
                   capture_output=True, text=True, env=env)
print(p.stdout[-4000:]); print(p.stderr[-2000:]); sys.exit(p.returncode)
`,
		},
	},
}

// TestLabReceiptBoundsMatchTheLabConfig keeps labReceiptIdleTTL and
// labReceiptMaxAge honest. The receipt boundary the client notes quote is read
// from those constants, and they are only right while they equal what the
// daemon actually runs with — which is either what port49d-lab.yaml sets or,
// where it sets nothing, internal/config's default.
//
// It asserts against `config.Load` rather than scanning the yaml for a key,
// which is the difference between a guard and a formality: the previous
// version only checked that port49d-lab.yaml did not *set* `receipt_ttl`, so
// when the default moved from 30s to 15m/2h underneath it, it stayed green
// while every note quoting the old number went wrong. That is exactly the
// class of error this harness exists to make impossible.
//
// It deploys nothing and needs no device.
func TestLabReceiptBoundsMatchTheLabConfig(t *testing.T) {
	c := loadLabConfig(t)
	if c.ReceiptIdleTTL != labReceiptIdleTTL || c.ReceiptMaxAge != labReceiptMaxAge {
		t.Fatalf("the daemon would run with receipt_idle_ttl=%s receipt_max_age=%s, but the notes quote "+
			"%s/%s. Set the constants in clients_test.go to match what port49d-lab.yaml and "+
			"internal/config's defaults produce, or every client note quoting them is wrong.",
			c.ReceiptIdleTTL, c.ReceiptMaxAge, labReceiptIdleTTL, labReceiptMaxAge)
	}
}

// loadLabConfig loads port49d-lab.yaml exactly as the daemon does, so a test
// asserts against the real resolved config rather than against the yaml text.
//
// Three things stand between the file and config.Load. The repository root is
// resolved here rather than read from the package's `root`, which is only set
// once a platform has been brought up — this test deploys nothing and must run
// without a device. `inventory_file` is relative to that root, because the
// harness runs the daemon from there while `go test` runs from tests/lab;
// rewriting that one line is less invasive than chdir'ing the test process.
// And the shared key comes from the environment by name, so it has to be
// present for the load to succeed — labKeyDefault is what the harness itself
// falls back to.
func loadLabConfig(t *testing.T) config.Config {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "port49d-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		s := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(s, "inventory_file:"); ok {
			lines[i] = "inventory_file: " + filepath.Join(root, strings.TrimSpace(rest))
		}
	}
	p := filepath.Join(t.TempDir(), "port49d-lab.yaml")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PORT49_LAB_KEY") == "" {
		t.Setenv("PORT49_LAB_KEY", labKeyDefault)
	}
	c, err := config.Load(p)
	if err != nil {
		t.Fatalf("the lab config no longer loads: %v", err)
	}
	return c
}
