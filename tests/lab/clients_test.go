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
//     (`receipt_replayed`) until `receipt_ttl` expires. So "survives" means
//     the job completed, and the note reports the mix of `token_redeemed` and
//     `receipt_replayed` that carried it — which is the `receipt_ttl` question
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
				"install pyeapi, napalm, ansible-core, nornir, nornir-napalm, nornir-netmiko, netmiko.", venvPython, err)
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

		ran := 0
		for _, r := range results {
			if r.ok {
				ran++
			}
		}
		if ran == 0 {
			t.Fatalf("not one of the %d clients completed a job, so no authentication cost was measured "+
				"on %s. Each client's output is in the note.", len(results), l.p.name)
		}
	})
}

const venvPython = "/home/rwendt/lab-venv/bin/python"

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
}

func (r clientResult) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s\n\n%s\n\n", r.spec.name, r.spec.what)
	state := "**the job did not complete**"
	if r.ok {
		state = "the job completed"
	}
	fmt.Fprintf(&b, "Ten tasks, %s in %s.\n\n", state, r.elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "port49's own counts for the window:\n\n```\nredeem records        %d  (token_redeemed %d, receipt_replayed %d, denied %d)\n"+
		"authorize_session     %d\nauthorize_command     %d\ndistinct ctx_id       %d\n```\n\n",
		r.redeems, r.fresh, r.replayed, r.denied, r.sessAuthz, r.cmdAuthz, len(r.ctxIDs))
	if len(r.denials) > 0 {
		fmt.Fprintf(&b, "Denials, verbatim from the log:\n\n```\n%s\n```\n\n", strings.Join(r.denials, "\n"))
	}
	fmt.Fprintf(&b, "**Inferred** from the authentication count, not measured — the capture holds no HTTPS or "+
		"SSH bytes: %s\n\n", clientWireInference(r))
	fmt.Fprintf(&b, "What the client printed:\n\n```\n%s\n```\n\n", strings.TrimRight(clientTail(r.out), "\n"))
	return b.String()
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
	b.WriteString("| client | job completed | TACACS+ authentications per 10 tasks | fresh / replayed | " +
		"single-use token survived the job | wire, inferred |\n|---|---|---|---|---|---|\n")
	for _, r := range rs {
		done := "**no**"
		survived := "—"
		if r.ok {
			done = "yes"
			survived = "**yes**"
			if r.denied > 0 {
				survived = fmt.Sprintf("yes, with %d denial(s)", r.denied)
			}
		} else if r.denied > 0 {
			survived = "**no**"
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
		fmt.Fprintf(&b, "| %s | %s | **%d** | %d / %d | %s | %s |\n",
			r.spec.name, done, r.redeems, r.fresh, r.replayed, survived, wire)
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

	for _, rec := range l.drainRecords(off, 10*time.Second) {
		sess := sub(rec, "session")
		if id := str(sess, "ctx_id"); id != "" {
			r.ctxIDs[id] = true
		}
		switch str(rec, "event") {
		case "redeem":
			r.redeems++
			switch str(rec, "reason") {
			case "token_redeemed":
				r.fresh++
			case "receipt_replayed":
				r.replayed++
			}
			if str(rec, "verdict") == "deny" {
				r.denied++
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
			what: "Ten worker threads against one device as one user. **This is the `(nas, username)` " +
				"login-context key under its accepted worst case**: ten concurrent logins sharing one " +
				"context. What port49 logs, and whether any session is refused, is the finding.",
			timeout: 8 * time.Minute,
			script: pyPreamble + `
from nornir import InitNornir
from nornir_netmiko.tasks import netmiko_send_command
import yaml, tempfile, os
hosts = {"leaf1": {"hostname": HOST, "username": USER, "password": PASS,
                   "platform": "arista_eos",
                   "connection_options": {"netmiko": {"extras": {"fast_cli": False}}}}}
d = tempfile.mkdtemp()
open(os.path.join(d, "hosts.yaml"), "w").write(yaml.safe_dump(hosts))
open(os.path.join(d, "groups.yaml"), "w").write("{}\n")
nr = InitNornir(runner={"plugin": "threaded", "options": {"num_workers": 10}},
                inventory={"plugin": "SimpleInventory",
                           "options": {"host_file": os.path.join(d, "hosts.yaml"),
                                       "group_file": os.path.join(d, "groups.yaml")}},
                logging={"enabled": False})
# Ten separate task runs against the one host, so ten workers really do open
# ten sessions rather than one worker running ten commands on one.
for i in range(N):
    res = nr.run(task=netmiko_send_command, command_string="show hostname")
    for h, r in res.items():
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
