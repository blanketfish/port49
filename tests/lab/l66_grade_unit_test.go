//go:build lab

package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The ssh debug logs below are real: OpenSSH_10.2p1 (Ubuntu), run on this host with the options Ansible's
// ssh plugin gives it (ControlMaster=auto, ControlPersist, a ControlPath, a private UserKnownHostsFile,
// HostKeyAlias=<name>, StrictHostKeyChecking=accept-new, LogLevel=DEBUG3, -E <file>) against a throwaway
// sshd on 127.0.0.1 (key login, to get a master) and against the L66 stand-in on 127.0.0.1 (every login
// refused). Lines were taken verbatim from `-E` files and the long ones left out; nothing here is from a lab
// device.

// l66SSHFirst is the first of two names at one address: a new connection that authenticated and filed its key
// under its alias.
const l66SSHFirst = `debug1: OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026
debug1: auto-mux: Trying existing master at '/tmp/p49fx.ghkL/1696919fd39b81d5b3c90b205cbe261f7122f1a2'
debug1: Control socket "/tmp/p49fx.ghkL/1696919fd39b81d5b3c90b205cbe261f7122f1a2" does not exist
debug1: Connection established.
debug1: using hostkeyalias: l66a
debug1: load_hostkeys: fopen /tmp/p49fx.ghkL/kh: No such file or directory
debug1: Server host key: ssh-ed25519 SHA256:DA6NdD1/zTxSARapcKIeefK5575vCXSu/j2jezFKih8
debug1: using hostkeyalias: l66a
debug1: load_hostkeys: fopen /tmp/p49fx.ghkL/kh: No such file or directory
Warning: Permanently added 'l66a' (ED25519) to the list of known hosts.
Authenticated to 127.0.0.1 ([127.0.0.1]:2298) using "publickey".
`

// l66SSHSecond is the second name at the same address, which found the first's master. It never connected,
// never looked its alias up and filed nothing.
const l66SSHSecond = `debug1: OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026
debug1: auto-mux: Trying existing master at '/tmp/p49fx.ghkL/1696919fd39b81d5b3c90b205cbe261f7122f1a2'
debug2: fd 4 setting O_NONBLOCK
debug2: mux_client_hello_exchange: master version 4
debug3: mux_client_forwards: request forwardings: 0 local, 0 remote
debug3: mux_client_request_session: entering
debug3: mux_client_request_alive: entering
debug3: mux_client_request_alive: done pid = 4140045
debug3: mux_client_request_session: session request sent
debug1: mux_client_request_session: master session id: 2
debug2: Received exit status from master 0
`

// l66SSHRefused is a new connection to the stand-in under the name l66b: no master existed, the key was filed
// under the alias, and the login was refused.
const l66SSHRefused = `debug1: auto-mux: Trying existing master at '/tmp/p49fx.PG2h/37ec4802dc27d24771429e2bf12236bccd84df6f'
debug1: Control socket "/tmp/p49fx.PG2h/37ec4802dc27d24771429e2bf12236bccd84df6f" does not exist
debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2299.
debug1: Connection established.
debug1: using hostkeyalias: l66b
debug1: using hostkeyalias: l66b
Warning: Permanently added 'l66b' (ED25519) to the list of known hosts.
debug1: Authentications that can continue: password,publickey,keyboard-interactive
u@127.0.0.1: Permission denied (password,publickey,keyboard-interactive).
`

func TestL66ReadAliasSeesANewConnectionFileItsKeyUnderTheAlias(t *testing.T) {
	a := l66ReadAlias(l66SSHFirst, "l66a")
	if !a.Connected || a.Muxed || !a.Authenticated || !a.AliasUsed || !a.Filed {
		t.Errorf("first = %+v", a)
	}
	if j := strings.Join(a.Lines, "\n"); !strings.Contains(j, "using hostkeyalias: l66a") || !strings.Contains(j, "Permanently added 'l66a'") {
		t.Errorf("lines = %q", a.Lines)
	}
}

func TestL66ReadAliasSeesASecondNameReuseTheMasterAndNeverLookItsAliasUp(t *testing.T) {
	b := l66ReadAlias(l66SSHSecond, "l66b")
	if !b.Muxed || b.Connected || b.Authenticated || b.AliasUsed || b.Filed || len(b.Lines) != 0 {
		t.Errorf("second = %+v", b)
	}
}

func TestL66ReadAliasIsNotFooledByATriedMasterThatIsNotThere(t *testing.T) {
	// "auto-mux: Trying existing master" is printed whether or not there is one: the socket not existing is the
	// tell, and a connection that was refused was still a new connection.
	r := l66ReadAlias(l66SSHRefused, "l66b")
	if r.Muxed || !r.Connected || r.Authenticated || !r.AliasUsed || !r.Filed {
		t.Errorf("refused = %+v", r)
	}
}

func TestL66ReadAliasDoesNotCountAnotherNamesAlias(t *testing.T) {
	r := l66ReadAlias(l66SSHFirst, "l66b")
	if r.AliasUsed || r.Filed || len(r.Lines) != 0 {
		t.Errorf("l66a's lines are not l66b's: %+v", r)
	}
}

func TestL66GradeNamesRefusesALogThatCannotShowAnything(t *testing.T) {
	good := map[string]string{"l66a": l66SSHFirst, "l66b": l66SSHSecond}
	if why := l66GradeNames(good); why != "" {
		t.Errorf("two debug logs: %q", why)
	}
	if why := l66GradeNames(map[string]string{"l66a": l66SSHFirst, "l66b": ""}); !strings.Contains(why, "l66b") {
		t.Errorf("an empty log names its host: %q", why)
	}
	if why := l66GradeNames(map[string]string{"l66a": l66SSHFirst, "l66b": "Warning: Permanently added\n"}); !strings.Contains(why, "l66b") {
		t.Errorf("a log with no debug1 line shows nothing about the lookup: %q", why)
	}
	if why := l66GradeNames(nil); why == "" {
		t.Error("no logs at all measured nothing")
	}
}

func TestL66ChangedKeyErrorIsTheClientsOwnWording(t *testing.T) {
	cases := []struct {
		typ, text string
		want      bool
	}{
		{"libssh", "Failed to connect: Host key for server has changed: abc", true},
		{"libssh", "ssh connection failed: Host key type for server has changed: abc", true},
		{"libssh", "Host is unknown: abc", false},
		{"libssh", "Failed to connect: Connection timed out", false},
		{"libssh", "BadHostKeyException: Host key for server '10.0.0.1' does not match", false},
		{"paramiko", "BadHostKeyException: Host key for server '10.0.0.1' does not match: got 'AAAA', expected 'BBBB'", true},
		{"paramiko", "Host key for server '10.0.0.1' does not match: got 'AAAA'", true},
		{"paramiko", "Unable to connect to port 22: timed out", false},
		{"paramiko", "Host key for server has changed: abc", false},
		{"other", "Host key for server has changed", false},
	}
	for _, c := range cases {
		if got := l66ChangedKeyError(c.typ, c.text); got != c.want {
			t.Errorf("l66ChangedKeyError(%s, %q) = %v, want %v", c.typ, c.text, got, c.want)
		}
	}
}

func TestL66GradeChangedNeedsEveryPartOfTheRefusal(t *testing.T) {
	ok := l66ChangedIn{SSHType: "libssh", Failed: true, ErrText: "Host key for server has changed: x"}
	if pass, why := l66GradeChanged(ok); !pass || why != "" {
		t.Fatalf("a refused play with no packet, no redeem and the client's own words: %v %q", pass, why)
	}
	cases := []struct {
		name string
		mut  func(*l66ChangedIn)
		want string
	}{
		{"the play passed", func(i *l66ChangedIn) { i.Failed = false }, "did not fail"},
		{"packets went to port49", func(i *l66ChangedIn) { i.Packets = 3 }, "TACACS+ packets"},
		{"a redeem was recorded", func(i *l66ChangedIn) { i.Redeems = 1 }, "redeem"},
		{"another record was written", func(i *l66ChangedIn) { i.Other = []string{"authorize_command"} }, "records other than"},
		{"the failure was a timeout", func(i *l66ChangedIn) { i.ErrText = "Connection timed out" }, "changed host key"},
		{"no error text at all", func(i *l66ChangedIn) { i.ErrText = "" }, "changed host key"},
	}
	for _, c := range cases {
		in := ok
		c.mut(&in)
		pass, why := l66GradeChanged(in)
		if pass || !strings.Contains(why, c.want) {
			t.Errorf("%s: pass=%v why=%q, want a failure naming %q", c.name, pass, why, c.want)
		}
	}
}

func TestL66GradeDeniedNeedsEveryPartOfTheDenial(t *testing.T) {
	ok := l66DeniedIn{Failed: true, Named: true, GoodRunGood: true, MintDenies: 1}
	if pass, why := l66GradeDenied(ok); !pass || why != "" {
		t.Fatalf("a denied device and a clean -vvv: %v %q", pass, why)
	}
	cases := []struct {
		name string
		mut  func(*l66DeniedIn)
		want string
	}{
		{"the task passed", func(i *l66DeniedIn) { i.Failed = false }, "did not fail"},
		{"no_grants_matched not in the output", func(i *l66DeniedIn) { i.Named = false }, "no_grants_matched"},
		{"no deny record", func(i *l66DeniedIn) { i.MintDenies = 0 }, "mint deny"},
		{"a token in the denied run's output", func(i *l66DeniedIn) { i.DeniedHits = []int{4} }, "token"},
		{"a token in the good run's output", func(i *l66DeniedIn) { i.GoodHits = []int{9} }, "token"},
		{"the good run was not good", func(i *l66DeniedIn) { i.GoodRunGood = false }, "good run"},
		{"packets in the denied window", func(i *l66DeniedIn) { i.DeniedPackets = 2 }, "TACACS+ packets"},
		{"another record in the denied window", func(i *l66DeniedIn) { i.Other = []string{"redeem"} }, "records other than"},
	}
	for _, c := range cases {
		in := ok
		c.mut(&in)
		pass, why := l66GradeDenied(in)
		if pass || !strings.Contains(why, c.want) {
			t.Errorf("%s: pass=%v why=%q, want a failure naming %q", c.name, pass, why, c.want)
		}
	}
}

const l66PersistLog = `2026-10-14 jsonrpc request: {"jsonrpc": "2.0", "method": "set_options", "id": "1", "params": {"direct": {"x": 1}}}
2026-10-14 some other line
2026-10-14 jsonrpc request: {"jsonrpc": "2.0", "method": "exec_command", "id": "2", "params": ["show version"]}
`

func TestL66JSONRPCCountsRequestsAndSeesSetOptions(t *testing.T) {
	n, so := l66JSONRPC(l66PersistLog)
	if n != 2 || !so {
		t.Errorf("= %d %v", n, so)
	}
	n, so = l66JSONRPC("jsonrpc request: {\"method\": \"exec_command\"}\njsonrpc response: {}\n")
	if n != 1 || so {
		t.Errorf("a response is not a request, and no set_options: %d %v", n, so)
	}
	if n, _ := l66JSONRPC(""); n != 0 {
		t.Errorf("empty log: %d", n)
	}
}

func TestL66TheLogSearchPlaysHaveAtLeastThreeTasks(t *testing.T) {
	// The first task starts the persistent process and sets its options in-process; only a later task sends
	// set_options, with the password, over the socket, where `persistent_log_messages` logs it.
	if l66LogTasks < 3 {
		t.Errorf("l66LogTasks = %d", l66LogTasks)
	}
	if got := strings.Count(l66Playbook("once", l66Platforms["arista_eos"], l66LogTasks, ""), "eos_command"); got != l66LogTasks {
		t.Errorf("the log-search play has %d command tasks, want %d", got, l66LogTasks)
	}
}

func TestL66GradeLogSearchNeedsALogThatCouldHaveLeaked(t *testing.T) {
	ok := l66LogSearchIn{RunGood: true, Log: l66PersistLog}
	if pass, inv, why := l66GradeLogSearch(ok); !pass || inv != "" || why != "" {
		t.Fatalf("a good run, a log with the jsonrpc traffic and no hit: %v %q %q", pass, inv, why)
	}
	for name, mut := range map[string]func(*l66LogSearchIn){
		"a hit in stdout":  func(i *l66LogSearchIn) { i.OutHits = []int{3} },
		"a hit in stderr":  func(i *l66LogSearchIn) { i.ErrHits = []int{3} },
		"a hit in the log": func(i *l66LogSearchIn) { i.LogHits = []int{1} },
	} {
		in := ok
		mut(&in)
		if pass, inv, why := l66GradeLogSearch(in); pass || inv != "" || why == "" {
			t.Errorf("%s: pass=%v invalid=%q why=%q: a leak is a FAIL, not INVALID", name, pass, inv, why)
		}
	}
	for name, mut := range map[string]func(*l66LogSearchIn){
		"the run was not good":     func(i *l66LogSearchIn) { i.RunGood = false },
		"an empty log":             func(i *l66LogSearchIn) { i.Log = "" },
		"one jsonrpc request only": func(i *l66LogSearchIn) { i.Log = "jsonrpc request: {\"method\": \"set_options\"}\n" },
		"two requests, no set_options": func(i *l66LogSearchIn) {
			i.Log = "jsonrpc request: {\"method\": \"a\"}\njsonrpc request: {\"method\": \"b\"}\n"
		},
	} {
		in := ok
		mut(&in)
		if pass, inv, _ := l66GradeLogSearch(in); pass || inv == "" {
			t.Errorf("%s: pass=%v invalid=%q: a search of a log that could not have held it proves nothing", name, pass, inv)
		}
	}
}

func TestL66GradeMovedNeedsTheStandinToHaveBeenReached(t *testing.T) {
	known := map[string]bool{"aaa": true}
	r2 := map[string]bool{"bbb": true}
	if inv, p := l66GradeMoved(l66StandinTally{Connects: 1, Passwords: 1, Hashes: []string{"bbb"}}, known, r2); inv != "" || !p {
		t.Errorf("a password that is step 2's token: %q %v", inv, p)
	}
	if inv, p := l66GradeMoved(l66StandinTally{Connects: 1, Kbdint: 1, Hashes: []string{"aaa"}}, known, nil); inv != "" || !p {
		t.Errorf("a token the run's other windows named, with step 2's mint missed by the drain: %q %v", inv, p)
	}
	if inv, p := l66GradeMoved(l66StandinTally{Connects: 2, Hashes: nil}, known, r2); inv != "" || p {
		t.Errorf("reached, no attempt: a real zero: %q %v", inv, p)
	}
	if inv, p := l66GradeMoved(l66StandinTally{Connects: 1, Passwords: 1, Hashes: []string{"zzz"}}, known, r2); inv != "" || p {
		t.Errorf("an attempt that is not any known token: %q %v", inv, p)
	}
	if inv, _ := l66GradeMoved(l66StandinTally{}, known, r2); inv == "" {
		t.Error("the stand-in never saw a connection: nothing was measured")
	}
	if inv, _ := l66GradeMoved(l66StandinTally{Connects: 1, Passwords: 1, Hashes: []string{"zzz"}}, nil, nil); inv == "" {
		t.Error("attempts, but no token hash known at all: the comparison cannot be made")
	}
}

func TestL66GradeGapIsALoginAgain(t *testing.T) {
	for _, c := range []struct {
		starts, redeems int
		want            bool
	}{{1, 1, false}, {2, 1, true}, {1, 2, true}, {0, 0, false}, {3, 3, true}} {
		if got := l66GradeGap(c.starts, c.redeems); got != c.want {
			t.Errorf("l66GradeGap(%d, %d) = %v, want %v", c.starts, c.redeems, got, c.want)
		}
	}
}

func TestL66ParamikoRefusedMarkersReadsInvalidHostKey(t *testing.T) {
	if !l66ParamikoRefusedMarkers("paramiko.hostkeys.InvalidHostKey: ('@revoked unrelated.l66.invalid ssh-ed25519 AAAA', Error('Incorrect padding'))") {
		t.Error("InvalidHostKey")
	}
	if l66ParamikoRefusedMarkers("Unable to connect to port 22: timed out") {
		t.Error("a timeout is not the markers")
	}
}

// l66AnsibleMarkerError is what Ansible prints when paramiko 5.0 loads a known_hosts file with an @revoked
// line: str(paramiko.hostkeys.InvalidHostKey), which netcommon returns as the task's message. Produced with
// the venv's paramiko 5.0 on a scratch file in a scratch HOME (HostKeys().load), key shortened.
const l66AnsibleMarkerError = `fatal: [leaf1]: FAILED! => {"changed": false, "msg": "('@revoked unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFpE4Ds9AoeMvg03iBi/EzHvoGYtH2hxs1RBuMFxHLHt', Error('Incorrect padding'))"}`

func TestL66ParamikoRefusedMarkersReadsWhatAnsiblePrints(t *testing.T) {
	if !l66ParamikoRefusedMarkers(l66AnsibleMarkerError) {
		t.Error("the repr of an InvalidHostKey is the marker refusal")
	}
	if !l66ParamikoRefusedMarkers(`"msg": "('@cert-authority *.unrelated.l66.invalid ssh-ed25519 AAAA', Error('Incorrect padding'))"`) {
		t.Error("an @cert-authority line is refused the same way")
	}
	for _, no := range []string{"host key mismatch for 172.100.100.11", "Unable to connect to port 22: timed out",
		`"msg": "('@revoked x ssh-ed25519 AAAA'` /* no decode error: not this failure */} {
		if l66ParamikoRefusedMarkers(no) {
			t.Errorf("%q is not the marker refusal", no)
		}
	}
}

func TestL66ChangedKeyErrorKnowsNetcommonsParamikoWording(t *testing.T) {
	// netcommon 8.7.0 catches BadHostKeyException and raises AnsibleConnectionFailure("host key mismatch for %s").
	if !l66ChangedKeyError("paramiko", `"msg": "host key mismatch for 172.100.100.11"`) {
		t.Error("netcommon's paramiko wording")
	}
	if l66ChangedKeyError("libssh", "host key mismatch for 172.100.100.11") {
		t.Error("libssh's refusal is pylibssh's own words, not netcommon's paramiko ones")
	}
	if l66ChangedKeyError("paramiko", "Authentication failed.") {
		t.Error("an unrelated failure")
	}
}

func TestL66RunPlayStopsAtOnceWhenTheOperatorsFileWasWritten(t *testing.T) {
	e := &l66Env{fatal: "the operator's own known_hosts was written"}
	r, err := e.runPlay(context.Background(), "x", "once", 1, "", l66InvSpec{}, l66Opts{})
	if err == nil || !strings.Contains(err.Error(), "operator's own") || r.stdout != "" {
		t.Errorf("a run that has found the operator's file written starts no further play: %v %+v", err, r)
	}
}

func TestL66GradeStepOneAllowsNotRunOnlyForAMeasuredClientBehaviour(t *testing.T) {
	cases := []struct {
		name string
		in   l66StepOneIn
		want string
	}{
		{"logged in and filed a key", l66StepOneIn{Passed: true, LoggedIn: true, Filed: 1}, "ok"},
		{"filed a key and logged in though the command failed", l66StepOneIn{LoggedIn: true, Filed: 1}, "ok"},
		{"filed a key but never logged in", l66StepOneIn{Passed: true, Filed: 1}, "invalid"},
		{"passed, logged in, no key, and its own cell measured that", l66StepOneIn{Passed: true, LoggedIn: true, MeasuredNoFile: true}, "not run"},
		{"passed, logged in, no key, never measured elsewhere", l66StepOneIn{Passed: true, LoggedIn: true}, "invalid"},
		{"the play failed (docker, network, device) and filed nothing", l66StepOneIn{MeasuredNoFile: true}, "invalid"},
		{"the play passed but no login reached port49d", l66StepOneIn{Passed: true, MeasuredNoFile: true}, "invalid"},
		{"nothing at all", l66StepOneIn{}, "invalid"},
	}
	for _, c := range cases {
		if got, why := l66GradeStepOne(c.in); got != c.want || (got != "ok" && why == "") {
			t.Errorf("%s: = %q (%q), want %q with a reason", c.name, got, why, c.want)
		}
	}
}

// TestL66PlayEndIsInvalidUnlessAnsiblePlaybookEndedOnItsOwn: lab run 2 graded L66e-ssh OBSERVED on vJunos while
// its step 1 had hung until the play's deadline (exit -1, an empty recap). A run that was ended (the deadline, a
// signal, a process that could not be waited on) or that printed no PLAY RECAP never ran its play to an end, so
// whatever a cell reads from it is not a measurement. An exit of 2 or 4 is Ansible's own verdict and is read.
func TestL66PlayEndIsInvalidUnlessAnsiblePlaybookEndedOnItsOwn(t *testing.T) {
	deadline := fmt.Errorf("ansible-playbook was ended at the cell's deadline: %w", context.DeadlineExceeded)
	cases := []struct {
		name       string
		exit       int
		err        error
		recapHosts int
		want       []string // "" for a normal end; otherwise words the reason holds
	}{
		{"passed", 0, nil, 1, nil},
		{"a task failed: Ansible's verdict, read by the cell", 2, nil, 1, nil},
		{"unreachable: Ansible's verdict, read by the cell", 4, nil, 2, nil},
		{"the vJunos hang: ended at the deadline, no recap", -1, deadline, 0, []string{"step-1", "ended abnormally", "deadline"}},
		{"ended at the deadline after its recap was printed", -1, deadline, 1, []string{"ended abnormally", "deadline"}},
		{"killed by a signal from elsewhere", -1, nil, 0, []string{"killed by a signal", "exit -1"}},
		{"killed by a signal after its recap", -1, nil, 1, []string{"killed by a signal"}},
		{"the process could not be waited on", 0, exec.ErrWaitDelay, 1, []string{"ended abnormally", "WaitDelay"}},
		{"no PLAY RECAP: the play never ran to an end", 1, nil, 0, []string{"no PLAY RECAP", "exit 1"}},
		{"exit 0 and no recap", 0, nil, 0, []string{"no PLAY RECAP"}},
	}
	for _, c := range cases {
		got := l66PlayEnd("step-1", c.exit, c.err, c.recapHosts)
		if len(c.want) == 0 {
			if got != "" {
				t.Errorf("%s: = %q, want a normal end", c.name, got)
			}
			continue
		}
		if got == "" {
			t.Errorf("%s: read as a normal end, want INVALID", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", c.name, got, w)
			}
		}
	}
}

// TestL66AnAbnormalPlayMakesItsCellInvalidWhateverItsGrader: whatever a cell's own grader made of a run, a play
// that did not end on its own leaves the cell INVALID (the vJunos L66e-ssh row was OBSERVED), and no note is
// written for the run.
func TestL66AnAbnormalPlayMakesItsCellInvalidWhateverItsGrader(t *testing.T) {
	why := l66PlayEnd("L66e-ssh-device", -1, fmt.Errorf("ansible-playbook was ended at the cell's deadline: %w",
		context.DeadlineExceeded), 0)
	for _, kind := range []string{"claim", "refusal", "record"} {
		for _, ok := range []bool{true, false} {
			graded := l66Outcome(kind, ok, false, true, false)
			got := l66Settle(graded, "", why, "", false)
			if got != "INVALID" {
				t.Errorf("%s ok=%v: graded %s, settled %s, want INVALID", kind, ok, graded, got)
			}
			if w, _ := l66Writable([]l66Result{{id: "L66e-ssh", outcome: got}}); w {
				t.Errorf("%s ok=%v: a run with that cell writes a note", kind, ok)
			}
		}
	}
}

func TestL66SettleLetsInvalidAndFatalOutrankNotRun(t *testing.T) {
	cases := []struct {
		outcome, fatal, invalid, notRun string
		unread                          bool
		want                            string
	}{
		{"PASS", "", "", "", false, "PASS"},
		{"FAIL", "", "", "", false, "FAIL"},
		{"FAIL", "", "", "no key", false, "NOT RUN (no key)"},
		{"FAIL", "", "docker is down", "no key", false, "INVALID"},
		{"PASS", "wrote the real file", "", "no key", false, "INVALID"},
		{"INVALID", "", "", "", false, "INVALID"},
		{"TIMEOUT", "", "", "y", false, "TIMEOUT"},
		// A cell whose budget ran out while a play ran: the play was ended at the deadline, so it measured nothing.
		{"TIMEOUT", "", "ansible-playbook was ended at the cell's deadline", "", false, "INVALID"},
		{"TIMEOUT", "wrote the real file", "", "", false, "INVALID"},
		// A count that could not be read is INVALID alone (review M11, rr2 M2): it does not lose to NOT RUN.
		{"INVALID", "", "", "no key", true, "INVALID"},
		{"FAIL", "", "", "no key", true, "INVALID"},
		{"FAIL", "", "", "", true, "INVALID"},
	}
	for _, c := range cases {
		if got := l66Settle(c.outcome, c.fatal, c.invalid, c.notRun, c.unread); got != c.want {
			t.Errorf("l66Settle(%q, fatal=%q, invalid=%q, notRun=%q, unread=%v) = %q, want %q", c.outcome, c.fatal, c.invalid,
				c.notRun, c.unread, got, c.want)
		}
	}
}

// TestL66AFirstContactThatEndedAbnormallyNeverMeasuredNoFile: a play that passed and redeemed but did not end on
// its own (it was killed, or printed no recap) says nothing about whether the client files a key (review M7).
func TestL66AFirstContactThatEndedAbnormallyNeverMeasuredNoFile(t *testing.T) {
	cases := []struct {
		name           string
		passed         bool
		redeems, added int
		end            string
		want           bool
	}{
		{"passed, redeemed, filed nothing", true, 1, 0, "", true},
		{"filed a line", true, 1, 1, "", false},
		{"no redeem", true, 0, 0, "", false},
		{"did not pass", false, 1, 0, "", false},
		{"ended abnormally", true, 1, 0, "the play L66c-libssh was killed by a signal (exit -1), so it measured nothing", false},
	}
	for _, c := range cases {
		if got := l66NoFile(c.passed, c.redeems, c.added, c.end); got != c.want {
			t.Errorf("%s: l66NoFile = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestL66AFirstContactPlayThatDiedBeforeConnectingIsInvalidNotFail: a claim cell whose play ran no task, or
// whose mint was not permitted, never reached the device, so FAIL would blame the client (review M10).
func TestL66AFirstContactPlayThatDiedBeforeConnectingIsInvalidNotFail(t *testing.T) {
	cases := []struct {
		name                       string
		recapOK, mints, mintDenies int
		wantWhy                    bool
	}{
		{"ran, minted", 2, 1, 0, false},
		{"ran, minted, one denied too", 2, 2, 1, false},
		{"no task succeeded", 0, 1, 0, true},
		{"no mint record", 2, 0, 0, true},
		{"every mint denied", 2, 1, 1, true},
		{"nothing at all", 0, 0, 0, true},
	}
	for _, c := range cases {
		got := l66FirstContactNeverConnected(c.recapOK, c.mints, c.mintDenies)
		if (got != "") != c.wantWhy {
			t.Errorf("%s: l66FirstContactNeverConnected = %q, want a reason: %v", c.name, got, c.wantWhy)
		}
	}
}

// TestL66RedeemsOfMintedCountsOnlyTokensTheWindowMinted: c2's FAIL text says each redeem carries the hash of a
// token this run minted, so the count must be that (review M11, rr2 M1).
func TestL66RedeemsOfMintedCountsOnlyTokensTheWindowMinted(t *testing.T) {
	mint := func(h string) map[string]any {
		return map[string]any{"event": "mint", "mint": map[string]any{"token_sha256": []any{h}}}
	}
	redeem := func(h string) map[string]any {
		return map[string]any{"event": "redeem", "auth": map[string]any{"credential_sha256": h}}
	}
	cases := []struct {
		name string
		recs []map[string]any
		want int
	}{
		{"none", nil, 0},
		{"a redeem of a minted token", []map[string]any{mint("aa"), redeem("aa")}, 1},
		{"a redeem of another token", []map[string]any{mint("aa"), redeem("bb")}, 0},
		{"two of three", []map[string]any{mint("aa"), mint("bb"), redeem("aa"), redeem("bb"), redeem("cc")}, 2},
		{"a redeem with no mint in the window", []map[string]any{redeem("aa")}, 0},
	}
	for _, c := range cases {
		if got := l66RedeemsOfMinted(c.recs); got != c.want {
			t.Errorf("%s: l66RedeemsOfMinted = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestL66PreflightEnvIsThePrivateEnvOfItsOwnDir(t *testing.T) {
	pre := t.TempDir()
	t.Setenv("ANSIBLE_HOME", "/real/.ansible")
	env := l66PreflightEnv(os.Environ(), pre, "/l/nss.so")
	for _, w := range []string{"HOME=" + pre, "LD_PRELOAD=/l/nss.so", "NSS_WRAPPER_PASSWD=" + pre + "/nss_passwd",
		"NSS_WRAPPER_GROUP=" + pre + "/nss_group", "PYTHONDONTWRITEBYTECODE=1"} {
		if !slices.Contains(env, w) {
			t.Errorf("preflight env lacks %s", w)
		}
	}
	if slices.Contains(env, "HOME="+os.Getenv("HOME")) && os.Getenv("HOME") != pre {
		t.Error("the preflight runs in the real HOME")
	}
	if slices.Contains(env, "ANSIBLE_HOME=/real/.ansible") {
		t.Error("an inherited ANSIBLE_HOME reached the preflight")
	}
}

func TestL66CellCapIsTheDefaultForL66aAndRaisedForEveryOtherCell(t *testing.T) {
	if got := l66CellCap("L66a"); got != 0 {
		t.Errorf("L66a measures the cap, so it runs under the default: %d", got)
	}
	for _, id := range []string{"L66b", "L66b2-idle", "L66b2-reset", "L66d", "L66d2", "L66c1-libssh", "L66e-ssh", "L66e2"} {
		if got := l66CellCap(id); got != l48CandidateCap {
			t.Errorf("%s runs under cap %d, want the raised %d", id, got, l48CandidateCap)
		}
	}
	if l48CandidateCap <= l48DefaultCandidateCap {
		t.Error("the raised cap is not above the default")
	}
}

func TestL66CapConfigAddsOneTokenBlockOrNone(t *testing.T) {
	base := "listen: x\nbroker:\n  listen: y\n"
	if got, err := l66CapConfig(base, 0); err != nil || got != base {
		t.Errorf("cap 0 leaves the default: %q %v", got, err)
	}
	got, err := l66CapConfig(base, 64)
	if err != nil || !strings.HasPrefix(got, base) || !strings.Contains(got, "\ntoken: {candidate_cap: 64}\n") {
		t.Errorf("cap 64: %q %v", got, err)
	}
	if _, err := l66CapConfig("listen: x\ntoken: {candidate_cap: 3}\n", 64); err == nil {
		t.Error("a base with its own token block would be a duplicate key")
	}
}

func TestL66CapNoteStatesTheCap(t *testing.T) {
	if n := l66CapNote(0); !strings.Contains(n, "default") || !strings.Contains(n, "8") {
		t.Errorf("default: %q", n)
	}
	if n := l66CapNote(64); !strings.Contains(n, "64") || !strings.Contains(n, "raised") {
		t.Errorf("raised: %q", n)
	}
}

func TestL66MintRefusedByCapReadsTheFirstMintOnly(t *testing.T) {
	mint := func(verdict, reason string) map[string]any {
		return map[string]any{"event": "mint", "verdict": verdict, "reason": reason}
	}
	other := map[string]any{"event": "redeem", "reason": "candidate_cap_reached"}
	cases := []struct {
		name string
		recs []map[string]any
		want bool
	}{
		{"none", nil, false},
		{"a good first mint", []map[string]any{mint("permit", "")}, false},
		{"first mint refused by the cap", []map[string]any{mint("deny", "candidate_cap_reached")}, true},
		{"cap reached only later (L66a's own measurement)", []map[string]any{mint("permit", ""), mint("deny", "candidate_cap_reached")}, false},
		{"a redeem before it is not a mint", []map[string]any{other, mint("permit", "")}, false},
		{"another denial first", []map[string]any{mint("deny", "no_grant")}, false},
	}
	for _, c := range cases {
		if got := l66MintRefusedByCap(c.recs); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestL66GradeCapIsTheMeasurementWhenTheControlHolds(t *testing.T) {
	counts := func(mints, denies, redeems int) l66Counts {
		c := l66Counts{Mints: mints, MintDenies: denies, Redeems: redeems, MintReasons: map[string]int{}, RedeemReasons: map[string]int{}}
		if denies > 0 {
			c.MintReasons["candidate_cap_reached"] = denies
		}
		return c
	}
	cases := []struct {
		name     string
		in       l66CapIn
		outcome  string
		failedAt int
		want     []string
	}{
		// The 72a29169 eos run: two mints per evaluation, then three more and the refused tenth, at task 8.
		{"the eos run: refused at task 8 after two mints per evaluation",
			l66CapIn{Recap: l66Recap{OK: 7, Failed: 1}, Counts: counts(10, 1, 1), Starts: 1, ConnLookups: 2}, "PASS", 8,
			[]string{"fails at task 8 with candidate_cap_reached", "10 mint records (1 denied)", "8 tasks attempted (7 ok, 1 failed",
				"1.25 mint records per task attempted", "1 redeem", "1 TACACS+ authentication start", "2 lookups",
				"token.candidate_cap of 8"}},
		{"refused at task 3",
			l66CapIn{Recap: l66Recap{OK: 2, Failed: 1}, Counts: counts(9, 1, 1), Starts: 1, ConnLookups: 2}, "PASS", 3,
			[]string{"task 3", "3 tasks attempted", "3.00 mint records per task attempted"}},
		{"all ten passed, and the counts leave the cap unreached",
			l66CapIn{Recap: l66Recap{OK: 10}, Counts: counts(9, 0, 1), Starts: 1, ConnLookups: 2}, "PASS", 0,
			[]string{"all 10 tasks passed", "9 mint records", "10 tasks attempted", "0.90 mint records per task attempted"}},
		{"all ten passed with more unspent tokens than the cap allows: contradicts the cap",
			l66CapIn{Recap: l66Recap{OK: 10}, Counts: counts(20, 0, 1), Starts: 1, ConnLookups: 2}, "INVALID", 0,
			[]string{"contradicts", "at least 19", "20 mint records"}},
		{"passed but not ten tasks",
			l66CapIn{Recap: l66Recap{OK: 6}, Counts: counts(6, 0, 1), Starts: 1, ConnLookups: 2}, "INVALID", 0,
			[]string{"6 ok", "ten"}},
		{"failed for another reason, control held",
			l66CapIn{Recap: l66Recap{OK: 4, Failed: 1}, Counts: counts(5, 0, 1), Starts: 1, ConnLookups: 2}, "PASS", 5,
			[]string{"task 5", "not the cap", "5 tasks attempted"}},
		{"a cap denial, but the recap does not show one failed task: no task number is claimed",
			l66CapIn{Recap: l66Recap{OK: 4, Unreachable: 1}, Counts: counts(9, 1, 1), Starts: 1, ConnLookups: 2}, "PASS", 0,
			[]string{"candidate_cap_reached", "does not show", "unreachable"}},
		{"no task passed: no good login to be the control",
			l66CapIn{Recap: l66Recap{Failed: 1}, Counts: counts(1, 0, 0), Starts: 0, ConnLookups: 2}, "INVALID", 0, []string{"control"}},
		{"tasks passed but no redeem was recorded",
			l66CapIn{Recap: l66Recap{OK: 3, Failed: 1}, Counts: counts(4, 1, 0), Starts: 1, ConnLookups: 2}, "INVALID", 0, []string{"control"}},
		{"tasks passed but no TACACS+ start was seen",
			l66CapIn{Recap: l66Recap{OK: 3, Failed: 1}, Counts: counts(4, 1, 1), Starts: 0, ConnLookups: 2}, "INVALID", 0, []string{"control"}},
		{"the very first mint was refused by the cap: the store was not fresh",
			l66CapIn{Recap: l66Recap{OK: 9, Failed: 1}, Counts: counts(10, 1, 1), Starts: 1, FirstMintRefused: true, ConnLookups: 2},
			"INVALID", 0, []string{"fresh"}},
	}
	for _, c := range cases {
		outcome, at, text := l66GradeCap(c.in)
		if outcome != c.outcome || at != c.failedAt {
			t.Errorf("%s: %s at %d, want %s at %d (%s)", c.name, outcome, at, c.outcome, c.failedAt, text)
		}
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s: text lacks %q: %s", c.name, w, text)
			}
		}
		// The reading states what was counted, never a per-task rate it did not measure.
		for _, never := range []string{"once per task", "a mint for each task"} {
			if strings.Contains(text, never) {
				t.Errorf("%s: text claims %q: %s", c.name, never, text)
			}
		}
	}
}

func TestL66ConnLookupsCountsTheLookupsInTheConnectionVariables(t *testing.T) {
	s := l66InvSpec{Hosts: []l66Host{{"leaf1", "172.100.100.11"}}, Platform: l66Platforms["arista_eos"], Conn: "network_cli", SSHType: "libssh"}
	s.Mode = "lookup"
	if got := l66ConnLookups(l66Inventory(s)); got != 2 {
		t.Errorf("lookup inventory: %d lookups, want 2 (ansible_user and ansible_password)", got)
	}
	s.Mode = "fact"
	if got := l66ConnLookups(l66Inventory(s)); got != 0 {
		t.Errorf("fact inventory: %d lookups, want 0", got)
	}
}

func TestL66CommentKHIsACommentAlone(t *testing.T) {
	c := l66CommentKH()
	if !strings.HasPrefix(c, "# ") || strings.Count(c, "\n") != 1 || strings.Contains(c, "@") || len(l66ParseKH(c)) != 0 {
		t.Errorf("comment baseline = %q", c)
	}
}

func TestL66NSSFilesGiveTheUserThePrivateHome(t *testing.T) {
	p := l66NSSPasswd("ryan", 1000, 1000, "/w/home", "/bin/sh")
	var mine []string
	for _, ln := range strings.Split(strings.TrimSpace(p), "\n") {
		f := strings.Split(ln, ":")
		if len(f) != 7 {
			t.Fatalf("a passwd line has seven fields: %q", ln)
		}
		if f[2] == "1000" {
			mine = f
		}
	}
	if mine == nil || mine[0] != "ryan" || mine[5] != "/w/home" || mine[6] != "/bin/sh" || mine[3] != "1000" {
		t.Errorf("passwd = %q", p)
	}
	if !strings.Contains(p, "root:x:0:0:") {
		t.Errorf("root is in the file too: %q", p)
	}
	g := l66NSSGroup("ryan", 1000)
	if !strings.Contains(g, "ryan:x:1000:") {
		t.Errorf("group = %q", g)
	}
}

func TestL66FindNSSWrapperLooksUnderEachDir(t *testing.T) {
	dir := t.TempDir()
	if _, ok := l66FindNSSWrapper([]string{dir}); ok {
		t.Error("an empty dir has no wrapper")
	}
	lib := filepath.Join(dir, "libnss_wrapper.so")
	if err := os.WriteFile(lib, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := l66FindNSSWrapper([]string{"/nonexistent-l66", dir}); !ok || got != lib {
		t.Errorf("= %q %v", got, ok)
	}
}

func TestL66AnsibleEnvRunsUnderNSSWrapperWithTheAskpassMechanism(t *testing.T) {
	t.Setenv("ANSIBLE_STDOUT_CALLBACK", "json") // the operator's own Ansible settings never reach a play
	e := &l66Env{l64Env: &l64Env{home: "/w/home"}, work: "/w", collDir: "/w/coll", nssLib: "/usr/lib/x/libnss_wrapper.so"}
	env := e.ansibleEnv(l66Opts{})
	want := []string{"LD_PRELOAD=/usr/lib/x/libnss_wrapper.so", "NSS_WRAPPER_PASSWD=/w/nss_passwd", "NSS_WRAPPER_GROUP=/w/nss_group",
		"ANSIBLE_SSH_PASSWORD_MECHANISM=ssh_askpass", "HOME=/w/home", "ANSIBLE_HOST_KEY_CHECKING=False"}
	for _, w := range want {
		if !slices.Contains(env, w) {
			t.Errorf("env lacks %s", w)
		}
	}
	if slices.Contains(env, "ANSIBLE_STDOUT_CALLBACK=json") {
		t.Error("an inherited ANSIBLE_* variable reached the play")
	}
	for _, kv := range env {
		if strings.Contains(kv, "sshpass") {
			t.Errorf("sshpass is not used: %s", kv)
		}
	}
	if kh := e.ansibleEnv(l66Opts{hostKeys: true}); !slices.Contains(kh, "ANSIBLE_HOST_KEY_CHECKING=True") || !slices.Contains(kh, "ANSIBLE_HOST_KEY_AUTO_ADD=True") {
		t.Error("hostKeys turns checking and auto-add on")
	}
}

func TestL66PreflightAndPlaysShareOnePrivateHomeNeverTheRealOne(t *testing.T) {
	real := os.Getenv("HOME")
	t.Setenv("ANSIBLE_HOME", real+"/.ansible") // an inherited Ansible setting must not survive
	home := t.TempDir()
	pre := l66PrivateEnv(os.Environ(), home, "/l/nss.so", home+"/pw", home+"/gr")
	e := &l66Env{l64Env: &l64Env{home: home}, work: home, nssLib: "/l/nss.so"}
	play := e.ansibleEnv(l66Opts{})
	getenv := func(env []string, k string) (v string, n int) {
		for _, kv := range env {
			if strings.HasPrefix(kv, k+"=") {
				v, n = strings.TrimPrefix(kv, k+"="), n+1
			}
		}
		return
	}
	for name, env := range map[string][]string{"preflight": pre, "play": play} {
		h, n := getenv(env, "HOME")
		if n != 1 || h != home || h == real {
			t.Errorf("%s: HOME = %q (%d times), want the private %q and not %q", name, h, n, home, real)
		}
		if lp, n := getenv(env, "LD_PRELOAD"); n != 1 || lp != "/l/nss.so" {
			t.Errorf("%s: LD_PRELOAD = %q (%d times)", name, lp, n)
		}
		if p, _ := getenv(env, "NSS_WRAPPER_PASSWD"); !strings.HasPrefix(p, home) {
			t.Errorf("%s: NSS_WRAPPER_PASSWD = %q", name, p)
		}
	}
	if _, n := getenv(pre, "ANSIBLE_HOME"); n != 0 {
		t.Error("an inherited ANSIBLE_HOME reached the preflight")
	}
}

func TestL66CellBudgetStopsBeforeTheTestsDeadline(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	want, reserve, min := 10*time.Minute, 5*time.Minute, 2*time.Minute
	if b, ok := l66CellBudget(want, time.Time{}, false, now, reserve, min); !ok || b != want {
		t.Errorf("no deadline: %v %v", b, ok)
	}
	if b, ok := l66CellBudget(want, now.Add(60*time.Minute), true, now, reserve, min); !ok || b != want {
		t.Errorf("plenty of time: %v %v", b, ok)
	}
	if b, ok := l66CellBudget(want, now.Add(12*time.Minute), true, now, reserve, min); !ok || b != 7*time.Minute {
		t.Errorf("12 min left, 5 kept for teardown: %v %v", b, ok)
	}
	if _, ok := l66CellBudget(want, now.Add(6*time.Minute), true, now, reserve, min); ok {
		t.Error("6 min left leaves 1 min after the reserve, less than a cell needs")
	}
	if _, ok := l66CellBudget(want, now.Add(-time.Minute), true, now, reserve, min); ok {
		t.Error("past the deadline")
	}
}
