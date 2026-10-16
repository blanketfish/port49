//go:build lab

package lab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestL64EndedReadsAnEndThatLeftAnOrphanAsAbnormal: a command that exits non-zero while a descendant still holds
// its output pipes is not a normal end (review M8): Go's Wait returns the ExitError and drops ErrWaitDelay, so
// the pipes' state is passed in.
func TestL64EndedReadsAnEndThatLeftAnOrphanAsAbnormal(t *testing.T) {
	exit3 := exec.Command("sh", "-c", "exit 3").Run()
	var ee *exec.ExitError
	if !errors.As(exit3, &ee) {
		t.Fatalf("setup: %v", exit3)
	}
	boom := errors.New("fork failed")
	cases := []struct {
		name     string
		wait     error
		ctx      error
		held     bool
		wantExit int
		wantErr  string // a substring, "" for none
	}{
		{"a clean end", nil, nil, false, 0, ""},
		{"a non-zero exit", exit3, nil, false, 3, ""},
		{"a clean exit that left an orphan", nil, nil, true, 0, "held its output"},
		{"a non-zero exit that left an orphan", exit3, nil, true, 3, "held its output"},
		{"another error passes through", boom, nil, false, 0, "fork failed"},
		{"the deadline", exit3, context.DeadlineExceeded, false, -1, "deadline"},
	}
	for _, c := range cases {
		exit, err := l64Ended(c.wait, c.ctx, c.held, "x")
		if c.name != "the deadline" && exit != c.wantExit {
			t.Errorf("%s: exit %d, want %d", c.name, exit, c.wantExit)
		}
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: error %v, want none", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: error %v, want one naming %q", c.name, err, c.wantErr)
		}
	}
	if _, err := l64Ended(exit3, context.DeadlineExceeded, false, "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the deadline's error does not wrap it: %v", err)
	}
}

func TestL64RunSeesAnOrphanHoldingThePipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	// The shell exits 3 at once; the sleep it left behind keeps the pipes open.
	out, _, exit, err := l64RunGrace(ctx, 300*time.Millisecond, nil, t.TempDir(), "sh", "-c", "echo before; sleep 30 & exit 3")
	if time.Since(start) > 10*time.Second {
		t.Errorf("the orphan held the call for %s", time.Since(start))
	}
	if exit != 3 || err == nil || !strings.Contains(out, "before") {
		t.Errorf("exit %d err %v out %q, want 3, an error and the output", exit, err, out)
	}
	out, _, exit, err = l64RunGrace(ctx, 300*time.Millisecond, nil, t.TempDir(), "sh", "-c", "echo fine; exit 3")
	if exit != 3 || err != nil || !strings.Contains(out, "fine") {
		t.Errorf("a plain non-zero exit: exit %d err %v out %q", exit, err, out)
	}
}

// The orphan's process group is killed while the leader is still a zombie, unreaped, so its pgid cannot have
// been reused by then (9d minor N2).
func TestL64RunKillsTheOrphanGroupBeforeReapingTheLeader(t *testing.T) {
	var state string
	defer func(f func(int)) { l64BeforeOrphanKill = f }(l64BeforeOrphanKill)
	l64BeforeOrphanKill = func(pid int) {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			state = "reaped: " + err.Error()
			return
		}
		// "pid (comm) S ...": the state follows the last ")".
		state = strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, exit, err := l64RunGrace(ctx, 300*time.Millisecond, nil, t.TempDir(), "sh", "-c", "sleep 30 & exit 3")
	if state != "Z" {
		t.Errorf("the leader's state at the kill was %q, want Z (exited, not yet reaped)", state)
	}
	if exit != 3 || err == nil {
		t.Errorf("exit %d err %v, want 3 and an error for the orphan", exit, err)
	}
}

// The fixtures are OpenSSH 10.2p1's wording, from
// tests/ssh-compat/2026-10-13-openssh-accept-new.md: the Warning line of a
// filed key, the lines of a refused one, and ssh-keygen -F's output.

const l64Accepted = `debug1: Authenticated to 172.100.100.11 ([172.100.100.11]:22) using "keyboard-interactive".
Warning: Permanently added 'leaf1' (ED25519) to the list of known hosts.
`

const l64Changed = `debug1: Server host key: ssh-ed25519 SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
The fingerprint for the ED25519 key sent by the remote host is
SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG.
Please contact your system administrator.
Add correct host key in /h/.ssh/known_hosts to get rid of this message.
Offending ED25519 key in /h/.ssh/known_hosts:1
  remove with:
  ssh-keygen -f '/h/.ssh/known_hosts' -R 'leaf1'
Host key for leaf1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before leaf1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under leaf1 is not the one 172.100.100.11 presents: either the device's key changed, or the address inventory gives for leaf1 is not the device. Verify the key on its console, then run ssh-keygen -f '/h/.ssh/known_hosts' -R 'leaf1' and connect again
`

const l64OtherTypeErr = `debug1: Server host key: ssh-ed25519 SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
The fingerprint for the ED25519 key sent by the remote host is
SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG.
Offending ECDSA key in /h/.ssh/known_hosts:1
  remove with:
  ssh-keygen -f '/h/.ssh/known_hosts' -R 'leaf1'
Host key for leaf1 has changed and you have requested strict checking.
Host key verification failed.
`

const l64NoMatch = "Unable to negotiate with 172.100.100.11 port 22: no matching host key type found. Their offer: ssh-rsa\n"

func TestL64ReadsAnAcceptedKeyFromSSHsStderr(t *testing.T) {
	r := l64ReadSSH(l64Accepted)
	if r.Class != "accepted" {
		t.Errorf("class = %q, want accepted", r.Class)
	}
	if !slices.Equal(r.Added, []string{"ED25519"}) {
		t.Errorf("added = %v, want [ED25519]", r.Added)
	}
	if r.AuthenticatedBy != "keyboard-interactive" {
		t.Errorf("authenticated by %q", r.AuthenticatedBy)
	}
	if r.NamesKeygenR {
		t.Error("an accepted key's stderr names no ssh-keygen -R")
	}
}

func TestL64ReadsAChangedKeyAndWhereItNamesKeygen(t *testing.T) {
	r := l64ReadSSH(l64Changed)
	if r.Class != "changed" {
		t.Errorf("class = %q, want changed (the same type: ED25519 filed, ED25519 sent)", r.Class)
	}
	if !r.Banner || !r.VerifyFailed {
		t.Errorf("banner %v, verify failed %v: both are in the fixture", r.Banner, r.VerifyFailed)
	}
	if !r.NamesKeygenR {
		t.Error("ssh-keygen -f '...' -R 'leaf1' is in the fixture")
	}
	if r.FiledType != "ED25519" || r.SentType != "ED25519" {
		t.Errorf("filed %q, sent %q", r.FiledType, r.SentType)
	}
	if len(r.Added) != 0 {
		t.Errorf("added = %v: a refused key files nothing", r.Added)
	}
}

func TestL64ReadsAKeyOfAnotherTypeFromTheTypesTheNamesCarry(t *testing.T) {
	r := l64ReadSSH(l64OtherTypeErr)
	if r.Class != "other_type" {
		t.Errorf("class = %q, want other_type (ECDSA filed, ED25519 sent)", r.Class)
	}
	if r.FiledType != "ECDSA" || r.SentType != "ED25519" {
		t.Errorf("filed %q, sent %q", r.FiledType, r.SentType)
	}
}

func TestL64ReadsADeviceThatOffersNoFiledType(t *testing.T) {
	r := l64ReadSSH(l64NoMatch)
	if r.Class != "no_matching_host_key" {
		t.Errorf("class = %q, want no_matching_host_key", r.Class)
	}
}

func TestL64ReadsNothingWorryingFromAQuietRun(t *testing.T) {
	r := l64ReadSSH("debug1: Next authentication method: keyboard-interactive\n" +
		"debug1: Next authentication method: password\n")
	if r.Class != "clean" || r.VerifyFailed || r.Banner {
		t.Errorf("%+v", r)
	}
	if !slices.Equal(r.Methods, []string{"keyboard-interactive", "password"}) {
		t.Errorf("methods = %v", r.Methods)
	}
	if got := r.Asks(); got != 2 {
		t.Errorf("asks = %d, want 2: both methods ask the askpass", got)
	}
}

func TestL64CountsOutputLinesNotBlanks(t *testing.T) {
	if got := l64Lines(""); got != 0 {
		t.Errorf("empty output counts %d", got)
	}
	if got := l64Lines("a\n\n  \nb\n"); got != 2 {
		t.Errorf("counts %d, want 2", got)
	}
}

func TestL64FamilyOfAKeyTypeIsTheSameInEveryNaming(t *testing.T) {
	for in, want := range map[string]string{
		"ED25519": "ed25519", "ssh-ed25519": "ed25519", "ECDSA": "ecdsa", "ecdsa-sha2-nistp384": "ecdsa",
		"RSA": "rsa", "ssh-rsa": "rsa", "": "",
	} {
		if got := l64Family(in); got != want {
			t.Errorf("l64Family(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestL64CountsKnownHostsLinesNotCommentsOrBlanks(t *testing.T) {
	file := "# a comment\n\nleaf1 ssh-ed25519 AAAA\n|1|salt|hash ssh-rsa BBBB\n@revoked leaf1 ssh-rsa CCCC\n  \n"
	if got := l64KnownHostsLines(file); got != 3 {
		t.Errorf("lines = %d, want 3", got)
	}
	if got := l64KnownHostsLines(""); got != 0 {
		t.Errorf("an empty file has %d lines", got)
	}
}

func TestL64ReadsEveryLineSSHKeygenFindsWithItsType(t *testing.T) {
	out := "# Host leaf1 found: line 1\nleaf1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n" +
		"# Host leaf1 found: line 2\nleaf1 ecdsa-sha2-nistp256 AAAAE2VjZHNh\n" +
		"# Host leaf1 found: line 3\n|1|c2FsdA==|aGFzaA== ssh-rsa AAAAB3NzaC1yc2E\n"
	es := l64ParseKeygenF(out)
	if len(es) != 3 {
		t.Fatalf("entries = %d, want 3: %+v", len(es), es)
	}
	var types []string
	for _, e := range es {
		types = append(types, e.Type)
	}
	if !slices.Equal(types, []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}) {
		t.Errorf("types = %v: every line, not the first only", types)
	}
	if es[0].Hashed || !es[2].Hashed {
		t.Errorf("hashed: %v %v %v", es[0].Hashed, es[1].Hashed, es[2].Hashed)
	}
	if es[0].Blob != "AAAAC3NzaC1lZDI1NTE5" {
		t.Errorf("blob = %q", es[0].Blob)
	}
}

func TestL64KeygenFindsNothingForAnUnfiledName(t *testing.T) {
	if es := l64ParseKeygenF(""); len(es) != 0 {
		t.Errorf("entries = %+v", es)
	}
	if es := l64ParseKeygenF("@revoked leaf1 ssh-rsa CCCC\n"); len(es) != 1 || es[0].Marker != "@revoked" {
		t.Errorf("a marker line is an entry with its marker: %+v", es)
	}
}

func TestL64FreshKeysAreMadeOfTheFiledTypeAndTheOtherType(t *testing.T) {
	for typ, want := range map[string][]string{
		"ssh-ed25519":         {"-t", "ed25519"},
		"ecdsa-sha2-nistp256": {"-t", "ecdsa", "-b", "256"},
		"ecdsa-sha2-nistp521": {"-t", "ecdsa", "-b", "521"},
		"ssh-rsa":             {"-t", "rsa", "-b", "2048"},
	} {
		got, ok := l64KeygenArgs(typ)
		if !ok || !slices.Equal(got, want) {
			t.Errorf("l64KeygenArgs(%q) = %v, %v; want %v", typ, got, ok, want)
		}
	}
	if _, ok := l64KeygenArgs("ssh-dss"); ok {
		t.Error("ssh-dss is not a type the harness makes")
	}
	for filed, want := range map[string]string{
		"ssh-ed25519": "ssh-rsa", "ecdsa-sha2-nistp256": "ssh-rsa", "ssh-rsa": "ssh-ed25519", "ssh-dss": "ssh-ed25519",
	} {
		if got := l64OtherType(filed); got != want {
			t.Errorf("l64OtherType(%q) = %q, want %q", filed, got, want)
		}
	}
}

func TestL64PacketsInAWindowCountBothEnds(t *testing.T) {
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	pkts := []l29Packet{{at: at.Add(-time.Second)}, {at: at}, {at: at.Add(time.Second)}, {at: at.Add(2 * time.Second)},
		{at: at.Add(3 * time.Second)}}
	if got := l64PacketsIn(pkts, at, at.Add(2*time.Second)); got != 3 {
		t.Errorf("packets in [at, at+2s] = %d, want 3 (the ends count)", got)
	}
	if got := l64PacketsIn(nil, at, at.Add(time.Hour)); got != 0 {
		t.Errorf("no packets counted %d", got)
	}
}

func TestL64OtherRecordsAreEveryEventButMintAndBlob(t *testing.T) {
	recs := []map[string]any{{"event": "mint"}, {"event": "blob"}, {"event": "redeem"}, {"event": "mint"},
		{"event": "authorize_session"}}
	if got := l64OtherRecords(recs); !slices.Equal(got, []string{"redeem", "authorize_session"}) {
		t.Errorf("other = %v", got)
	}
	if got := l64Redeems(recs); got != 1 {
		t.Errorf("redeems = %d", got)
	}
}

func TestL64ReadsTheDriversOneLineAndNothingElse(t *testing.T) {
	out := "some noise\nP49RESULT {\"outcome\": \"connected\", \"output_lines\": 12, \"key_type\": \"ssh-ed25519\"}\n"
	d, ok := l64ParseDriver(out)
	if !ok || d.Outcome != "connected" || d.OutputLines != 12 || d.KeyType != "ssh-ed25519" {
		t.Errorf("%+v %v", d, ok)
	}
	d, ok = l64ParseDriver("P49RESULT {\"outcome\": \"port49_error\", \"error_class\": \"HostKeyError\", " +
		"\"code\": \"host_key_revoked\", \"text\": \"x\"}")
	if !ok || d.ErrorClass != "HostKeyError" || d.Code != "host_key_revoked" {
		t.Errorf("%+v %v", d, ok)
	}
	if _, ok := l64ParseDriver("Traceback (most recent call last):\n"); ok {
		t.Error("a traceback is not a result")
	}
	if _, ok := l64ParseDriver("P49RESULT {not json"); ok {
		t.Error("broken json is not a result")
	}
}

func TestL64TheConfigsKnownHostsFileIsThePrivateOne(t *testing.T) {
	sshG := "user alice\nhostname 172.100.100.11\nuserknownhostsfile /tmp/p49/.ssh/known_hosts\n" +
		"globalknownhostsfile /dev/null\n"
	if got := l64UserKnownHosts(sshG); !slices.Equal(got, []string{"/tmp/p49/.ssh/known_hosts"}) {
		t.Errorf("got %v", got)
	}
	// ssh's default: the real home's two files. The harness must refuse to run on it.
	def := "userknownhostsfile /home/u/.ssh/known_hosts /home/u/.ssh/known_hosts2\n"
	if got := l64UserKnownHosts(def); len(got) != 2 {
		t.Errorf("got %v", got)
	}
	if got := l64UserKnownHosts("user alice\n"); len(got) != 0 {
		t.Errorf("no line reads as no files, got %v", got)
	}
}

func TestL64ProgressLineIsOneLineForAWatchdog(t *testing.T) {
	got := l64Progress("arista_eos", "L64a", "PASS", 14250*time.Millisecond)
	want := "L64L65 arista_eos L64a PASS 14.3s"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestL64GradesAnSSHRefusal(t *testing.T) {
	refused := l64ReadSSH(l64Changed)
	if ok, why := l64GradeSSHRefusal(refused, 255, 0, nil); !ok {
		t.Errorf("a refusal with 0 packets and no records is the claim: %s", why)
	}
	for name, c := range map[string]struct {
		r       l64Stderr
		exit    int
		packets int
		other   []string
	}{
		"exit 0":       {refused, 0, 0, nil},
		"a packet":     {refused, 255, 1, nil},
		"a redeem":     {refused, 255, 0, []string{"redeem"}},
		"no -R advice": {l64ReadSSH("Host key verification failed.\n"), 255, 0, nil},
		"a filed key":  {l64ReadSSH(l64Accepted + "ssh-keygen -R x\n"), 255, 0, nil},
	} {
		if ok, _ := l64GradeSSHRefusal(c.r, c.exit, c.packets, c.other); ok {
			t.Errorf("%s: graded as the claim", name)
		}
	}
}

func TestL64GradesAPythonRefusal(t *testing.T) {
	d := l64Driver{Outcome: "port49_error", ErrorClass: "HostKeyError", Code: "host_key_changed"}
	if ok, why := l64GradePyRefusal(d, "", 0, nil); !ok {
		t.Errorf("HostKeyError, 0 packets, no records: %s", why)
	}
	if ok, why := l64GradePyRefusal(d, "host_key_changed", 0, nil); !ok {
		t.Errorf("the wanted code: %s", why)
	}
	if ok, _ := l64GradePyRefusal(d, "host_key_revoked", 0, nil); ok {
		t.Error("another code than the wanted one passed")
	}
	if ok, _ := l64GradePyRefusal(d, "", 2, nil); ok {
		t.Error("packets passed")
	}
	if ok, _ := l64GradePyRefusal(d, "", 0, []string{"redeem"}); ok {
		t.Error("a redeem passed")
	}
	if ok, _ := l64GradePyRefusal(l64Driver{Outcome: "connected"}, "", 0, nil); ok {
		t.Error("a connection passed as a refusal")
	}
	if ok, _ := l64GradePyRefusal(l64Driver{Outcome: "error", ErrorClass: "TimeoutError"}, "", 0, nil); ok {
		t.Error("a timeout passed as a HostKeyError")
	}
}

// C1: a refusal cell's zero means something only while the positive control holds.
func TestL64OutcomeTruthTable(t *testing.T) {
	for _, c := range []struct {
		name                                       string
		pass, timedOut, controlOK, refusal, unread bool
		want                                       string
	}{
		{"a pass", true, false, true, false, false, "PASS"},
		{"a refusal that passes with its control", true, false, true, true, false, "PASS"},
		{"a refusal that passes with the control failed", true, false, false, true, false, "INVALID"},
		{"a refusal that fails on packets, control failed", false, false, false, true, false, "FAIL"},
		{"a refusal whose count could not be read", false, false, true, true, true, "INVALID"},
		{"a refusal that passes yet the count was unread", true, false, true, true, true, "INVALID"},
		{"a refusal that fails with its control", false, false, true, true, false, "FAIL"},
		{"a non-refusal ignores the control", true, false, false, false, false, "PASS"},
		{"a non-refusal that fails", false, false, true, false, false, "FAIL"},
		{"a timeout", true, true, true, true, false, "TIMEOUT"},
	} {
		if got := l64Outcome(c.pass, c.timedOut, c.controlOK, c.refusal, c.unread); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestL64ControlNeedsPacketsAndARedeem(t *testing.T) {
	for _, c := range []struct {
		packets, redeems int
		want             bool
	}{{120, 1, true}, {0, 1, false}, {120, 0, false}, {-1, 1, false}, {-1, 0, false}} {
		if got := l64ControlOK(c.packets, c.redeems); got != c.want {
			t.Errorf("l64ControlOK(%d, %d) = %v", c.packets, c.redeems, got)
		}
	}
}

// I1: the absolute known_hosts path turns UpdateHostKeys off unless the config says so.
func TestL64CheckConfigRequiresThePrivateFileAndUpdateHostKeys(t *testing.T) {
	good := "userknownhostsfile /h/.ssh/known_hosts\nupdatehostkeys true\n"
	if err := l64CheckConfig(good, "/h/.ssh/known_hosts"); err != nil {
		t.Errorf("a good config refused: %v", err)
	}
	for name, g := range map[string]string{
		"updatehostkeys off": "userknownhostsfile /h/.ssh/known_hosts\nupdatehostkeys false\n",
		"no updatehostkeys":  "userknownhostsfile /h/.ssh/known_hosts\n",
		"the real file":      "userknownhostsfile /home/u/.ssh/known_hosts\nupdatehostkeys true\n",
		"two files":          "userknownhostsfile /h/.ssh/known_hosts /h/.ssh/known_hosts2\nupdatehostkeys true\n",
	} {
		if err := l64CheckConfig(g, "/h/.ssh/known_hosts"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// I3: lines are compared by type and key, never by the host field (a hashed salt differs each time).
func TestL64DiffComparesTypeAndBlobNotHost(t *testing.T) {
	a := l64Entry{Host: "leaf1", Type: "ssh-ed25519", Blob: "AAA"}
	b := l64Entry{Host: "|1|s|h", Hashed: true, Type: "ssh-rsa", Blob: "BBB"}
	c := l64Entry{Host: "leaf1", Type: "ssh-rsa", Blob: "CCC"}
	added, removed := l64Diff([]l64Entry{a, b}, []l64Entry{{Host: "|1|x|y", Type: "ssh-ed25519", Blob: "AAA"}, b})
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("the same keys under other host fields differ: +%v -%v", added, removed)
	}
	added, removed = l64Diff([]l64Entry{a, b}, []l64Entry{a, c})
	if len(added) != 1 || added[0].Blob != "CCC" || len(removed) != 1 || removed[0].Blob != "BBB" {
		t.Errorf("a secondary key that changed: +%v -%v", added, removed)
	}
	added, removed = l64Diff([]l64Entry{a}, []l64Entry{a, b})
	if len(added) != 1 || len(removed) != 0 {
		t.Errorf("a type that appeared: +%v -%v", added, removed)
	}
}

// A type first filed after the reload (UpdateHostKeys learning one more key on the first login that
// had a filed key, as EOS showed on 2026-10-14) is not a key that changed; a line gone, or a type
// filed before whose key is now another, is.
func TestL64ReloadChangedIsALostOrReplacedKeyNotANewType(t *testing.T) {
	ed := l64Entry{Host: "leaf1", Type: "ssh-ed25519", Blob: "AAA"}
	ec := l64Entry{Host: "leaf1", Type: "ecdsa-sha2-nistp521", Blob: "EEE"}
	ed2 := l64Entry{Host: "leaf1", Type: "ssh-ed25519", Blob: "ZZZ"}
	for _, tc := range []struct {
		name          string
		before, after []l64Entry
		want          bool
	}{
		{"unchanged", []l64Entry{ed}, []l64Entry{ed}, false},
		{"a new type learned", []l64Entry{ed}, []l64Entry{ed, ec}, false},
		{"the filed key replaced", []l64Entry{ed}, []l64Entry{ed2}, true},
		{"a second key of a filed type", []l64Entry{ed}, []l64Entry{ed, ed2}, true},
		{"a filed line gone", []l64Entry{ed, ec}, []l64Entry{ed}, true},
	} {
		if got := l64ReloadChanged(tc.before, tc.after); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// I4: the revoked line names the key the client negotiated, by the type the driver reported.
func TestL64PickEntryTakesTheLineOfTheNegotiatedType(t *testing.T) {
	es := []l64Entry{{Type: "ssh-rsa", Blob: "R"}, {Type: "ssh-ed25519", Blob: "E"}}
	if e, ok := l64PickEntry(es, "ssh-ed25519"); !ok || e.Blob != "E" {
		t.Errorf("%+v %v", e, ok)
	}
	if _, ok := l64PickEntry(es, "ecdsa-sha2-nistp256"); ok {
		t.Error("a type that is not filed was picked")
	}
	if _, ok := l64PickEntry(nil, "ssh-rsa"); ok {
		t.Error("nothing filed picked something")
	}
}

// I1: UpdateHostKeys may add key types after authentication; e2 grades the negotiated key's line.
func TestL64GradeE2LetsExtraTypesBeAnObservation(t *testing.T) {
	want := l64Entry{Type: "ssh-ed25519", Blob: "E"}
	clean := l64ReadSSH("debug1: Next authentication method: keyboard-interactive\n")
	same := []l64Entry{{Host: "|1|a|b", Type: "ssh-ed25519", Blob: "E"}}
	if ok, why := l64GradeE2(clean, 0, want, same); !ok {
		t.Errorf("unchanged line: %s", why)
	}
	extra := append(slices.Clone(same), l64Entry{Type: "ssh-rsa", Blob: "R"})
	if ok, why := l64GradeE2(clean, 0, want, extra); !ok {
		t.Errorf("an extra type is an observation, not a failure: %s", why)
	}
	for name, c := range map[string]struct {
		r     l64Stderr
		exit  int
		after []l64Entry
	}{
		"exit 255":        {clean, 255, same},
		"line gone":       {clean, 0, []l64Entry{{Type: "ssh-rsa", Blob: "R"}}},
		"line changed":    {clean, 0, []l64Entry{{Type: "ssh-ed25519", Blob: "OTHER"}}},
		"a key was filed": {l64ReadSSH(l64Accepted), 0, same},
	} {
		if ok, _ := l64GradeE2(c.r, c.exit, want, c.after); ok {
			t.Errorf("%s: passed", name)
		}
	}
}

// I7: the lines a watchdog reads.
func TestL64StartAndStageLines(t *testing.T) {
	if got, want := l64Start("juniper_vsrx", "L64b", 45*time.Minute), "L64L65 juniper_vsrx L64b START budget 45m0s"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := l64Stage("juniper_vsrx", "L64b", "seen down"), "L64L65 juniper_vsrx L64b STAGE seen down"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestL64KeyLinesShowUpdateHostKeysAtWork(t *testing.T) {
	got := l64KeyLines("debug1: client_input_hostkeys: searching /h/.ssh/known_hosts for leaf1\n" +
		"debug1: Learned new hostkey: RSA SHA256:abc\ndebug1: update_known_hosts: updating\ndebug1: unrelated\n")
	for _, want := range []string{"Learned new hostkey", "update_known_hosts", "client_input_hostkeys"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing from %q", want, got)
		}
	}
	if strings.Contains(got, "unrelated") {
		t.Errorf("kept %q", got)
	}
}

func TestL64AnExcerptKeepsOnlyTheLinesThatSayWhatSSHDecided(t *testing.T) {
	// A note's stderr excerpt keeps the lines that say what ssh decided, and drops the rest.
	got := l64KeyLines("debug1: Reading configuration data /x\ndebug1: Authenticated to h ([1.1.1.1]:22) using \"password\".\n" +
		"Warning: Permanently added 'leaf1' (ED25519) to the list of known hosts.\nOffending RSA key in /k:1\n")
	if strings.Contains(got, "Reading configuration") {
		t.Errorf("an unrelated line was kept: %q", got)
	}
	for _, want := range []string{"Authenticated to", "Permanently added", "Offending RSA key"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is missing from %q", want, got)
		}
	}
}
