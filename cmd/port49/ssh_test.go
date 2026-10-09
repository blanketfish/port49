package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hostkeys"
)

// sshTestBin is the system's OpenSSH, 8.5 or later, or the test is skipped:
// port49 ssh runs the real ssh, and the test box has 10.2p1.
func sshTestBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh on PATH: port49 ssh runs the system's OpenSSH")
	}
	v, err := sshVersion(p)
	if err != nil || !atLeast(v, minSSH) {
		t.Skipf("ssh is %v (%v): port49 ssh needs OpenSSH 8.5 or later", v, err)
	}
	return p
}

// sshRig is one port49 ssh run's world: an agent that answers each mint
// from items and its status from status, counting mints; the device's key
// pinned (unless pin is nil); an empty ssh_config; and the flags that reach
// them.
type sshRig struct {
	mints *atomic.Int32
	flags []string
	sock  string

	mu     sync.Mutex
	items  []api.MintItem // the nth mint answers items[n], the last one after that
	status agent.Status
}

// set makes the agent answer status, and, when items are given, the mints
// from them in turn.
func (r *sshRig) set(status agent.Status, items ...api.MintItem) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
	if len(items) > 0 {
		r.items = items
	}
}

func newSSHRig(t *testing.T, dev *deviceSSH, item api.MintItem, warn int, pin ssh.PublicKey) *sshRig {
	t.Helper()
	r := &sshRig{mints: new(atomic.Int32), items: []api.MintItem{item},
		status: agent.Status{CeilingWarningSeconds: warn}}
	r.sock = agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		r.mu.Lock()
		defer r.mu.Unlock()
		switch req.URL.Path {
		case "/token":
			n := int(r.mints.Add(1)) - 1
			_ = json.NewEncoder(w).Encode(r.items[min(n, len(r.items)-1)])
		case "/status":
			_ = json.NewEncoder(w).Encode(r.status)
		}
	}))
	dir := privateDir(t)
	known := filepath.Join(dir, "known_hosts")
	if pin != nil {
		if err := hostkeys.Pin(known, "leaf1", pin, false); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.flags = []string{"--socket", r.sock, "--ssh", sshTestBin(t), "--ssh-config", cfg, "--known-hosts", known,
		"--port", strconv.Itoa(dev.port)}
	return r
}

func (r *sshRig) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb lockedBuffer
	code := run(append(append([]string{"ssh"}, r.flags...), args...), &out, &errb)
	return code, out.String(), errb.String()
}

var sshPermit = api.MintItem{Device: "leaf1", Verdict: "permit", Address: "127.0.0.1", Platform: "arista_eos",
	Username: "alice", Login: "LOGINTOKEN"}

// tokenNowhere fails t if the minted token is in anything port49 ssh printed
// (Global Constraints).
func tokenNowhere(t *testing.T, printed ...string) {
	t.Helper()
	for _, s := range printed {
		if strings.Contains(s, "LOGINTOKEN") {
			t.Errorf("the token was printed: %q", s)
		}
	}
}

// The token reaches the device's own prompt, once, by either method, and the
// command after -- runs; the token is never printed.
func TestPortSSHLogsInWithTheTokenAndRunsTheCommand(t *testing.T) {
	for _, method := range []string{"keyboard-interactive", "password"} {
		dev := startDeviceSSH(t, []string{method}, "LOGINTOKEN", 0)
		r := newSSHRig(t, dev, sshPermit, 0, dev.key)
		code, out, errb := r.run(t, "leaf1", "--", "show", "version")
		if code != 0 || out != "ran: show version\n" || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" {
			t.Errorf("%s: code %d stdout %q stderr %q attempts %q", method, code, out, errb, dev.attempts())
		}
		tokenNowhere(t, out, errb)
	}
}

// The token is in the askpass's answer to ssh and nowhere else: not in ssh's
// argv, not in its environment, not on port49 ssh's stdout or stderr; and
// the askpass socket is gone once port49 ssh returns (Global Constraints). A
// fake ssh records its argv and environment, then runs the askpass as ssh
// would, with the device's prompt.
func TestTheTokenIsNeverInArgvOrTheEnvironment(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	dir := t.TempDir()
	at := func(name string) string { return filepath.Join(dir, name) }
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = -V ]; then echo 'OpenSSH_10.2p1, OpenSSL 3.5.5' >&2; exit 0; fi\n" +
		"printf '%s\\n' \"$@\" > '" + at("argv") + "'\n" +
		"env > '" + at("env") + "'\n" +
		"exec \"$SSH_ASKPASS\" \"alice@leaf1's password: \" > '" + at("answer") + "'\n"
	if err := os.WriteFile(at("ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = at("ssh")
	code, out, errb := r.run(t, "leaf1")
	read := func(name string) string {
		b, err := os.ReadFile(at(name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if answer := read("answer"); code != 0 || answer != "LOGINTOKEN\n" {
		t.Fatalf("code %d answer is the token: %v stderr %q", code, answer == "LOGINTOKEN\n", errb)
	}
	for name, s := range map[string]string{"argv": read("argv"), "environment": read("env")} {
		if strings.Contains(s, "LOGINTOKEN") {
			t.Errorf("the token is in ssh's %s", name)
		}
	}
	tokenNowhere(t, out, errb)
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(r.sock), "askpass-*.sock")); len(left) != 0 {
		t.Fatalf("the askpass socket outlived port49 ssh: %v", left)
	}
}

// A host presenting another key than the pin never sees the token: ssh stops
// at the key exchange, the askpass is never asked, and port49 ssh says how
// to re-pin (decision 42 ruling 7; Review Focus 1).
func TestAHostWithAnotherKeyNeverSeesTheToken(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive", "password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, testHostKey(t))
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || len(dev.attempts()) != 0 || !strings.Contains(errb, "Host key verification failed") ||
		!strings.Contains(errb, "so it was never sent") ||
		!strings.Contains(errb, "run 'port49 devices trust --replace leaf1'") {
		t.Fatalf("code %d stdout %q stderr %q attempts %q", code, out, errb, dev.attempts())
	}
	tokenNowhere(t, out, errb)
}

// With no pin, nothing is minted and ssh never starts (Review Focus 2).
func TestNoPinnedKeyMintsNothing(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil)
	code, _, errb := r.run(t, "leaf1")
	if code != 1 || r.mints.Load() != 0 || dev.connections() != 0 ||
		!strings.Contains(errb, "no host key is pinned for leaf1") {
		t.Fatalf("code %d mints %d conns %d stderr %q", code, r.mints.Load(), dev.connections(), errb)
	}
}

// No agent, an ended session, an unreachable broker: no ssh starts, and the
// agent's words say why (Review Focus 2).
func TestNoTokenNoSSH(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		body   any
		want   string
	}{
		"session over": {http.StatusGone, api.Error{Error: "session_over",
			Detail: "agent: the session is over; run `port49 login`"}, "the session is over"},
		"broker unreachable": {http.StatusBadGateway, api.Error{Error: "broker_error",
			Detail: "agent: the broker at https://b:8443 is unreachable: dial tcp: connection refused"}, "is unreachable"},
	} {
		dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
		r := newSSHRig(t, dev, sshPermit, 0, dev.key)
		r.flags[1] = agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_ = json.NewEncoder(w).Encode(c.body)
		}))
		code, _, errb := r.run(t, "leaf1")
		if code != 1 || dev.connections() != 0 || !strings.Contains(errb, c.want) {
			t.Errorf("%s: code %d conns %d stderr %q", name, code, dev.connections(), errb)
		}
	}
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	r.flags[1] = filepath.Join(t.TempDir(), "gone", "agent.sock")
	code, _, errb := r.run(t, "leaf1")
	if code != 1 || dev.connections() != 0 || !strings.Contains(errb, "port49 ssh: no agent at ") {
		t.Fatalf("no agent: code %d conns %d stderr %q", code, dev.connections(), errb)
	}
}

// A device that refuses the token and offers the other method is not sent a
// second or an empty password: port49 ssh ends the connection (decision 42
// ruling 10; Review Focus 3).
func TestTheTokenIsPresentedOnce(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive", "password"}, "", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" ||
		!strings.Contains(errb, "leaf1 asked for the password again after it was sent the token") {
		t.Fatalf("code %d attempts %q stderr %q", code, dev.attempts(), errb)
	}
	tokenNowhere(t, out, errb)
}

// A token that expired before the device asked for it is never sent: port49
// ssh mints once more through the agent and answers the prompt with that
// token, still once (decision 42 ruling 10; pre-flight I-3).
func TestATokenExpiredBeforeThePromptIsMintedAgain(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	stale, fresh := sshPermit, sshPermit
	stale.Login, stale.ExpiresAt = "STALETOKEN", time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	fresh.ExpiresAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, stale, 0, dev.key)
	r.set(agent.Status{}, stale, fresh)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || out != "ran: show version\n" || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" ||
		r.mints.Load() != 2 {
		t.Fatalf("code %d stdout %q stderr %q attempts %q mints %d", code, out, errb, dev.attempts(), r.mints.Load())
	}
	tokenNowhere(t, out, errb)
}

// With no fresh token to be had, nothing is sent, ssh is ended, and port49
// ssh says the token expired before the device asked, never that policy
// refused it.
func TestATokenExpiredBeforeThePromptIsNeverSent(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	stale := sshPermit
	stale.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, stale, 0, dev.key)
	r.set(agent.Status{}, stale, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || len(dev.attempts()) != 0 ||
		!strings.Contains(errb, "past its expires_at ("+stale.ExpiresAt+"), and a fresh mint answered deny no_grants_matched") ||
		strings.Contains(errb, "port49 explain") {
		t.Fatalf("code %d attempts %q stderr %q", code, dev.attempts(), errb)
	}
	tokenNowhere(t, out, errb)
}

// An OpenSSH older than 8.5 is refused before a mint: 8.4p1's
// keyboard-interactive prompt names no host (decision 42 ruling 10).
func TestAnOldOpenSSHIsRefusedBeforeAMint(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	old := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(old, []byte("#!/bin/sh\necho 'OpenSSH_8.4p1 Debian-5+deb11u3, OpenSSL 1.1.1w' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = old
	code, _, errb := r.run(t, "leaf1")
	if code != 1 || r.mints.Load() != 0 || !strings.Contains(errb, "is OpenSSH 8.4; port49 ssh needs 8.5 or later") {
		t.Fatalf("code %d mints %d stderr %q", code, r.mints.Load(), errb)
	}
}

// A port49 that ssh's children run, inheriting askpassEnv, is no command:
// given two or more arguments it says why rather than run one under port49
// ssh's socket (decision 42 ruling 10). Given one under ssh's askpass
// environment it is an askpass call, and askpassCall says so.
func TestAPort49UnderSSHIsNoCommand(t *testing.T) {
	t.Setenv(askpassEnv, filepath.Join(t.TempDir(), "askpass.sock"))
	t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	var out, errb bytes.Buffer
	if code := run([]string{"token", "leaf1"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unset "+askpassEnv) {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if _, ok := askpassCall([]string{"token", "leaf1"}); ok {
		t.Fatal("two arguments were taken for an askpass call")
	}
	if sock, ok := askpassCall([]string{"a prompt"}); !ok || sock == "" {
		t.Fatal("one argument under the askpass environment was not an askpass call")
	}
	t.Setenv("SSH_ASKPASS_REQUIRE", "")
	if _, ok := askpassCall([]string{"a prompt"}); ok {
		t.Fatal("an askpass call without SSH_ASKPASS_REQUIRE=force")
	}
}

// Within the ceiling warning at start, the warning comes before ssh runs
// (decision 42 ruling 11; Review Focus 5).
func TestTheCeilingWarningBeforeSSHStarts(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	item := sshPermit
	item.SessionExpiresAt = time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, item, 1800, dev.key)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || !strings.HasPrefix(errb, "port49: your session on leaf1 ends at "+item.SessionExpiresAt) {
		t.Fatalf("code %d stderr %q", code, errb)
	}
	tokenNowhere(t, out, errb)
}

// fastWarning makes the in-session warning's first timer fire after 300ms,
// whatever it was armed for, and any later one at its real time; it returns
// what each was armed for. The session's ceiling is hours out, so no margin
// of a busy -race run decides the test.
func fastWarning(t *testing.T) func() []time.Duration {
	t.Helper()
	var mu sync.Mutex
	var armed []time.Duration
	prev := sshAfterFunc
	sshAfterFunc = func(d time.Duration, f func()) *time.Timer {
		mu.Lock()
		defer mu.Unlock()
		armed = append(armed, d)
		if len(armed) == 1 {
			return time.AfterFunc(300*time.Millisecond, f)
		}
		return time.AfterFunc(d, f)
	}
	t.Cleanup(func() { sshAfterFunc = prev })
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(armed)
	}
}

// A session that outlives the warning's moment gets the warning on the
// terminal at it, once (decision 42 ruling 11; Review Focus 5).
func TestTheCeilingWarningComesInSession(t *testing.T) {
	armed := fastWarning(t)
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 3*time.Second)
	item := sshPermit
	item.SessionExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, item, 3600, dev.key)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Count(errb, "\r\nport49: your session on leaf1 ends at "+item.SessionExpiresAt) != 1 {
		t.Fatalf("code %d stderr %q", code, errb)
	}
	if a := armed(); len(a) != 1 || a[0] < 59*time.Minute || a[0] > time.Hour {
		t.Fatalf("armed %v, want once, an hour before the ceiling", a)
	}
	tokenNowhere(t, out, errb)
}

// A port49 refresh in another terminal moves the ceiling: when the warning
// is due, the agent's last refresh says so, and the warning waits for the
// new moment instead of naming the old one (decision 42 ruling 11;
// pre-flight I-2).
func TestARefreshInSessionMovesTheWarning(t *testing.T) {
	armed := fastWarning(t)
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 3*time.Second)
	item := sshPermit
	item.SessionExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(5 * time.Hour).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, item, 3600, dev.key)
	r.set(agent.Status{CeilingWarningSeconds: 3600, Sessions: []api.RefreshedSession{
		{Device: "spine1", Username: "alice", Outcome: "extended", SessionExpires: later},
		{Device: "leaf1", Username: "alice", Outcome: "extended", SessionExpires: later},
	}})
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Contains(errb, "your session on leaf1 ends at") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
	if a := armed(); len(a) != 2 || a[1] < 3*time.Hour+59*time.Minute || a[1] > 4*time.Hour {
		t.Fatalf("armed %v, want a second time, an hour before the new ceiling", a)
	}
	tokenNowhere(t, out, errb)
}

// The askpass answers the device's own prompt with the token once, a second
// own prompt never, and any other prompt from the terminal (decision 42
// ruling 10).
func TestAskpassAnswersTheDevicesPromptOnce(t *testing.T) {
	dir, err := os.MkdirTemp("", "p49a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var killed atomic.Int32
	srv := &askpassServer{ln: ln, token: "LOGINTOKEN", username: "alice", device: "leaf1"}
	srv.setKill(func() { killed.Add(1) })
	go srv.serve()
	t.Cleanup(func() { ln.Close() })
	prev := askTerminal
	askTerminal = func(prompt string, stdout, _ io.Writer) int {
		_, _ = io.WriteString(stdout, "JUMPPASS\n")
		return 0
	}
	t.Cleanup(func() { askTerminal = prev })
	ask := func(prompt string) (int, string) {
		var out, errb strings.Builder
		code := askpassMain(sock, []string{prompt}, &out, &errb)
		return code, out.String()
	}
	if code, out := ask("bob@jump's password: "); code != 0 || out != "JUMPPASS\n" {
		t.Fatalf("a jump host's prompt: %d %q", code, out)
	}
	if code, out := ask("(alice@leaf1) Password: "); code != 0 || out != "LOGINTOKEN\n" {
		t.Fatalf("the device's prompt: %d %v", code, out == "LOGINTOKEN\n")
	}
	if code, out := ask("alice@leaf1's password: "); code != 1 || out != "" || killed.Load() != 1 {
		t.Fatalf("the device's prompt again: %d %q, killed %d", code, out, killed.Load())
	}
	if code := askpassMain(sock, nil, io.Discard, io.Discard); code != 1 {
		t.Fatal("no prompt was answered")
	}
}

func TestOwnPrompt(t *testing.T) {
	for prompt, own := range map[string]bool{
		"alice@leaf1's password: ":       true,
		"(alice@leaf1) Password: ":       true,
		"(alice@leaf1) Enter token: ":    true,
		"alice@leaf10's password: ":      false,
		"(alice@leaf10) Password: ":      false,
		"bob@leaf1's password: ":         false,
		"alice@jump's password: ":        false,
		"Enter passphrase for key 'x': ": false,
	} {
		if ownPrompt(prompt, "alice", "leaf1") != own {
			t.Errorf("ownPrompt(%q) = %v", prompt, !own)
		}
	}
}

// A yes/no question is answered with echo on, a password never.
func TestAskEchoes(t *testing.T) {
	for _, c := range []struct {
		prompt, hint string
		echo         bool
	}{
		{"Are you sure you want to continue connecting (yes/no/[fingerprint])? ", "", true},
		{"Allow use of key /home/alice/.ssh/id_ed25519?", "confirm", true},
		{"bob@jump's password: ", "", false},
	} {
		if askEchoes(c.prompt, c.hint) != c.echo {
			t.Errorf("askEchoes(%q, %q) = %v", c.prompt, c.hint, !c.echo)
		}
	}
}

// SSH_ASKPASS_PROMPT=none is OpenSSH's notification hint: ssh shows it, later
// kills the askpass, and never reads an answer. The askpass writes the prompt
// to the terminal and returns at once: it reads nothing, touches no echo, and
// does not ask port49 ssh (R-N1).
func TestAnAskpassNotificationIsShownAndNeverRead(t *testing.T) {
	t.Setenv("SSH_ASKPASS_PROMPT", "none")
	var shown []string
	prevNotify := notifyTerminal
	notifyTerminal = func(prompt string, _ io.Writer) { shown = append(shown, prompt) }
	t.Cleanup(func() { notifyTerminal = prevNotify })
	prevAsk := askTerminal
	askTerminal = func(string, io.Writer, io.Writer) int {
		t.Error("a notification was asked of the terminal for an answer")
		return 1
	}
	t.Cleanup(func() { askTerminal = prevAsk })
	var out, errb strings.Builder
	// No socket is listening: a notification does not reach for one.
	sock := filepath.Join(t.TempDir(), "none.sock")
	if code := askpassMain(sock, []string{"Confirm user presence for key ED25519 SHA256:x"}, &out, &errb); code != 0 ||
		out.Len() != 0 || len(shown) != 1 || shown[0] != "Confirm user presence for key ED25519 SHA256:x" {
		t.Fatalf("code %d stdout %q stderr %q shown %q", code, out.String(), errb.String(), shown)
	}
}

// The command line forces what decision 42 ruling 10 lists, in this order;
// the destination follows --. The file's path and the address are quoted,
// with % doubled, since ssh expands % tokens and splits on whitespace there.
func TestSSHArgs(t *testing.T) {
	got := sshArgs(sshOptions{config: "/c", knownHosts: "/k", device: "leaf1", address: "10.0.0.1", username: "alice",
		port: 2222, verbose: true, command: []string{"show", "version"}})
	want := `-F /c -o HostName="10.0.0.1" -o HostKeyAlias=leaf1 -o UserKnownHostsFile="/k" ` +
		"-o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o CheckHostIP=no " +
		"-o VerifyHostKeyDNS=no -o KnownHostsCommand=none -o PubkeyAuthentication=no " +
		"-o PreferredAuthentications=keyboard-interactive,password -o KbdInteractiveAuthentication=yes " +
		"-o PasswordAuthentication=yes -o NumberOfPasswordPrompts=1 -o BatchMode=no -o ControlMaster=no " +
		"-o ControlPath=none -o ForwardAgent=no -v -l alice -p 2222 -- leaf1 show version"
	if strings.Join(got, " ") != want {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
	odd := sshArgs(sshOptions{knownHosts: "/home/a b/%d/known_hosts", device: "leaf1", address: "fe80::1%eth0",
		username: "alice"})
	if s := strings.Join(odd, " "); !strings.Contains(s, `-o HostName="fe80::1%%eth0"`) ||
		!strings.Contains(s, `-o UserKnownHostsFile="/home/a b/%%d/known_hosts"`) {
		t.Fatalf("got %s", s)
	}
}
