// The L60 session harness (spec §15 L60; tests/lab/results/L60-ser8.md, "Open
// cells"): one Go test per open cell, each gated by its own environment
// variable and run from Ryan's own terminal, as the touch probes were. RUNBOOK.md
// in this directory is the order they run in.
//
// The harness drives port49 as an operator does: it builds the client binary
// (the hwkey_dlopen build) and runs `port49 login`, `token`, `refresh` as
// child processes on Ryan's terminal, against a broker it serves in-process.
// A PIN goes from Ryan's keyboard straight to port49's own prompt on /dev/tty,
// or from a pin-source file Ryan made (PORT49_L60_PIN_SOURCE, whose path alone
// the harness passes on): the harness never prints one, and reads one only in
// cell (e)'s last step, where port49's own opener logs in with the pin-source
// file inside the test process to read a physical pull's return code. A
// token `port49 token` prints is read from its stdout and only its length is
// said.
//
// Every observation is one line, `L60 <cell> <field>: <value>`, in the test
// log (run with -v) and appended to observations.log in the lab directory, for
// the results note. A device serial is masked in both.

package l60

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/hwkey/serialmask"
	"github.com/blanketfish/port49/internal/testpki"
)

// The environment the cells read. Each cell has its own gate.
const (
	envDir       = "PORT49_L60_DIR"        // the lab directory; default <user cache>/port49-l60
	envModule    = "PORT49_L60_MODULE"     // default defaultModule
	envPINSource = "PORT49_L60_PIN_SOURCE" // a file holding the PIN, made by Ryan, 0600
	envRoots     = "PORT49_L60_YUBICO_ROOTS"
	envStatusN   = "PORT49_L60_STATUS_N"

	gateImport = "PORT49_L60_IMPORT"
	gateB      = "PORT49_L60_B"
	gateD      = "PORT49_L60_D"
	gateE      = "PORT49_L60_E"
	gateE2     = "PORT49_L60_E2"
	gateF      = "PORT49_L60_F"
	gateFLock  = "PORT49_L60_FLOCK"
	gateStatus = "PORT49_L60_STATUS"
	gateCOrder = "PORT49_L60_C_ORDER"
	gateSelf   = "PORT49_L60_SELFTEST"
)

const defaultModule = "/usr/lib/x86_64-linux-gnu/libykcs11.so"

// The PIV slots' CKA_IDs under libykcs11 (L60-ser8.md, cell (c)).
const (
	slot9a = "01" // PIN once, touch never: the session key
	slot9c = "02" // PIN once, touch always: the touch key
)

// labEmail is the identity the lab certificates carry and the policy grants.
const labEmail = "alice@example.com"

// Files in the lab directory. It outlives a run: the CA that signs the
// certificate imported into slot 9a must be the one a later run's broker
// trusts. Nothing here is secret beyond the lab CA's own key.
const (
	fileCA       = "client-ca.pem"
	fileCAKey    = "client-ca-key.pem"
	fileSlotCert = "slot9a.pem"
	fileObs      = "observations.log"
)

// Per-step deadlines.
const (
	cmdDeadline   = 60 * time.Second // a port49 command no person waits on
	typedDeadline = 3 * time.Minute  // a command that asks Ryan to type
	handDeadline  = 3 * time.Minute  // a pull, a re-insertion, an Enter
	touchDeadline = 60 * time.Second // a mint that waits on a touch
)

// gate skips t unless its variable is 1.
func gate(t *testing.T, name, what string) {
	t.Helper()
	if os.Getenv(name) != "1" {
		t.Skipf("set %s=1 and run from a terminal (%s); see tests/lab/l60/RUNBOOK.md", name, what)
	}
}

// lab is one cell's run: Ryan's terminal, the client binary, the agents it
// started, and where the observations go.
type lab struct {
	t       *testing.T
	study   string // the register entry the observations belong to: "L60", or "L86" (l86_test.go)
	cell    string
	dir     string    // the lab directory
	tty     *os.File  // nil in the self-test, which asks nothing
	out     io.Writer // what Ryan sees: the terminal
	saved   *term.State
	bin     string
	home    string // the children's HOME
	module  string
	mu      sync.Mutex
	agents  map[string]int // socket -> agent pid
	obsFile *os.File
	broker  *labBroker // the cell's broker, whose refresh pacing a refresh steps past
	// onKill is what a killed cell also undoes (the lab lock, Keycloak): the
	// signal guard (l86Guard) runs it after the agents and the terminal.
	onKill []func()
}

// newLab opens Ryan's terminal and the lab directory, and with build builds
// port49.
func newLab(t *testing.T, cell string, build bool) *lab { return newStudyLab(t, "L60", cell, build) }

// newStudyLab is newLab for the register entry study.
func newStudyLab(t *testing.T, study, cell string, build bool) *lab {
	t.Helper()
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("no terminal: run this from your own terminal, not under a tool (%v)", err)
	}
	t.Cleanup(func() { tty.Close() })
	return setupStudyLab(t, study, cell, build, tty, tty, labDir(t))
}

// setupLab is newLab on a given terminal (nil for none) and lab directory.
func setupLab(t *testing.T, cell string, build bool, tty *os.File, out io.Writer, dir string) *lab {
	t.Helper()
	return setupStudyLab(t, "L60", cell, build, tty, out, dir)
}

func setupStudyLab(t *testing.T, study, cell string, build bool, tty *os.File, out io.Writer, dir string) *lab {
	t.Helper()
	h := &lab{t: t, study: study, cell: cell, tty: tty, out: out, module: cmpOr(os.Getenv(envModule), defaultModule),
		agents: map[string]int{}, dir: dir}
	if tty != nil {
		if st, err := term.GetState(int(tty.Fd())); err == nil {
			h.saved = st
		}
	}
	var err error
	h.obsFile, err = os.OpenFile(filepath.Join(h.dir, fileObs), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	h.home = privateDir(t, "l60h")
	t.Cleanup(func() {
		h.stopAllAgents()
		h.restoreTTY()
		h.obsFile.Close()
	})
	h.say("\n=== %s cell %s, %s ===", study, cell, time.Now().Format(time.RFC3339))
	h.obs("run_started", time.Now().UTC().Format(time.RFC3339))
	if build {
		h.bin = buildPort49(t, h)
	}
	return h
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// labDir is the lab directory, made 0700.
func labDir(t *testing.T) string {
	t.Helper()
	d := os.Getenv(envDir)
	if d == "" {
		c, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		d = filepath.Join(c, "port49-l60")
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// privateDir is a fresh 0700 directory short enough for a Unix socket path.
func privateDir(t *testing.T, prefix string) string {
	t.Helper()
	d, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// repoRoot is the module root, found from the package directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			t.Fatal("no go.mod above the test's directory")
		}
		d = p
	}
}

// buildPort49 builds the client binary (make build-client's command) into
// the lab directory, fresh each run so it is this tree's port49.
func buildPort49(t *testing.T, h *lab) string {
	t.Helper()
	if p := os.Getenv("PORT49_L86_BIN"); p != "" && h.study == "L86" {
		// make l86-build's client, so the run is that build's (tests/lab/L86-runbook.md).
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			t.Fatalf("PORT49_L86_BIN=%s is not an executable file: run make l86-build", p)
		}
		return p
	}
	out := filepath.Join(h.dir, "bin", "port49-client")
	h.say("building port49 with the hwkey_dlopen tag (under a minute)...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-tags", "hwkey_dlopen", "-o", out, "./cmd/port49")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building port49: %v\n%s", err, b)
	}
	return out
}

// say writes a line to Ryan's terminal.
func (h *lab) say(format string, a ...any) {
	fmt.Fprintf(h.out, format+"\n", a...)
}

// step announces a numbered step.
func (h *lab) step(n, format string, a ...any) {
	h.say("\n[%s %s] %s", h.cell, n, fmt.Sprintf(format, a...))
}

// obs records one observation: in the test log and in observations.log.
func (h *lab) obs(field, value string) {
	if h.study == "L86" {
		// An admin call's words never carry a token, a challenge or a signature; a long opaque
		// run is masked all the same.
		value = longOpaque.ReplaceAllString(value, "<opaque>")
	}
	line := fmt.Sprintf("%s %s %s: %s", h.study, h.cell, field, oneLine(redact(value)))
	h.t.Log(line)
	fmt.Fprintf(h.obsFile, "%s %s\n", time.Now().UTC().Format(time.RFC3339), line)
}

// oneLine joins a multi-line value with " | " and bounds it.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	var parts []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			parts = append(parts, l)
		}
	}
	s = strings.Join(parts, " | ")
	if len(s) > 900 {
		s = s[:900] + "…"
	}
	if s == "" {
		return "(empty)"
	}
	return s
}

// longOpaque is a run that can only be a token, a hash or a signature.
var longOpaque = regexp.MustCompile(`[A-Za-z0-9+_=-]{40,}`)

// redact masks a device serial: libykcs11's token label carries it
// ("YubiKey PIV #<serial>"), and the results note keeps it out. The rule is
// serialmask's, shared with port49 hwkey.
func redact(s string) string { return serialmask.MaskSerial(s) }

// readLine reads one line Ryan types, within d. A terminal that takes no
// deadline is read with none.
func (h *lab) readLine(d time.Duration) (string, error) {
	if h.tty == nil {
		return "", errors.New("harness fault: no terminal to ask on")
	}
	h.restoreTTY() // a killed prompt may have left echo off
	deadlineSet := h.tty.SetReadDeadline(time.Now().Add(d)) == nil
	defer func() {
		if deadlineSet {
			_ = h.tty.SetReadDeadline(time.Time{})
		}
	}()
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := h.tty.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return strings.TrimSpace(string(b)), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return "", fmt.Errorf("no answer within %v", d)
			}
			return "", err
		}
	}
}

// waitEnter tells Ryan what to do and waits for Enter, within d; past it the
// cell fails, so nothing hangs.
func (h *lab) waitEnter(what string, d time.Duration) {
	h.t.Helper()
	h.flushInput()
	h.say("  >>> %s\n      Press Enter when done (deadline %v).", what, d)
	if _, err := h.readLine(d); err != nil {
		h.t.Fatalf("step not confirmed: %v", err)
	}
}

// askInt asks Ryan for a number.
func (h *lab) askInt(question string) int {
	h.t.Helper()
	// Only what is typed after the question answers it (L86 cell (c): a stray
	// line from the login was read as the first answer, and the question asked
	// twice).
	h.flushInput()
	for range 3 {
		h.say("  ??? %s (type a number, Enter; deadline %v)", question, handDeadline)
		s, err := h.readLine(handDeadline)
		if err != nil {
			h.t.Fatalf("no answer: %v", err)
		}
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	h.t.Fatal("no number after three asks")
	return 0
}

// flushInput discards what was typed before a question was shown.
func (h *lab) flushInput() {
	if h.tty != nil {
		flushTTYInput(h.tty)
	}
}

// restoreTTY puts Ryan's terminal back as the cell found it.
func (h *lab) restoreTTY() {
	if h.saved != nil && h.tty != nil {
		_ = term.Restore(int(h.tty.Fd()), h.saved)
	}
}

// result is what a port49 command did.
type result struct {
	code     int
	stdout   string // "" for a token command: see tokenBytes
	stderr   string
	took     time.Duration
	timedOut bool
	// tokenBytes is the length of what `port49 token` printed; the token
	// itself is dropped unread.
	tokenBytes int
}

// runOpts say how a port49 command runs.
type runOpts struct {
	deadline time.Duration
	// terminal gives the command Ryan's terminal as stdin, so a login sees a
	// person there; false is /dev/null.
	terminal bool
	// detached runs it in a session of its own, with no controlling
	// terminal: nothing can be asked.
	detached bool
	// token: stdout is a token, measured and dropped, never shown.
	token bool
}

// port49 runs the client binary with args. stderr, and stdout unless it is a
// token, show live on Ryan's terminal and are kept for the observations.
func (h *lab) port49(o runOpts, args ...string) result {
	h.t.Helper()
	if o.deadline == 0 {
		o.deadline = cmdDeadline
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.deadline)
	defer cancel()
	args, sock := splitSock(args)
	cmd := exec.CommandContext(ctx, h.bin, args...)
	cmd.Env = h.childEnv()
	if sock != "" {
		cmd.Env = append(cmd.Env, "PORT49_TEST_AGENT_SOCKET="+sock)
	}
	// SIGTERM first: port49's PIN prompt restores the terminal on it.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	if o.terminal && h.tty != nil {
		cmd.Stdin = h.tty
	}
	if o.detached {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	var outb, errb bytes.Buffer
	cmd.Stderr = io.MultiWriter(&errb, h.out)
	if o.token {
		cmd.Stdout = &outb
	} else {
		cmd.Stdout = io.MultiWriter(&outb, h.out)
	}
	if h.broker != nil && len(args) > 0 && (args[0] == "refresh" || args[0] == "login") {
		// A login to a running agent refreshes it too.
		h.broker.stepPastPacing()
	}
	h.say("  $ port49 %s", strings.Join(args, " "))
	start := time.Now()
	err := cmd.Run()
	r := result{took: time.Since(start), stderr: errb.String(), timedOut: ctx.Err() != nil}
	h.restoreTTY()
	r.code = -1
	if cmd.ProcessState != nil {
		r.code = cmd.ProcessState.ExitCode()
	} else if err != nil {
		h.t.Fatalf("running port49: %s", redact(err.Error()))
	}
	if o.token {
		r.tokenBytes = len(bytes.TrimRight(outb.Bytes(), "\n"))
		clear(outb.Bytes())
	} else {
		r.stdout = outb.String()
		h.noteAgent(sock, r.stdout)
	}
	return r
}

// childEnv is the environment port49 runs in: a HOME of the run's own, so
// no ~/.port49 of Ryan's is read or written, and no PORT49_CONFIG.
func (h *lab) childEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "HOME" || k == "XDG_CONFIG_HOME" || k == "PORT49_CONFIG" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+h.home, "XDG_CONFIG_HOME="+filepath.Join(h.home, ".config"))
}

var agentStarted = regexp.MustCompile(`agent pid (\d+), log ([^)]+)\)`)

// parseAgentLine reads the pid and log path `port49 login` prints when it
// starts an agent.
func parseAgentLine(stdout string) (pid int, log string, ok bool) {
	m := agentStarted.FindStringSubmatch(stdout)
	if m == nil {
		return 0, "", false
	}
	pid, err := strconv.Atoi(m[1])
	return pid, m[2], err == nil
}

// sockMark begins an argument that is not for port49: it names the agent the
// command talks to, which no flag does. port49 strips it and puts the path in
// PORT49_TEST_AGENT_SOCKET in the child's environment (splitSock).
const sockMark = "\x00agent="

// onSock is the argument that points a command at the agent at sock.
func onSock(sock string) string { return sockMark + sock }

// splitSock separates the agent's socket from the arguments for port49.
func splitSock(args []string) (rest []string, sock string) {
	for _, a := range args {
		if p, ok := strings.CutPrefix(a, sockMark); ok {
			sock = p
			continue
		}
		rest = append(rest, a)
	}
	return rest, sock
}

// noteAgent remembers an agent a login started, by its socket.
func (h *lab) noteAgent(sock string, stdout string) {
	pid, _, ok := parseAgentLine(stdout)
	if !ok {
		return
	}
	h.mu.Lock()
	h.agents[sock] = pid
	h.mu.Unlock()
}

// stopAgent ends the agent at sock by its pid (never by a pattern) and waits
// until its socket stops answering.
func (h *lab) stopAgent(sock string) {
	h.mu.Lock()
	pid, ok := h.agents[sock]
	delete(h.agents, sock)
	h.mu.Unlock()
	if !ok {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if _, err := h.status(sock); err != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

func (h *lab) stopAllAgents() {
	h.mu.Lock()
	var socks []string
	for s := range h.agents {
		socks = append(socks, s)
	}
	h.mu.Unlock()
	for _, s := range socks {
		h.stopAgent(s)
	}
}

// agentsRunning is how many agents this cell started and has not stopped.
func (h *lab) agentsRunning() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.agents)
}

// status is the agent's GET /status.
func (h *lab) status(sock string) (agent.Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return agent.NewClient(sock).Status(ctx)
}

// obsStatus records the agent's GET /status fields that say the key's state
// (never the CA bytes, never a key_ref's pin-source path).
func (h *lab) obsStatus(field, sock string) agent.Status {
	st, err := h.status(sock)
	if err != nil {
		h.obs(field, "no answer: "+err.Error())
		return st
	}
	v := fmt.Sprintf("key_state=%s touch_key=%v", st.KeyState, st.TouchKey)
	if st.TouchKeyState != "" {
		v += " touch_key_state=" + st.TouchKeyState
	}
	if st.TouchKeyUnusable != "" {
		v += " touch_key_unusable=" + strconv.Quote(st.TouchKeyUnusable)
	}
	v += fmt.Sprintf(" handshakes=%d session_ends_at=%s", st.Handshakes, st.SessionEndsAt)
	h.obs(field, v)
	return st
}

// obsResult records a command's exit code, words and time.
func (h *lab) obsResult(field string, r result) {
	h.obs(field+"_code", strconv.Itoa(r.code))
	if r.timedOut {
		h.obs(field+"_timed_out", "yes: the step's deadline passed and the command was stopped")
	}
	if r.stdout != "" {
		h.obs(field+"_stdout", r.stdout)
	}
	h.obs(field+"_stderr", r.stderr)
	if r.tokenBytes > 0 {
		h.obs(field+"_minted", fmt.Sprintf("a %d-byte token (not shown)", r.tokenBytes))
	}
	h.obs(field+"_took", r.took.Round(time.Millisecond).String())
}

// keyRef is the pkcs11: reference of the slot with CKA_ID id. With
// pinSource it names Ryan's pin-source file (the path only).
func (h *lab) keyRef(id string, pinSource bool) string {
	ref := "pkcs11:id=%" + id + "?module-path=" + h.module
	if pinSource {
		ref += "&pin-source=file://" + h.pinSourcePath()
	}
	return ref
}

// pinSourcePath is PORT49_L60_PIN_SOURCE, checked to exist and be 0600 (its
// contents are port49's to read, not the harness's).
func (h *lab) pinSourcePath() string {
	h.t.Helper()
	p := os.Getenv(envPINSource)
	if p == "" {
		h.t.Fatalf("this cell needs %s: the path of a 0600 file holding the PIV PIN, made by you (RUNBOOK.md step 0)", envPINSource)
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		h.t.Fatalf("%s=%s must be a regular file of mode 0600 (%v)", envPINSource, p, err)
	}
	return p
}

// pinTriesRe reads `ykman piv info`'s "PIN tries remaining: 3/3" (or "3").
var pinTriesRe = regexp.MustCompile(`(?m)^\s*PIN tries remaining:\s*(\d+)(?:\s*/\s*(\d+))?`)

// parsePINTries is the tries left and the total (0 when not printed).
func parsePINTries(out string) (left, total int, ok bool) {
	m := pinTriesRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	left, _ = strconv.Atoi(m[1])
	if m[2] != "" {
		total, _ = strconv.Atoi(m[2])
	}
	return left, total, true
}

// pinTries runs `ykman piv info` (no PIN, no management key) and keeps only
// its PIN-tries line. It runs only while no agent of this cell is up: ykman
// selects the PIV applet, which may end a login an agent holds.
func (h *lab) pinTries(field string) int {
	h.t.Helper()
	if n := h.agentsRunning(); n != 0 {
		h.t.Fatalf("harness fault: ykman asked with %d agent(s) up", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ykman", "piv", "info").CombinedOutput()
	left, total, ok := parsePINTries(string(out))
	clear(out)
	if err != nil || !ok {
		h.t.Fatalf("`ykman piv info` gave no PIN-tries line (%v)", err)
	}
	h.obs(field, fmt.Sprintf("%d/%d", left, total))
	h.say("  PIN tries remaining: %d/%d", left, total)
	return left
}

// pinWords classifies port49 login's words for a refused PIN
// (cmd/port49/hwlogin.go pinRefusedWords): which token flags they show.
func pinWords(stderr string) string {
	switch {
	case strings.Contains(stderr, "PIN is blocked") || strings.Contains(stderr, "PIN is locked") ||
		strings.Contains(stderr, "unblock"):
		return "blocked"
	case strings.Contains(stderr, "one try is left"):
		return "final_try set (count_low not shown: the words name the final try first)"
	case strings.Contains(stderr, "fewer tries are left"):
		return "count_low set, final_try not set"
	case strings.Contains(stderr, "the token refused the PIN"):
		return "neither count_low nor final_try set"
	}
	return "no PIN refusal in the words"
}

// --- the lab PKI ---

// loadClientCA is the lab directory's client CA, made by the import cell.
func loadClientCA(dir string) (*testpki.CA, error) {
	cb, err := os.ReadFile(filepath.Join(dir, fileCA))
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, fileCAKey))
	if err != nil {
		return nil, err
	}
	c, _ := pem.Decode(cb)
	k, _ := pem.Decode(kb)
	if c == nil || k == nil {
		return nil, errors.New("the lab CA files hold no PEM")
	}
	cert, err := x509.ParseCertificate(c.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(k.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the lab CA key is not ECDSA")
	}
	return &testpki.CA{Cert: cert, Key: ek}, nil
}

// parsePEMCert is the first certificate in a PEM file's bytes.
func parsePEMCert(raw []byte) (*x509.Certificate, error) {
	for {
		var b *pem.Block
		if b, raw = pem.Decode(raw); b == nil {
			return nil, errors.New("no PEM certificate")
		}
		if b.Type == "CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
	}
}

// writeClientCA makes the lab client CA in dir, valid a year.
func writeClientCA(dir string, now time.Time) (*testpki.CA, error) {
	ca, err := testpki.NewCA("port49 L60 lab client CA", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, fileCAKey), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return ca, os.WriteFile(filepath.Join(dir, fileCA), ca.PEM(), 0o600)
}

// issueFor certifies pub as the lab identity, a client certificate valid 90
// days: what slot 9a is given.
func issueFor(ca *testpki.CA, pub any, now time.Time) ([]byte, error) {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: sn,
		Subject: pkix.Name{CommonName: labEmail}, EmailAddresses: []string{labEmail},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// fileClient writes the control's file key and certificate, from the lab
// CA, into a temporary directory.
func fileClient(t *testing.T, ca *testpki.CA) (cert, key string) {
	t.Helper()
	now := time.Now()
	c, err := ca.Issue(testpki.Leaf{CommonName: labEmail, Emails: []string{labEmail}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cp, kp, err := testpki.PEMs(c)
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	cert, key = filepath.Join(d, "control.pem"), filepath.Join(d, "control-key.pem")
	if err := os.WriteFile(cert, cp, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, kp, 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// needLabCA is the lab CA, or a failure saying to run the import cell first.
func (h *lab) needLabCA() *testpki.CA {
	h.t.Helper()
	ca, err := loadClientCA(h.dir)
	if err != nil {
		h.t.Fatalf("no lab CA in %s (%v): run the import step first (%s=1, RUNBOOK.md step 1)", h.dir, err, gateImport)
	}
	return ca
}

// yubicoRoots is Yubico's PIV root file (RUNBOOK.md step 0).
func (h *lab) yubicoRoots() []byte {
	h.t.Helper()
	p := cmpOr(os.Getenv(envRoots), filepath.Join(h.dir, "yubico-piv-ca-1.pem"))
	b, err := os.ReadFile(p)
	if err != nil {
		h.t.Fatalf("Yubico's PIV root is needed at %s (RUNBOOK.md step 0): %v", p, err)
	}
	return b
}

// loginArgs are a `port49 login`'s flags: the broker, its CA, the socket, the
// key, and the certificate file when one is given (else the token's).
func loginArgs(b *labBroker, sock, key, cert, touch string) []string {
	a := []string{"login", "--broker", b.url, "--broker-ca", b.serverCA, onSock(sock), "--key", key}
	if cert != "" {
		a = append(a, "--cert", cert)
	}
	if touch != "" {
		a = append(a, "--touch-key", touch)
	}
	return a
}

// socketIn is an agent socket path in a fresh private directory.
func socketIn(t *testing.T) string {
	return filepath.Join(privateDir(t, "l60s"), "agent.sock")
}

// agentLogTail is the end of the agent log a login printed, for the
// observations (the agent never logs a PIN or a token).
func agentLogTail(stdout string, n int) string {
	_, p, ok := parseAgentLine(stdout)
	if !ok {
		return ""
	}
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
