//go:build lab

package lab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// L64 and L65 (plan 9d, Task 11): `port49 ssh` under OpenSSH's accept-new, and
// the Python client (`port49.netmiko.connect`), against each platform. The
// device's host key is OpenSSH's job here, so each cell reads what OpenSSH or
// Paramiko did with a known_hosts file in a private home, and what reached
// port49d.
//
// Every subprocess runs under a deadline, and every cell under its own: a
// failed cell records its outcome and the run goes on. A progress line per
// cell goes to stdout (l64Progress) for the lab watchdog.

// ---------------------------------------------------------------------------
// Readers: pure, and unit-tested in l64_l65_unit_test.go
// ---------------------------------------------------------------------------

var (
	l64AddedRe     = regexp.MustCompile(`Warning: Permanently added '[^']+' \((\w+)\) to the list of known hosts`)
	l64OffendingRe = regexp.MustCompile(`Offending (\w+) key in \S+:\d+`)
	l64SentRe      = regexp.MustCompile(`The fingerprint for the (\w+) key sent by the remote host is`)
	l64ServerRe    = regexp.MustCompile(`Server host key: (\S+) SHA256:`)
	l64NextAuthRe  = regexp.MustCompile(`Next authentication method: (\S+)`)
	l64AuthedRe    = regexp.MustCompile(`Authenticated to \S+ \(\S+\) using "([^"]+)"`)
	l64KeygenRRe   = regexp.MustCompile(`ssh-keygen\b[^\n]*-R\b`)
	l64KeyLineRe   = regexp.MustCompile(`Authenticated to|Permanently added|Offending|Host key|REMOTE HOST|ssh-keygen|` +
		`no matching host key|Next authentication method|port49 ssh:|fingerprint for|` +
		`Learned new hostkey|update_known_hosts|client_input_hostkeys`)
)

// l64Stderr is what ssh's stderr (run with -v) and port49 ssh's own lines say.
type l64Stderr struct {
	// Class is accepted (a key was filed), changed (a filed key of the type the device sent is not its key),
	// other_type (the filed key is of another type than the one the device sent), no_matching_host_key (the
	// device offers no filed type), or clean (none of these).
	Class           string
	Added           []string // the key types of each "Permanently added" line
	FiledType       string   // "Offending ECDSA key": the type that was filed
	SentType        string   // the type the device sent, as ssh names it
	Banner          bool     // WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED
	VerifyFailed    bool
	NamesKeygenR    bool
	Methods         []string // each "Next authentication method"
	AuthenticatedBy string
}

// Asks is how many of the methods ssh tried ask the askpass: the password and the keyboard-interactive
// ones. ssh -v does not log the askpass itself; the redeem records in port49d's log say how many of the asks
// reached the device.
func (r l64Stderr) Asks() int {
	n := 0
	for _, m := range r.Methods {
		if m == "password" || m == "keyboard-interactive" {
			n++
		}
	}
	return n
}

// l64Family names a key type alike however OpenSSH spells it: "ED25519" and "ssh-ed25519" are "ed25519".
func l64Family(typ string) string {
	t := strings.ToLower(typ)
	switch {
	case strings.Contains(t, "ed25519"):
		return "ed25519"
	case strings.Contains(t, "ecdsa"):
		return "ecdsa"
	case strings.Contains(t, "rsa"):
		return "rsa"
	}
	return ""
}

// l64ReadSSH classifies the stderr of one `port49 ssh -v` (OpenSSH 10.2p1's wording).
func l64ReadSSH(stderr string) l64Stderr {
	var r l64Stderr
	for _, m := range l64AddedRe.FindAllStringSubmatch(stderr, -1) {
		r.Added = append(r.Added, m[1])
	}
	if m := l64OffendingRe.FindStringSubmatch(stderr); m != nil {
		r.FiledType = m[1]
	}
	if m := l64SentRe.FindStringSubmatch(stderr); m != nil {
		r.SentType = m[1]
	} else if m := l64ServerRe.FindStringSubmatch(stderr); m != nil {
		r.SentType = m[1]
	}
	for _, m := range l64NextAuthRe.FindAllStringSubmatch(stderr, -1) {
		r.Methods = append(r.Methods, m[1])
	}
	if m := l64AuthedRe.FindStringSubmatch(stderr); m != nil {
		r.AuthenticatedBy = m[1]
	}
	r.Banner = strings.Contains(stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED")
	r.VerifyFailed = strings.Contains(stderr, "Host key verification failed")
	r.NamesKeygenR = l64KeygenRRe.MatchString(stderr)
	refused := r.Banner || r.VerifyFailed || strings.Contains(stderr, "has changed and you have requested strict checking")
	switch {
	case strings.Contains(stderr, "no matching host key type found"):
		r.Class = "no_matching_host_key"
	case refused && r.FiledType != "" && r.SentType != "" && l64Family(r.FiledType) != l64Family(r.SentType):
		r.Class = "other_type"
	case refused:
		r.Class = "changed"
	case len(r.Added) > 0:
		r.Class = "accepted"
	default:
		r.Class = "clean"
	}
	return r
}

// l64KeyLines is the lines of ssh's stderr that say what it decided about the key and the login: the
// excerpt a note keeps, with the rest of -v's chatter left out.
func l64KeyLines(stderr string) string {
	var keep []string
	for _, ln := range strings.Split(stderr, "\n") {
		if l64KeyLineRe.MatchString(ln) {
			keep = append(keep, strings.TrimRight(ln, " \r"))
		}
	}
	return strings.Join(keep, "\n")
}

// l64Lines is how many non-blank lines s holds: the output a command printed, counted and never shown.
func l64Lines(s string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

// l64KnownHostsLines is how many lines of a known_hosts file hold a key: not blank, not a comment.
func l64KnownHostsLines(content string) int {
	n := 0
	for _, ln := range strings.Split(content, "\n") {
		if s := strings.TrimSpace(ln); s != "" && !strings.HasPrefix(s, "#") {
			n++
		}
	}
	return n
}

// l64Entry is one key line `ssh-keygen -F` found.
type l64Entry struct {
	Marker string // @revoked, @cert-authority, or ""
	Host   string
	Hashed bool
	Type   string
	Blob   string
}

// l64ParseKeygenF reads `ssh-keygen -F <name> -f <file>`'s output: a "# Host x found: line N" comment, then
// the line itself, for each line found. Every line is returned, not the first only.
func l64ParseKeygenF(out string) []l64Entry {
	var es []l64Entry
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		var e l64Entry
		if strings.HasPrefix(f[0], "@") {
			e.Marker, f = f[0], f[1:]
		}
		if len(f) < 3 {
			continue
		}
		e.Host, e.Type, e.Blob = f[0], f[1], f[2]
		e.Hashed = strings.HasPrefix(e.Host, "|1|")
		es = append(es, e)
	}
	return es
}

// l64KeygenArgs is the ssh-keygen arguments (after -q -N "" -f FILE) that make a key of the OpenSSH type typ.
func l64KeygenArgs(typ string) ([]string, bool) {
	switch typ {
	case "ssh-ed25519":
		return []string{"-t", "ed25519"}, true
	case "ssh-rsa":
		return []string{"-t", "rsa", "-b", "2048"}, true
	case "ecdsa-sha2-nistp256":
		return []string{"-t", "ecdsa", "-b", "256"}, true
	case "ecdsa-sha2-nistp384":
		return []string{"-t", "ecdsa", "-b", "384"}, true
	case "ecdsa-sha2-nistp521":
		return []string{"-t", "ecdsa", "-b", "521"}, true
	}
	return nil, false
}

// l64OtherType is a key type other than filed: RSA if Ed25519 or ECDSA was filed, Ed25519 if RSA.
func l64OtherType(filed string) string {
	if l64Family(filed) == "rsa" || l64Family(filed) == "" {
		return "ssh-ed25519"
	}
	return "ssh-rsa"
}

// l64PacketsIn counts the packets pkts holds with from <= at <= to.
func l64PacketsIn(pkts []l29Packet, from, to time.Time) int {
	n := 0
	for _, p := range pkts {
		if !p.at.Before(from) && !p.at.After(to) {
			n++
		}
	}
	return n
}

// l64OtherRecords is the events of recs other than mint and blob, in order: a refused login leaves nothing else.
func l64OtherRecords(recs []map[string]any) []string {
	var out []string
	for _, r := range recs {
		if e := str(r, "event"); e != "mint" && e != "blob" {
			out = append(out, e)
		}
	}
	return out
}

func l64Redeems(recs []map[string]any) int {
	n := 0
	for _, r := range recs {
		if str(r, "event") == "redeem" {
			n++
		}
	}
	return n
}

// l64Driver is the one line the Python driver prints; it holds outcomes, counts and a type, never a token.
type l64Driver struct {
	Outcome     string `json:"outcome"`
	ErrorClass  string `json:"error_class"`
	Code        string `json:"code"`
	Text        string `json:"text"`
	OutputLines int    `json:"output_lines"`
	KeyType     string `json:"key_type"`
}

const l64DriverPrefix = "P49RESULT "

func l64ParseDriver(out string) (l64Driver, bool) {
	for _, ln := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(ln), l64DriverPrefix)
		if !ok {
			continue
		}
		var d l64Driver
		if json.Unmarshal([]byte(rest), &d) == nil && d.Outcome != "" {
			return d, true
		}
	}
	return l64Driver{}, false
}

// l64UserKnownHosts is the files `ssh -G` says it reads for the user ("userknownhostsfile a b").
func l64UserKnownHosts(sshG string) []string {
	for _, ln := range strings.Split(sshG, "\n") {
		if rest, ok := strings.CutPrefix(ln, "userknownhostsfile "); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

// l64Outcome is a cell's verdict. A refusal cell's zero (no packet, no redeem) means something only while the
// positive control holds, so a refusal that passes with the control failed, or with a count that could not be
// read, is INVALID and never PASS; one that fails stays a FAIL, since what it saw is real whatever the control.
func l64Outcome(pass, timedOut, controlOK, refusal, unread bool) string {
	switch {
	case timedOut:
		return "TIMEOUT"
	case refusal && unread:
		return "INVALID"
	case pass && refusal && !controlOK:
		return "INVALID"
	case !pass:
		return "FAIL"
	}
	return "PASS"
}

// l64ControlOK is whether a good login's window proves the counter counts: TACACS+ packets and a redeem. An
// unreadable count (-1) proves nothing.
func l64ControlOK(packets, redeems int) bool { return packets > 0 && redeems > 0 }

// l64CheckConfig refuses a private ssh_config that would not behave as the operator's default client: ssh must
// read the private known_hosts file and no other, with UpdateHostKeys on (an absolute UserKnownHostsFile turns
// it off unless the config says so).
func l64CheckConfig(sshG, kh string) error {
	if got := l64UserKnownHosts(sshG); !slices.Equal(got, []string{kh}) {
		return fmt.Errorf("ssh -G reads %v, not only %s: the run would touch the operator's own known_hosts", got, kh)
	}
	for _, ln := range strings.Split(sshG, "\n") {
		if v, ok := strings.CutPrefix(ln, "updatehostkeys "); ok && strings.TrimSpace(v) == "true" {
			return nil
		}
	}
	return errors.New("ssh -G does not say updatehostkeys true: the run would measure a client that files only the negotiated key")
}

// l64Diff compares two readings of the filed lines by key type and blob (the host field of a hashed line is
// salted afresh): the lines after has that before did not, and the lines before had that after lacks.
func l64Diff(before, after []l64Entry) (added, removed []l64Entry) {
	has := func(es []l64Entry, e l64Entry) bool {
		return slices.ContainsFunc(es, func(o l64Entry) bool { return o.Type == e.Type && o.Blob == e.Blob })
	}
	for _, e := range after {
		if !has(before, e) {
			added = append(added, e)
		}
	}
	for _, e := range before {
		if !has(after, e) {
			removed = append(removed, e)
		}
	}
	return added, removed
}

// l64PickEntry is the filed line of key type typ.
func l64PickEntry(es []l64Entry, typ string) (l64Entry, bool) {
	for _, e := range es {
		if e.Type == typ && e.Marker == "" {
			return e, true
		}
	}
	return l64Entry{}, false
}

// l64GradeE2 reads L65 (e2): `port49 ssh` against the entry Python filed exits 0, files nothing new (class
// clean, no "Permanently added"), and leaves the negotiated key's line as it was. Types UpdateHostKeys adds
// after authentication are an observation, not a failure.
func l64GradeE2(r l64Stderr, exit int, want l64Entry, after []l64Entry) (bool, string) {
	var bad []string
	if exit != 0 {
		bad = append(bad, fmt.Sprintf("exit %d, not 0", exit))
	}
	if r.Class != "clean" || len(r.Added) != 0 {
		bad = append(bad, fmt.Sprintf("ssh: %s, added %v", r.Class, r.Added))
	}
	if _, removed := l64Diff([]l64Entry{want}, after); len(removed) != 0 {
		bad = append(bad, "the negotiated key's line is not as Python filed it")
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	return true, ""
}

// l64Start and l64Stage are the lines a cell writes to stdout when it starts and at each stage of a long one.
func l64Start(platform, cell string, budget time.Duration) string {
	return fmt.Sprintf("L64L65 %s %s START budget %s", platform, cell, budget)
}

func l64Stage(platform, cell, stage string) string {
	return fmt.Sprintf("L64L65 %s %s STAGE %s", platform, cell, stage)
}

// l64Progress is the line a cell writes to stdout when it ends.
func l64Progress(platform, cell, outcome string, d time.Duration) string {
	return fmt.Sprintf("L64L65 %s %s %s %s", platform, cell, outcome, d.Round(100*time.Millisecond))
}

// l64GradeSSHRefusal reads the L64 (c) and (d) claim: exit 255, no TACACS+ packet, no record but mint and
// blob, no key filed, and the stderr naming ssh-keygen -R.
func l64GradeSSHRefusal(r l64Stderr, exit, packets int, other []string) (bool, string) {
	var bad []string
	if exit != 255 {
		bad = append(bad, fmt.Sprintf("exit %d, not 255", exit))
	}
	if packets != 0 {
		bad = append(bad, fmt.Sprintf("%d TACACS+ packets, not 0", packets))
	}
	if len(other) != 0 {
		bad = append(bad, "records other than mint and blob: "+strings.Join(other, ", "))
	}
	if len(r.Added) != 0 {
		bad = append(bad, "a key was filed: "+strings.Join(r.Added, ", "))
	}
	if !r.NamesKeygenR {
		bad = append(bad, "its stderr does not name ssh-keygen -R")
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	return true, ""
}

// l64GradePyRefusal reads the L65 (c), (d) and (f) claim: a HostKeyError (of the code wantCode, if one is
// named), no TACACS+ packet, no record but mint and blob.
func l64GradePyRefusal(d l64Driver, wantCode string, packets int, other []string) (bool, string) {
	var bad []string
	if d.Outcome != "port49_error" || d.ErrorClass != "HostKeyError" {
		bad = append(bad, fmt.Sprintf("outcome %s %s, not a HostKeyError", d.Outcome, d.ErrorClass))
	}
	if wantCode != "" && d.Code != wantCode {
		bad = append(bad, fmt.Sprintf("code %q, not %q", d.Code, wantCode))
	}
	if packets != 0 {
		bad = append(bad, fmt.Sprintf("%d TACACS+ packets, not 0", packets))
	}
	if len(other) != 0 {
		bad = append(bad, "records other than mint and blob: "+strings.Join(other, ", "))
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// The lab side
// ---------------------------------------------------------------------------

const (
	l64CellBudget   = 4 * time.Minute
	l64ReloadBudget = 45 * time.Minute
	// l64Grace is how long past its budget a cell is given to return: its subprocesses die at the budget.
	l64Grace = time.Minute
)

// l64DriverScript is the Python each Python cell runs in the venv. It reads the token through the library and
// prints one line of outcomes: a code, a line count, a key type. Nothing it prints is, or is derived from,
// a token.
const l64DriverScript = `import json, os, sys

def say(**kw):
    print("P49RESULT " + json.dumps(kw), flush=True)

def short(s, n=200):
    return " ".join(str(s).split())[:n]

try:
    import port49
    from port49.netmiko import connect
except Exception as e:
    say(outcome="import_error", error_class=type(e).__name__, text=short(e))
    sys.exit(3)

conn = None
try:
    agent = port49.Agent(port49=os.environ["P49_BIN"], socket=os.environ["P49_SOCK"], timeout=90)
    conn = connect(os.environ["P49_DEVICE"], agent=agent, ssh_config=os.environ["P49_SSHCONF"],
                   conn_timeout=30, auth_timeout=60, banner_timeout=60)
    out = conn.send_command(os.environ["P49_CMD"], read_timeout=60)
    key = conn.remote_conn_pre.get_transport().get_remote_server_key().get_name()
    say(outcome="connected", output_lines=len(out.splitlines()), key_type=key)
except port49.Port49Error as e:
    say(outcome="port49_error", error_class=type(e).__name__, code=e.code, text=short(e))
    sys.exit(2)
except BaseException as e:
    say(outcome="error", error_class=type(e).__name__, text=short(e))
    sys.exit(1)
finally:
    if conn is not None:
        try:
            conn.disconnect()
        except Exception:
            pass
`

var l64Install sync.Once
var l64Versions string

// l64Run runs a command under ctx and returns its output and exit status. A command killed at the deadline
// is an error; one that exits non-zero is not.
func l64Run(ctx context.Context, env []string, dir, name string, args ...string) (stdout, stderr string, exit int, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env, cmd.Dir = env, dir
	// Its own process group, ended whole at the deadline: the ssh under `port49 ssh` and the CLI under the
	// driver must not outlive the cell and reach the device in a later cell's window.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	cmd.WaitDelay = 10 * time.Second // a descendant that holds the pipes cannot keep this from returning
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		exit, err = ee.ExitCode(), nil
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("%s was ended at the cell's deadline: %w", filepath.Base(name), ctx.Err())
	}
	return so.String(), se.String(), exit, err
}

// l64Result is one cell's row.
type l64Result struct {
	id, outcome, observation string
	elapsed                  time.Duration
}

// l64Env is one platform's run: a private home, the agent, the daemon, one capture, the cells' results.
type l64Env struct {
	t    *testing.T
	l    *lab
	node string

	home, khPath, cfgPath, driverPath, keyDir string
	daemonCfg                                 string // port49d's config with the broker block
	sock                                      string
	stopAgent                                 func()

	results          []l64Result
	controlOK        bool // the good login's window held TACACS+ packets: the counter counts
	reloadKeyChanged bool
	filedType        string
	filedEntries     []l64Entry // every line L64a left, read after its login
	pyFile           string     // the known_hosts content Python's first contact filed
	pyEntry          l64Entry   // the line of the type Python negotiated in L65a
	idleNote         string
	keyN             int

	// Per cell: unread is set when a TACACS+ count could not be read, invalid when the cell could not measure
	// its claim at all; both are reset when the cell starts.
	unread  bool
	invalid string
	// reloadFailed is why the device was not back after L64b, which ends the platform's run.
	reloadFailed string
}

func (e *l64Env) env() []string {
	var out []string
	for _, kv := range os.Environ() {
		// No ssh-agent (the operator's real keys are not for the lab) and no other port49 askpass.
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "SSH_AUTH_SOCK=") || strings.HasPrefix(kv, "SSH_ASKPASS") ||
			strings.HasPrefix(kv, "PORT49_ASKPASS=") || strings.HasPrefix(kv, "PYTHONDONTWRITEBYTECODE=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "HOME="+e.home, "PYTHONDONTWRITEBYTECODE=1")
}

// writeConfig writes the private ssh_config. Its known_hosts path is absolute: ssh expands "~" from the
// passwd entry, not from $HOME, so "~/.ssh/known_hosts" would be the operator's real file.
//
// An absolute path also turns UpdateHostKeys off (it is on by default only for the default path), so the
// config says "UpdateHostKeys yes": the operator's default, made explicit. ssh -G is read after every write.
func (e *l64Env) writeConfig(hash bool) error {
	cfg := "UserKnownHostsFile " + e.khPath + "\nGlobalKnownHostsFile /dev/null\nUpdateHostKeys yes\n"
	if hash {
		cfg += "HashKnownHosts yes\n"
	}
	if err := os.WriteFile(e.cfgPath, []byte(cfg), 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sshG, _, _, err := l64Run(ctx, e.env(), e.home, "ssh", "-G", "-F", e.cfgPath, "--", e.node)
	if err != nil {
		return err
	}
	return l64CheckConfig(sshG, e.khPath)
}

func (e *l64Env) writeKnownHosts(content string) error {
	return os.WriteFile(e.khPath, []byte(content), 0o600)
}

func (e *l64Env) readKnownHosts() string {
	b, _ := os.ReadFile(e.khPath)
	return string(b)
}

// keygenFind is every line `ssh-keygen -F <node>` finds in the private known_hosts file.
func (e *l64Env) keygenFind(ctx context.Context) ([]l64Entry, error) {
	out, _, _, err := l64Run(ctx, e.env(), e.home, "ssh-keygen", "-F", e.node, "-f", e.khPath)
	return l64ParseKeygenF(out), err
}

// freshKey makes a key of the OpenSSH type typ and returns its base64 blob.
func (e *l64Env) freshKey(ctx context.Context, typ string) (string, error) {
	args, ok := l64KeygenArgs(typ)
	if !ok {
		return "", fmt.Errorf("the harness cannot make a %s key", typ)
	}
	e.keyN++
	path := filepath.Join(e.keyDir, "k"+strconv.Itoa(e.keyN))
	args = append(append([]string{"-q", "-N", "", "-f", path}, args...), "-C", "l64")
	if _, se, exit, err := l64Run(ctx, e.env(), e.home, "ssh-keygen", args...); err != nil || exit != 0 {
		return "", fmt.Errorf("ssh-keygen for %s: exit %d %v %s", typ, exit, err, strings.TrimSpace(se))
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(pub))
	if len(f) < 2 || f[0] != typ {
		return "", fmt.Errorf("ssh-keygen made %q, not %s", f, typ)
	}
	return f[1], nil
}

// flush is flushCapture without a *testing.T: a cell may outlive its test goroutine's patience and must not
// log through t.
func (e *l64Env) flush() {
	before := pcapSize(e.l.capAbs)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		capProbe()
		for i := 0; i < 10 && time.Now().Before(deadline); i++ {
			if pcapSize(e.l.capAbs) > before {
				time.Sleep(200 * time.Millisecond)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// tacacsIn counts the TACACS+ packets in a window of the capture; -1, and e.unread, when it cannot be read.
func (e *l64Env) tacacsIn(from, to time.Time) int {
	e.flush()
	pkts, err := l29Packets(e.l.capAbs, e.l.p.addr)
	if err != nil {
		e.unread = true
		return -1
	}
	return l64PacketsIn(pkts, from, to)
}

// waitQuiet waits for a window of 10s in which the device talks to port49d on its own no more, so that a
// refused login's zero is the login's: up to 18 windows, then the last one is taken as it is.
func (e *l64Env) waitQuiet(ctx context.Context) string {
	var recs, pkts int
	for i := 0; i < 18; i++ {
		from, off := time.Now(), e.l.mark()
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			return "the wait for a quiet window was ended by the cell's deadline"
		}
		recs, pkts = len(e.l.recordsSince(off)), e.tacacsIn(from, time.Now())
		if recs+pkts == 0 {
			return "a window of 10s with no decision record and no TACACS+ packet preceded it"
		}
	}
	return fmt.Sprintf("**the device never went quiet**: the last 10s window before it held %d decision records and %d "+
		"TACACS+ packets", recs, pkts)
}

// sshRun is one `port49 ssh -v <node> -- show version`.
type l64SSHRun struct {
	exit    int
	stdout  string
	stderr  string
	read    l64Stderr
	packets int
	recs    []map[string]any
	other   []string
	redeems int
	err     error
}

func (r l64SSHRun) counts() string {
	return fmt.Sprintf("%d TACACS+ packets, %d redeem records, records other than mint and blob: %v",
		r.packets, r.redeems, r.other)
}

func (e *l64Env) portSSH(ctx context.Context) l64SSHRun {
	off, from := e.l.mark(), time.Now()
	var r l64SSHRun
	r.stdout, r.stderr, r.exit, r.err = l64Run(ctx, e.env(), root, filepath.Join(root, "bin", "port49"), "ssh", "-v",
		"--socket", e.sock, "--ssh-config", e.cfgPath, e.node, "--", "show version")
	r.recs = e.l.drainRecords(off, 6*time.Second)
	r.packets = e.tacacsIn(from, time.Now())
	r.read = l64ReadSSH(r.stderr)
	r.other, r.redeems = l64OtherRecords(r.recs), l64Redeems(r.recs)
	return r
}

type l64PyRun struct {
	d       l64Driver
	parsed  bool
	exit    int
	stderr  string
	packets int
	recs    []map[string]any
	other   []string
	redeems int
	err     error
}

func (e *l64Env) python(ctx context.Context) l64PyRun {
	off, from := e.l.mark(), time.Now()
	env := append(e.env(), "P49_BIN="+filepath.Join(root, "bin", "port49"), "P49_SOCK="+e.sock,
		"P49_SSHCONF="+e.cfgPath, "P49_DEVICE="+e.node, "P49_CMD=show version")
	var r l64PyRun
	var stdout string
	stdout, r.stderr, r.exit, r.err = l64Run(ctx, env, e.home, venvPython, "-I", "-B", e.driverPath)
	r.d, r.parsed = l64ParseDriver(stdout)
	r.recs = e.l.drainRecords(off, 6*time.Second)
	r.packets = e.tacacsIn(from, time.Now())
	r.other, r.redeems = l64OtherRecords(r.recs), l64Redeems(r.recs)
	return r
}

func (r l64PyRun) said() string {
	if !r.parsed {
		return fmt.Sprintf("the driver printed no result line (exit %d, error %v)", r.exit, r.err)
	}
	s := "outcome `" + r.d.Outcome + "`"
	if r.d.ErrorClass != "" {
		s += ", `" + r.d.ErrorClass + "`"
	}
	if r.d.Code != "" {
		s += ", code `" + r.d.Code + "`"
	}
	if r.d.Outcome == "connected" {
		s += fmt.Sprintf(", %d lines of output, the device's key `%s`", r.d.OutputLines, r.d.KeyType)
	}
	return s
}

func (r l64PyRun) counts() string {
	return fmt.Sprintf("%d TACACS+ packets, %d redeem records, records other than mint and blob: %v",
		r.packets, r.redeems, r.other)
}

// cell runs fn under its own budget and records its row. fn returns whether the cell's claims held and what
// it observed; it never calls t, since the run goes on past a cell that does not return. A cell that has not
// returned a minute after its budget ends the platform's run: its goroutine could still be using the device.
func (e *l64Env) cell(id string, budget time.Duration, fn func(ctx context.Context) (bool, string)) bool {
	start := time.Now()
	fmt.Fprintln(os.Stdout, l64Start(e.l.p.name, id, budget))
	e.unread, e.invalid = false, ""
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	type done struct {
		pass bool
		obs  string
	}
	ch := make(chan done, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- done{false, fmt.Sprintf("the cell panicked: %v", p)}
			}
		}()
		pass, obs := fn(ctx)
		ch <- done{pass, obs}
	}()
	var d done
	outcome := "PASS"
	select {
	case d = <-ch:
		outcome = l64Outcome(d.pass, ctx.Err() != nil, e.controlOK, l64Refusal(id), e.unread)
		if e.invalid != "" && outcome != "TIMEOUT" {
			outcome, d.obs = "INVALID", "**INVALID: "+e.invalid+".** "+d.obs
		}
	case <-time.After(budget + l64Grace):
		e.t.Logf("%s", l64Progress(e.l.p.name, id, "STUCK", time.Since(start)))
		fmt.Fprintln(os.Stdout, l64Progress(e.l.p.name, id, "STUCK", time.Since(start)))
		e.t.Fatalf("cell %s did not return %s after its %s budget; the platform's run ends here", id, l64Grace, budget)
	}
	if outcome == "INVALID" && e.invalid == "" {
		d.obs = "**INVALID: the positive control failed or a count could not be read** (the nearest good login's window held " +
			"no TACACS+ packet and redeem, or the capture could not be read, so a zero here is a zero of a counter that " +
			"does not count). " + d.obs
	}
	if outcome == "TIMEOUT" {
		d.obs = "**The cell's budget ran out.** " + d.obs
	}
	elapsed := time.Since(start)
	e.results = append(e.results, l64Result{id, outcome, d.obs, elapsed})
	fmt.Fprintln(os.Stdout, l64Progress(e.l.p.name, id, outcome, elapsed))
	e.t.Logf("%s: %s", id, d.obs)
	return outcome == "PASS"
}

// l64AfterReload are the cells that follow L64b, skipped when the device is not back.
var l64AfterReload = []string{"L64c", "L64d", "L65a", "L65b", "L65c", "L65d", "L65e2", "L65f1", "L65f2"}

// l64Types lists the key types of es for a note.
func l64Types(es []l64Entry) string {
	if len(es) == 0 {
		return "none"
	}
	var ts []string
	for _, e := range es {
		ts = append(ts, e.Type)
	}
	return strings.Join(ts, ", ")
}

// l64Refusal is whether the cell id claims a refusal, whose zero needs the positive control.
func l64Refusal(id string) bool {
	return slices.Contains([]string{"L64c", "L64d", "L65c", "L65d", "L65f1", "L65f2"}, id)
}

// l64Agent runs `port49 login` against port49d's broker and returns the agent's socket and a stop func.
func (e *l64Env) newAgent() (string, func(), error) {
	pki := filepath.Join(root, slicePKIDir)
	dir, err := os.MkdirTemp("", "p49l64")
	if err != nil {
		return "", nil, err
	}
	sock := filepath.Join(dir, "a", "agent.sock")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, errOut, exit, err := l64Run(ctx, os.Environ(), root, filepath.Join(root, "bin", "port49"), "login",
		"--broker", sliceBrokerURL, "--cert", filepath.Join(pki, testpki.LabClientCert), "--key",
		filepath.Join(pki, testpki.LabClientKey), "--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", sock)
	if err != nil || exit != 0 {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("port49 login: exit %d %v\n%s", exit, err, errOut)
	}
	return sock, func() {
		if m := agentPID.FindStringSubmatch(out + errOut); m != nil {
			if pid, err := strconv.Atoi(m[1]); err == nil {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
		os.RemoveAll(dir)
	}, nil
}

// admin runs fn on the break-glass CLI. The device takes the local password only while port49d is down, so
// the daemon is stopped for the session, and the broker daemon and a new agent are put back after.
func (e *l64Env) admin(fn func(c *cliConn) error) error {
	l := e.l
	if err := l.stopDaemon(); err != nil {
		return fmt.Errorf("could not stop port49d before the admin CLI: %w", err)
	}
	var fnErr error
	if c, err := l53Admin(l); err != nil {
		fnErr = fmt.Errorf("no admin CLI: %w", err)
	} else {
		fnErr = fn(c)
		c.Close()
	}
	e.stopAgent()
	e.stopAgent = func() {} // the agent is stopped; a failure below must not stop it twice
	if err := l.startDaemonWith(e.daemonCfg, true); err != nil {
		return fmt.Errorf("port49d would not start again: %w", err)
	}
	if err := l.awaitTACACS(); err != nil {
		return err
	}
	sock, stop, err := e.newAgent()
	if err != nil {
		return err
	}
	e.sock, e.stopAgent = sock, stop
	return fnErr
}

// reload saves the configuration and reloads the device, as L53 does, and returns whether the uptime shows it
// rebooted, what was compared, and the transcript of the reload's steps. The device must be seen down before
// it is waited for.
func (e *l64Env) reload(stage func(string)) (rebooted bool, why, transcript string, err error) {
	l := e.l
	addr := l.p.addr + ":22"
	var log strings.Builder
	var before string
	var beforeAt time.Time
	if err = e.admin(func(c *cliConn) error {
		out, err := l53Show(l, c, l53Uptime[l.p.name])
		before, beforeAt = out, time.Now()
		return err
	}); err != nil {
		return false, "", "", fmt.Errorf("the uptime before the reload: %w", err)
	}
	stage("uptime before the reload read")
	steps := slices.Clone(l53Reload[l.p.name])
	for i := range steps {
		if steps[i][0], err = l53BootLine(steps[i][0], before); err != nil {
			return false, "", "", fmt.Errorf("the reload steps: %w", err)
		}
	}
	var reloadAt, downAt time.Time
	downErr := make(chan error, 1)
	if err = e.admin(func(c *cliConn) error {
		for i, step := range steps {
			last := i == len(steps)-1
			if last {
				reloadAt = time.Now()
				stage("reload command sent")
				go func() {
					err := l53WaitDown(addr, 10*time.Minute)
					downAt = time.Now()
					downErr <- err
				}()
			}
			want := []string{"#", ">"}
			if step[1] != "" {
				want = []string{step[1]}
			}
			if last && step[1] == "" {
				fmt.Fprintf(&log, "reload step %q: sent, no prompt waited for\n", step[0])
				if err := c.send(step[0]); err != nil {
					return err
				}
				time.Sleep(3 * time.Second)
				continue
			}
			out, err := c.sendExpect(step[0], 90*time.Second, want...)
			fmt.Fprintf(&log, "reload step %q: err %v; the device said:\n%s\n", step[0], err, trimForNote(out))
			if err != nil {
				return err
			}
			if step[1] != "" {
				answered := len(c.transcript())
				if err := c.send(step[2]); err != nil {
					return err
				}
				if last {
					time.Sleep(5 * time.Second)
					fmt.Fprintf(&log, "after the answer %q, the device said:\n%s\n", step[2], trimForNote(c.transcript()[answered:]))
				}
			}
		}
		return nil
	}); err != nil {
		return false, "", log.String(), err
	}
	if err = <-downErr; err != nil {
		// As L53 does: ask the device once more, so the note says whether it ever went down.
		_ = e.admin(func(c *cliConn) error {
			up, _ := l53Show(l, c, l53Uptime[l.p.name])
			fmt.Fprintf(&log, "the device, asked after the failed wait, `%s`: %s\n", l53Uptime[l.p.name], trimForNote(up))
			return nil
		})
		return false, "", log.String(), fmt.Errorf("after the reload command: %w", err)
	}
	stage("seen down (no SSH banner on two connections in a row)")
	if err = l.waitDeviceReady(l.p.boot); err != nil {
		return false, "", log.String(), fmt.Errorf("after the reload: %w", err)
	}
	stage("seen up: SSH authentication served again")
	fmt.Fprintf(&log, "The reload command was sent at %s; the device was seen down (no SSH banner on two connections in a row) "+
		"at %s, and was serving SSH authentication again no later than %s after that.\n", reloadAt.UTC().Format("15:04:05"),
		downAt.UTC().Format("15:04:05"), time.Since(downAt).Round(time.Second))
	var after string
	var afterAt time.Time
	if err = e.admin(func(c *cliConn) error {
		out, err := l53Show(l, c, l53Uptime[l.p.name])
		after, afterAt = out, time.Now()
		return err
	}); err != nil {
		return false, "", log.String(), fmt.Errorf("the uptime after the reload: %w", err)
	}
	stage("uptime after the reload read; the daemon and agent are back")
	fmt.Fprintf(&log, "Before the reload, `%s` says: %q. After: %q.\n", l53Uptime[l.p.name],
		l53UptimeLine.FindAllString(before, -1), l53UptimeLine.FindAllString(after, -1))
	rebooted, why = l53Rebooted(before, after, afterAt.Sub(beforeAt))
	return rebooted, why, log.String(), nil
}

// l64CopyClient copies the Python package at src to dst, leaving out its tests and any build litter.
func l64CopyClient(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			switch d.Name() {
			case "tests", "__pycache__", "build", ".pytest_cache":
				return filepath.SkipDir
			}
			if strings.HasSuffix(d.Name(), ".egg-info") {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

// installClient puts ./clients/python[netmiko] in the lab venv, once per run, and records the versions of
// what the cells then use.
func installClient(t *testing.T) string {
	t.Helper()
	l64Install.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		env := append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		// From a temp copy, so the build leaves nothing in the tree; --force-reinstall so the venv runs this
		// tree's code. The venv is shared by every worktree: the version line names the commit installed.
		tmp, err := os.MkdirTemp("", "p49l64client")
		if err != nil {
			l64Versions = fmt.Sprintf("INSTALL FAILED: %v", err)
			return
		}
		defer os.RemoveAll(tmp)
		if err := l64CopyClient(filepath.Join(root, "clients", "python"), tmp); err != nil {
			l64Versions = fmt.Sprintf("INSTALL FAILED: copying clients/python: %v", err)
			return
		}
		out, se, exit, err := l64Run(ctx, env, tmp, venvPython, "-m", "pip", "install", "--disable-pip-version-check",
			"--force-reinstall", tmp+"[netmiko]")
		if err != nil || exit != 0 {
			l64Versions = fmt.Sprintf("INSTALL FAILED: exit %d %v\n%s%s", exit, err, trimForNote(out), trimForNote(se))
			return
		}
		out, se, exit, err = l64Run(ctx, env, root, venvPython, "-I", "-B", "-c",
			"import importlib.metadata as m, sys; print('Python', sys.version.split()[0], 'netmiko', m.version('netmiko'), "+
				"'paramiko', m.version('paramiko'), 'port49', m.version('port49'))")
		if err != nil || exit != 0 {
			l64Versions = fmt.Sprintf("VERSION READ FAILED: exit %d %v %s", exit, err, se)
			return
		}
		_, sv, _, _ := l64Run(ctx, env, root, "ssh", "-V")
		sha, _, _, _ := l64Run(ctx, env, root, "git", "-C", root, "rev-parse", "HEAD")
		l64Versions = strings.TrimSpace(out) + "; " + strings.TrimSpace(sv) + "; installed from clients/python at commit " +
			strings.TrimSpace(sha) + " into the shared lab venv"
	})
	if strings.Contains(l64Versions, "FAILED") {
		t.Fatalf("the lab venv: %s", l64Versions)
	}
	fmt.Fprintf(os.Stdout, "L64L65 client versions: %s\n", l64Versions)
	return l64Versions
}

// TestL64L65 measures L64 (`port49 ssh` under accept-new) and L65 (the Python client) on each selected
// platform. The reload cell (L64b) takes the device away for its boot budget, so it is run once, between the
// cells that need a key filed and the cells that replace it.
func TestL64L65(t *testing.T) {
	if os.Getenv("PORT49_LAB_SSH") != "1" {
		t.Skip("L64 and L65 reload each device: run them with `make lab-ssh` (PORT49_LAB_SSH=1)")
	}
	if _, err := os.Stat(venvPython); err != nil {
		t.Skipf("no client venv at %s: %v", venvPython, err)
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		versions := installClient(t)
		if err := testpki.WriteLab(filepath.Join(root, slicePKIDir), sliceEmail, time.Now()); err != nil {
			t.Fatal(err)
		}
		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := l.derivedConfig("slice", platformSessionAttributes[l.p.name], string(brokerYAML))
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the broker block, so nothing was measured: %v", err)
		}
		if err := l.awaitTACACS(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := l.stopDaemon(); err != nil {
				t.Errorf("could not stop the broker daemon: %v", err)
				return
			}
			std, err := l.configPath()
			if err != nil {
				t.Fatalf("derive this platform's daemon config: %v", err)
			}
			if err := l.startDaemonWith(std, true); err != nil {
				t.Fatalf("could not put port49d back on the lab config: %v", err)
			}
		}()

		// The private home: 0700, an ssh_config, an empty known_hosts. Nothing here touches the operator's
		// own ~/.ssh.
		home, err := os.MkdirTemp("", "p49l64home")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(home)
		sshDir := filepath.Join(home, ".ssh")
		keyDir := filepath.Join(home, "keys")
		for _, d := range []string{sshDir, keyDir} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		e := &l64Env{t: t, l: l, node: l.p.node, home: home, daemonCfg: cfg, keyDir: keyDir,
			khPath: filepath.Join(sshDir, "known_hosts"), cfgPath: filepath.Join(sshDir, "config"),
			driverPath: filepath.Join(home, "driver.py")}
		if err := os.WriteFile(e.driverPath, []byte(l64DriverScript), 0o600); err != nil {
			t.Fatal(err)
		}
		// writeConfig reads ssh -G after writing: ssh must read the private file and no other, with
		// UpdateHostKeys on.
		if err := e.writeConfig(false); err != nil {
			t.Fatalf("the private ssh_config: %v", err)
		}
		if err := e.writeKnownHosts(""); err != nil {
			t.Fatal(err)
		}
		if e.sock, e.stopAgent, err = e.newAgent(); err != nil {
			t.Fatal(err)
		}
		defer func() { e.stopAgent() }()

		stopCap := l.capture(t, "L64L65")
		defer stopCap()
		runL64L65(e, versions)
	})
}

// runL64L65 runs the cells in order and writes the two notes.
func runL64L65(e *l64Env, versions string) {
	l := e.l
	node := e.node
	addr := l.p.addr + ":22"

	// The ten seconds before anything: what the device says to port49d on its own.
	{
		from, off := time.Now(), l.mark()
		time.Sleep(10 * time.Second)
		e.idleNote = fmt.Sprintf("The 10s before the first cell: %d decision records and %d TACACS+ packets to or from the device.",
			len(l.recordsSince(off)), e.tacacsIn(from, time.Now()))
	}

	// L64 (a): the first contact. Read after the login, since ssh's UpdateHostKeys may file more key types
	// once authenticated.
	e.cell("L64a", l64CellBudget, func(ctx context.Context) (bool, string) {
		r := e.portSSH(ctx)
		es, ferr := e.keygenFind(ctx)
		var lines []string
		e.filedEntries = es
		for _, en := range es {
			lines = append(lines, en.Type)
			if e.filedType == "" {
				e.filedType = en.Type
			}
		}
		e.controlOK = l64ControlOK(r.packets, r.redeems)
		obs := fmt.Sprintf("`port49 ssh -v %s -- show version` with an empty known_hosts: exit %d; %d lines of output; ssh tried "+
			"%v, authenticated by `%s`; %d askpass asks (the keyboard-interactive and password methods tried); %d redeem records; "+
			"%d TACACS+ packets in the window (the positive control: it must be above 0); records: %s. ssh: %s. After the login "+
			"`ssh-keygen -F %s` finds %d line(s), of key types %v (a read error: %v); the file holds %d line(s).",
			node, r.exit, l64Lines(r.stdout), r.read.Methods, r.read.AuthenticatedBy,
			r.read.Asks(), r.redeems, r.packets, l64Summary(r.recs), r.read.Class, node, len(es), lines, ferr,
			l64KnownHostsLines(e.readKnownHosts()))
		obs += "\n\n```\n" + trimForNote(l64KeyLines(r.stderr)) + "\n```"
		return r.exit == 0 && strings.TrimSpace(r.stdout) != "" && len(es) > 0 && e.controlOK && r.err == nil, obs
	})

	// L65 (e1): Python against the entry port49 ssh filed.
	e.cell("L65e1", l64CellBudget, func(ctx context.Context) (bool, string) {
		before := l64KnownHostsLines(e.readKnownHosts())
		r := e.python(ctx)
		after := l64KnownHostsLines(e.readKnownHosts())
		return r.d.Outcome == "connected" && before == after && before > 0, fmt.Sprintf("`connect(%s)` against the entry `port49 ssh` "+
			"filed: %s; the file held %d line(s) before and %d after; %s. Driver stderr: %s", node, r.said(), before, after,
			r.counts(), trimForNote(l64Tail(r.stderr)))
	})

	// L64 (b): the reload, then port49 ssh again; M11: a key that changes here is marked, and the run goes on.
	e.cell("L64b", l64ReloadBudget, func(ctx context.Context) (bool, string) {
		// Every line filed, read before the reload: nothing filed is nothing to survive it.
		before, ferr := e.keygenFind(ctx)
		if len(before) == 0 {
			e.invalid = "L64a filed no key, so there is nothing for the reload to change; the reload was not run"
			return false, fmt.Sprintf("`ssh-keygen -F %s` finds no line (read error: %v).", node, ferr)
		}
		keyBefore, serr := labScan(ctx, addr)
		rebooted, why, steps, err := e.reload(func(s string) { fmt.Fprintln(os.Stdout, l64Stage(l.p.name, "L64b", s)) })
		if err != nil {
			e.reloadFailed = err.Error()
			return false, fmt.Sprintf("the reload failed: %v\n\n```\n%s\n```", err, trimForNote(steps))
		}
		var scanNote string
		keyChanged := false
		if keyAfter, aerr := labScan(ctx, addr); serr != nil || aerr != nil {
			scanNote = fmt.Sprintf("The scan (`labScan`'s key) before: %v; after: %v.", serr, aerr)
		} else if labFingerprint(keyAfter) != labFingerprint(keyBefore) {
			keyChanged = true
			scanNote = fmt.Sprintf("**The scan's key changed across the reload**: %s, then %s.", labFingerprint(keyBefore),
				labFingerprint(keyAfter))
		} else {
			scanNote = fmt.Sprintf("The scan's key is the same after the reload (%s).", labFingerprint(keyAfter))
		}
		r := e.portSSH(ctx)
		// This login is the nearest good one for the refusal cells that follow.
		e.controlOK = l64ControlOK(r.packets, r.redeems)
		if r.read.Banner || r.read.Class == "changed" || r.read.Class == "other_type" {
			keyChanged = true
		}
		// Every filed line again, secondary types included: any difference is a key that changed at the reload.
		after, _ := e.keygenFind(ctx)
		added, removed := l64Diff(before, after)
		if len(added)+len(removed) > 0 {
			keyChanged = true
		}
		if keyChanged {
			e.reloadKeyChanged = true
			fmt.Fprintf(os.Stdout, "RELOAD_KEY_CHANGED %s\n", l.p.name)
		}
		obs := fmt.Sprintf("The device rebooted: %v (%s). %s\n\nThe filed lines (type and key, compared with the host field left out) "+
			"before the reload: %d; after: %d; added by the login: %s; gone after it: %s.\n\n```\n%s\n```\n\n%s\n\nAfter it, "+
			"`port49 ssh -v %s -- show version`: exit %d; %d lines of output; %s; ssh: %s; the warning banner is present: %v.",
			rebooted, why, scanNote, len(before), len(after), l64Types(added), l64Types(removed), trimForNote(steps), e.idleNote, node,
			r.exit, l64Lines(r.stdout), r.counts(), r.read.Class, r.read.Banner)
		obs += "\n\n```\n" + trimForNote(l64KeyLines(r.stderr)) + "\n```"
		return rebooted && !keyChanged && r.exit == 0 && !r.read.Banner && r.read.Class == "clean" && len(r.read.Added) == 0 &&
			r.err == nil, obs
	})
	if e.reloadFailed != "" {
		// The device is not back: the cells after it would grind against it and read as client results.
		for _, id := range l64AfterReload {
			e.results = append(e.results, l64Result{id, "SKIPPED", "reload_failed: the device was not back after L64b (" +
				e.reloadFailed + ")", 0})
			fmt.Fprintln(os.Stdout, l64Progress(l.p.name, id, "SKIPPED", 0))
		}
		l64WriteNotes(e, versions)
		return
	}

	// L64 (c) and (d): the entry replaced under the name.
	e.replaced("L64c", false, func(ctx context.Context, typ string) (bool, string) {
		r := e.portSSH(ctx)
		ok, why := l64GradeSSHRefusal(r.read, r.exit, r.packets, r.other)
		return ok, fmt.Sprintf("`port49 ssh` against an entry replaced by a fresh `%s` key: exit %d; ssh: %s (filed type %q, sent "+
			"type %q); %d TACACS+ packets; records: %s; names `ssh-keygen -R`: %v. %s\n\n```\n%s\n```", typ, r.exit, r.read.Class,
			r.read.FiledType, r.read.SentType, r.packets, l64Summary(r.recs), r.read.NamesKeygenR, why, trimForNote(l64KeyLines(r.stderr)))
	})
	e.replaced("L64d", true, func(ctx context.Context, typ string) (bool, string) {
		r := e.portSSH(ctx)
		ok, why := l64GradeSSHRefusal(r.read, r.exit, r.packets, r.other)
		return ok, fmt.Sprintf("`port49 ssh` against an entry replaced by a `%s` key, a type other than the filed `%s`: exit %d; "+
			"ssh: %s (filed type %q, sent type %q); %d TACACS+ packets; records: %s; names `ssh-keygen -R`: %v. %s\n\n```\n%s\n```",
			typ, e.filedType, r.exit, r.read.Class, r.read.FiledType, r.read.SentType, r.packets, l64Summary(r.recs),
			r.read.NamesKeygenR, why, trimForNote(l64KeyLines(r.stderr)))
	})

	// L65 (a): Python's first contact, from an empty known_hosts that hashes.
	e.cell("L65a", l64CellBudget, func(ctx context.Context) (bool, string) {
		if err := e.writeConfig(true); err != nil {
			return false, err.Error()
		}
		if err := e.writeKnownHosts(""); err != nil {
			return false, err.Error()
		}
		r := e.python(ctx)
		content := e.readKnownHosts()
		es, ferr := e.keygenFind(ctx)
		e.pyFile = content
		var types []string
		hashed := len(es) > 0
		for _, en := range es {
			types = append(types, en.Type)
			hashed = hashed && en.Hashed
		}
		// The line of the type Paramiko accepted: what L65e2 verifies and L65f revokes.
		var found bool
		e.pyEntry, found = l64PickEntry(es, r.d.KeyType)
		return r.d.Outcome == "connected" && l64KnownHostsLines(content) == 1 && hashed && found, fmt.Sprintf("`connect(%s)` from an empty "+
			"known_hosts, with `HashKnownHosts yes`: %s; the file holds %d line(s); `ssh-keygen -F %s` finds %d, of key types %v, "+
			"hashed: %v (read error: %v); the key Paramiko accepted: `%s`; %s. Driver stderr: %s", node, r.said(),
			l64KnownHostsLines(content), node, len(es), types, hashed, ferr, r.d.KeyType, r.counts(), trimForNote(l64Tail(r.stderr)))
	})
	e.cell("L65b", l64CellBudget, func(ctx context.Context) (bool, string) {
		before := l64KnownHostsLines(e.readKnownHosts())
		r := e.python(ctx)
		after := l64KnownHostsLines(e.readKnownHosts())
		// This connection is the nearest good login for L65c and L65d.
		e.controlOK = l64ControlOK(r.packets, r.redeems)
		return r.d.Outcome == "connected" && before == after && before > 0, fmt.Sprintf("A second `connect(%s)`: %s; the file held "+
			"%d line(s) before and %d after; %s.", node, r.said(), before, after, r.counts())
	})

	// L65 (c) and (d): the same replacements, through connect.
	e.replaced("L65c", false, func(ctx context.Context, typ string) (bool, string) {
		r := e.python(ctx)
		ok, why := l64GradePyRefusal(r.d, "", r.packets, r.other)
		return ok, fmt.Sprintf("`connect(%s)` against an entry replaced by a fresh `%s` key: %s; %s. %s", node, typ, r.said(), r.counts(), why)
	})
	e.replaced("L65d", true, func(ctx context.Context, typ string) (bool, string) {
		r := e.python(ctx)
		ok, why := l64GradePyRefusal(r.d, "", r.packets, r.other)
		return ok, fmt.Sprintf("`connect(%s)` against an entry replaced by a `%s` key, a type other than the filed `%s`: %s; %s. %s",
			node, typ, e.filedType, r.said(), r.counts(), why)
	})

	// L65 (e2): port49 ssh against the entry Python filed.
	e.cell("L65e2", l64CellBudget, func(ctx context.Context) (bool, string) {
		if e.pyFile == "" {
			return false, "no entry was filed by L65a, so there is nothing to verify"
		}
		if err := e.writeKnownHosts(e.pyFile); err != nil {
			return false, err.Error()
		}
		if e.pyEntry.Blob == "" {
			return false, "L65a recorded no line for the key Python negotiated, so there is no line to verify"
		}
		before := l64KnownHostsLines(e.pyFile)
		r := e.portSSH(ctx)
		after := l64KnownHostsLines(e.readKnownHosts())
		// This login is the nearest good one for L65f1 and L65f2.
		e.controlOK = l64ControlOK(r.packets, r.redeems)
		es, ferr := e.keygenFind(ctx)
		ok, why := l64GradeE2(r.read, r.exit, e.pyEntry, es)
		added, _ := l64Diff([]l64Entry{e.pyEntry}, es)
		return ok && r.err == nil, fmt.Sprintf("`port49 ssh -v %s -- show version` against the entry Python filed (`%s`): "+
			"exit %d; ssh: %s; the file held %d line(s) before and %d after, of key types %s (UpdateHostKeys is on; types it adds "+
			"after authentication are an observation, the negotiated key's line must be unchanged; read error: %v); %s. %s\n\n```\n%s\n```",
			node, e.pyEntry.Type, r.exit, r.read.Class, before, after, l64Types(es), ferr, r.counts(), why,
			trimForNote(l64KeyLines(r.stderr))) + l64Added(added)
	})

	// L65 (f): the device's own key named by an @revoked line, beside the filed entry and then alone.
	e.cell("L65f1", l64CellBudget, func(ctx context.Context) (bool, string) {
		line, err := e.revokedLine()
		if err != nil {
			return false, err.Error()
		}
		if err := e.writeKnownHosts(e.pyFile + line); err != nil {
			return false, err.Error()
		}
		quiet := e.waitQuiet(ctx)
		r := e.python(ctx)
		ok, why := l64GradePyRefusal(r.d, "host_key_revoked", r.packets, r.other)
		return ok, fmt.Sprintf("`connect(%s)` with an `@revoked` line naming the key Python filed (`%s`) beside the filed entry: %s; %s. %s %s.",
			node, e.pyEntry.Type, r.said(), r.counts(), why, quiet)
	})
	e.cell("L65f2", l64CellBudget, func(ctx context.Context) (bool, string) {
		line, err := e.revokedLine()
		if err != nil {
			return false, err.Error()
		}
		if err := e.writeKnownHosts(line); err != nil {
			return false, err.Error()
		}
		quiet := e.waitQuiet(ctx)
		r := e.python(ctx)
		after := e.readKnownHosts()
		ok, why := l64GradePyRefusal(r.d, "host_key_revoked", r.packets, r.other)
		filed := after != line
		if filed {
			ok, why = false, strings.TrimSpace(why+" The file changed: something was filed.")
		}
		return ok, fmt.Sprintf("`connect(%s)` from a known_hosts holding only that `@revoked` line, at first contact: %s; %s; the file "+
			"held %d key line(s) after, and is unchanged: %v. %s %s.", node, r.said(), r.counts(), l64KnownHostsLines(after), !filed, why, quiet)
	})

	l64WriteNotes(e, versions)
}

// replaced runs a cell that needs the entry under the device's name replaced by a fresh key: of the filed
// type, or (other) of another type only. The device is given a quiet window first.
func (e *l64Env) replaced(id string, other bool, fn func(ctx context.Context, typ string) (bool, string)) {
	e.cell(id, l64CellBudget, func(ctx context.Context) (bool, string) {
		if e.filedType == "" {
			return false, "L64a filed no key, so there is no filed type to replace"
		}
		typ := e.filedType
		if other {
			typ = l64OtherType(e.filedType)
		}
		blob, err := e.freshKey(ctx, typ)
		if err != nil {
			return false, err.Error()
		}
		if err := e.writeKnownHosts(fmt.Sprintf("%s %s %s\n", e.node, typ, blob)); err != nil {
			return false, err.Error()
		}
		quiet := e.waitQuiet(ctx)
		pass, obs := fn(ctx, typ)
		return pass, obs + " " + quiet + "."
	})
}

// revokedLine is an @revoked line for the key Python filed in L65a, of the type the driver said Paramiko
// accepted: the device's own key at this moment, whatever L64a filed before the reload.
func (e *l64Env) revokedLine() (string, error) {
	if e.pyEntry.Type == "" || e.pyEntry.Blob == "" {
		return "", errors.New("L65a recorded no line for the key Python negotiated, so no @revoked line can name the device's own")
	}
	if _, err := base64.StdEncoding.DecodeString(e.pyEntry.Blob); err != nil {
		return "", fmt.Errorf("the filed key is not base64: %w", err)
	}
	return fmt.Sprintf("@revoked %s %s %s\n", e.node, e.pyEntry.Type, e.pyEntry.Blob), nil
}

// l64Added is the sentence a note carries for key lines UpdateHostKeys added.
func l64Added(added []l64Entry) string {
	if len(added) == 0 {
		return ""
	}
	return "\n\nObserved: ssh filed further key types after authentication (UpdateHostKeys): " + l64Types(added) + "."
}

func l64Summary(recs []map[string]any) string {
	n := map[string]int{}
	var order []string
	for _, r := range recs {
		ev := str(r, "event")
		if n[ev] == 0 {
			order = append(order, ev)
		}
		n[ev]++
	}
	if len(order) == 0 {
		return "none"
	}
	var parts []string
	for _, ev := range order {
		parts = append(parts, fmt.Sprintf("%s x%d", ev, n[ev]))
	}
	return strings.Join(parts, ", ")
}

// l64Tail is the last lines of a driver's stderr.
func l64Tail(s string) string { return l53Tail(strings.TrimSpace(s), 8) }

// l64WriteNotes writes results/L64-<platform>.md and L65-<platform>.md from the cells.
func l64WriteNotes(e *l64Env, versions string) {
	t, l := e.t, e.l
	for _, entry := range []string{"L64", "L65"} {
		var b strings.Builder
		fmt.Fprintf(&b, "Client versions in this run: %s.\n\n", versions)
		fmt.Fprintf(&b, "%s\n\n", e.idleNote)
		if e.reloadKeyChanged {
			fmt.Fprintf(&b, "**RELOAD_KEY_CHANGED %s**: the key the device presents changed across the reload (cell L64b). Per the plan's "+
				"gate (pre-flight M11) no conclusion is written and nothing was weakened; this is for Ryan.\n\n", l.p.name)
		}
		b.WriteString("| cell | outcome | elapsed |\n|---|---|---|\n")
		for _, r := range e.results {
			if strings.HasPrefix(r.id, entry) {
				fmt.Fprintf(&b, "| %s | %s | %s |\n", r.id, r.outcome, r.elapsed.Round(100*time.Millisecond))
			}
		}
		for _, r := range e.results {
			if strings.HasPrefix(r.id, entry) {
				fmt.Fprintf(&b, "\n### %s: %s\n\n%s\n", r.id, r.outcome, r.observation)
			}
		}
		claim := "`port49 ssh` under OpenSSH's accept-new against " + l.p.name + " (policy engine spec §15, L64): (a) a first contact, " +
			"(b) after a reload, (c) a replaced key of the filed type, (d) a key of another type only."
		if entry == "L65" {
			claim = "The Python client (`port49.netmiko.connect`) against " + l.p.name + " (policy engine spec §15, L65): (a) a first " +
				"contact, (b) a second connection, (c) and (d) a replaced key, (e) the entries each client filed, (f) an `@revoked` key."
		}
		l.result(t, entry, claim, b.String())
	}
}
