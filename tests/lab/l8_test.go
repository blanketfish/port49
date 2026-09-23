//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// L8: the maximum password length the platform accepts at an interactive
// prompt.
//
// The first method seeded a token of each length under its own username. That
// stopped working when port49d began minting every token itself at one length
// (30 characters, design §8), so this measures without a seeded secret at all.
//
// It types a probe password of length N under a username that holds no token,
// and reads `auth.credential_sha256` off the redeem record port49 writes for
// the refusal. That field is the SHA-256 of exactly the bytes the device put
// in the credential field, whatever the outcome. Hashing every prefix of the
// probe and looking for the one that matches says how many characters
// arrived: all N, a truncation to K, or something that is no prefix at all
// (the device altered it). No record at all means the device refused the
// password itself and sent port49 nothing.
//
// The probe is a cycle of ten lowercase letters. That is deliberately not
// token-shaped (labcreds.MinDistinct), so the note can quote it and the
// evidence audit does not mistake it for a credential, and it has no character
// a device might treat specially.
//
// The 30-character answer is not left to a probe. A real minted token is used
// for one full login, so "does the design's handle work here" is answered by
// the thing itself logging in.
func TestL8PasswordLength(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L8")
		defer stop()

		handle := l.l8Handle(t)

		probes := map[int]l8Probe{}
		run := func(n int) l8Probe {
			if p, ok := probes[n]; ok {
				return p
			}
			p := l.l8ProbeLength(n)
			probes[n] = p
			t.Logf("%s: L8 length %d: %s", l.p.name, n, p.outcome())
			return p
		}
		for _, n := range l8Sweep {
			run(n)
		}

		// Bisect the first boundary the sweep found, so the note gives a
		// number rather than a bracket.
		lo, hi := l8Boundary(probes)
		bisected := ""
		if hi > 0 && hi-lo > 1 {
			bisected = " Lengths not in the fixed sweep were chosen by bisecting the boundary it found."
		}
		for hi > 0 && hi-lo > 1 {
			mid := (lo + hi) / 2
			if run(mid).intact() {
				lo = mid
			} else {
				hi = mid
			}
		}

		anySeen := false
		for _, p := range probes {
			anySeen = anySeen || len(p.arrived) > 0
		}
		if !anySeen {
			t.Fatalf("no redeem record arrived for any probe length, so nothing was measured")
		}

		deviceLog := l.l8DeviceLog(t)

		var ns []int
		for n := range probes {
			ns = append(ns, n)
		}
		sort.Ints(ns)

		var table strings.Builder
		table.WriteString("| length | reached port49 | method | characters that arrived | SSH result |\n|---|---|---|---|---|\n")
		for _, n := range ns {
			p := probes[n]
			fmt.Fprintf(&table, "| %d | %s | %s | %s | %s |\n", n, p.reached(), p.methods(), p.arrivedText(), p.sshResult())
		}

		var failed strings.Builder
		for _, n := range ns {
			p := probes[n]
			if p.intact() {
				continue
			}
			fmt.Fprintf(&failed, "**Length %d, username `%s`.** Sent at the SSH password prompt (and again at the "+
				"keyboard-interactive prompt if the device offered one):\n\n```\n%s\n```\n\n", n, p.user, p.password)
			fmt.Fprintf(&failed, "What port49 received: %s.\n\n", p.arrivedDetail())
			fmt.Fprintf(&failed, "The device replied:\n\n```\n%s\n```\n\n", p.deviceReply())
		}
		if failed.Len() == 0 {
			failed.WriteString("None: every length tried arrived intact.\n\n")
		}

		var passed strings.Builder
		intactReply := probes[l8Sweep[0]].deviceReply()
		fmt.Fprintf(&passed, "The device's reply to an intact probe, for comparison (length %d, which port49 "+
			"received and refused):\n\n```\n%s\n```\n", l8Sweep[0], intactReply)
		if hi > 0 && probes[hi].deviceReply() == intactReply {
			fmt.Fprintf(&passed, "\nThe two replies are identical. An operator who types a password of %d characters "+
				"or more sees exactly what a wrong password produces, and port49 never hears of the attempt.\n", hi)
		}

		longest := l8Longest(probes)
		longestText := "**No probe length arrived intact.**"
		if longest > 0 {
			longestText = fmt.Sprintf("**Longest password that arrived intact: %d characters.**", longest)
			if hi == 0 {
				longestText = fmt.Sprintf("**Every length tried arrived intact, up to %d characters; no limit was "+
					"found below that.**", longest)
			} else {
				longestText += fmt.Sprintf(" %d characters did not.", hi)
			}
		}

		obs := fmt.Sprintf("Each probe is a password of the given length typed under a username that holds no "+
			"token, so port49 refuses it `token_not_found` and logs `auth.credential_sha256` — the SHA-256 of "+
			"exactly the bytes the device sent. \"Characters that arrived\" is the length of the one prefix of "+
			"the probe whose hash equals that field; `all N` means the password reached port49 byte for byte. "+
			"No record at all means the device refused the password locally and sent nothing. The probe is "+
			"`abcdefghij` repeated and cut to length.%s\n\n"+
			"%s\n%s\n\n"+
			"### The design's 30-character handle\n\n%s\n\n"+
			"### Every length that did not arrive intact\n\n%s"+
			"%s\n"+
			"### Device log\n\n%s\n\n%s",
			bisected, table.String(), longestText, handle, failed.String(), passed.String(), deviceLog,
			l8MethodNote(probes))
		l.result(t, "L8", "The maximum password length each platform accepts at an interactive prompt.", obs)
	})
}

// l8Sweep brackets the lengths a device is likely to cap at, each side of
// each power of two, plus 138, the longest the first method tried.
var l8Sweep = []int{30, 31, 32, 63, 64, 65, 127, 128, 129, 138, 255, 256, 257, 512, 1024}

// l8Arrived is one redeem record for a probe: what port49 was handed.
type l8Arrived struct {
	method string
	reason string
	// n is how many leading characters of the probe the credential was, or
	// -1 when it was not a prefix of the probe at all.
	n int
}

type l8Probe struct {
	n        int
	user     string
	password string
	err      error
	banner   string
	prompts  []string // keyboard-interactive rounds, verbatim
	arrived  []l8Arrived
}

func (p l8Probe) intact() bool {
	for _, a := range p.arrived {
		if a.n == p.n {
			return true
		}
	}
	return false
}

func (p l8Probe) reached() string {
	if len(p.arrived) == 0 {
		return "no"
	}
	return fmt.Sprintf("yes (%d record(s))", len(p.arrived))
}

func (p l8Probe) methods() string {
	if len(p.arrived) == 0 {
		return "—"
	}
	var m []string
	for _, a := range p.arrived {
		m = append(m, "`"+a.method+"`")
	}
	return strings.Join(m, ", ")
}

func (p l8Probe) arrivedText() string {
	if len(p.arrived) == 0 {
		return "—"
	}
	var s []string
	for _, a := range p.arrived {
		switch {
		case a.n == p.n:
			s = append(s, fmt.Sprintf("all %d", p.n))
		case a.n < 0:
			s = append(s, "**altered** (no prefix matches)")
		default:
			s = append(s, fmt.Sprintf("**first %d only**", a.n))
		}
	}
	return strings.Join(s, ", ")
}

func (p l8Probe) arrivedDetail() string {
	if len(p.arrived) == 0 {
		return "nothing — no redeem record for this username reached the decision log, so the device never asked"
	}
	var s []string
	for _, a := range p.arrived {
		s = append(s, fmt.Sprintf("a `%s` exchange refused `%s` carrying %s", a.method, a.reason, p.arrivedOne(a)))
	}
	return strings.Join(s, "; ")
}

func (p l8Probe) arrivedOne(a l8Arrived) string {
	switch {
	case a.n == p.n:
		return fmt.Sprintf("all %d characters", p.n)
	case a.n < 0:
		return "a credential that is no prefix of the probe"
	default:
		return fmt.Sprintf("the first %d characters only", a.n)
	}
}

func (p l8Probe) sshResult() string {
	if p.err == nil {
		return "logged in"
	}
	return "rejected"
}

func (p l8Probe) outcome() string {
	return fmt.Sprintf("reached=%s arrived=%s ssh=%s", p.reached(), p.arrivedText(), p.sshResult())
}

// deviceReply is everything the device said back during authentication:
// the SSH banner, each keyboard-interactive prompt, and how the exchange ended.
func (p l8Probe) deviceReply() string {
	var b strings.Builder
	if p.banner != "" {
		fmt.Fprintf(&b, "[SSH banner]\n%s\n", strings.TrimRight(p.banner, "\r\n"))
	}
	for _, q := range p.prompts {
		fmt.Fprintf(&b, "[keyboard-interactive prompt]\n%s\n", q)
	}
	if p.err != nil {
		fmt.Fprintf(&b, "[SSH authentication result]\n%v", p.err)
	} else {
		b.WriteString("[SSH authentication result]\nsucceeded")
	}
	return b.String()
}

func l8Password(n int) string {
	return strings.Repeat("abcdefghij", n/10+1)[:n]
}

// l8ProbeLength types one probe and reads back what port49 made of it.
func (l *lab) l8ProbeLength(n int) l8Probe {
	p := l8Probe{n: n, user: fmt.Sprintf("l8len%d", n), password: l8Password(n)}
	off := l.mark()

	nc, err := net.DialTimeout("tcp", l.p.addr+":22", 45*time.Second)
	if err != nil {
		p.err = err
		return p
	}
	nc.SetDeadline(time.Now().Add(90 * time.Second))
	cfg := l8SSHConfig(p.user, p.password, &p)
	c, chans, reqs, err := ssh.NewClientConn(nc, l.p.addr+":22", cfg)
	if err != nil {
		p.err = err
		nc.Close()
	} else {
		ssh.NewClient(c, chans, reqs).Close()
	}

	want := func(rs []map[string]any) bool { return len(l8Redeems(rs, p.user)) > 0 }
	recs := l.waitForRecords(off, 10*time.Second, want)
	// A keyboard-interactive attempt may follow a password one: give it a
	// moment to land beside the first.
	if want(recs) {
		recs = l.drainRecords(off, 3*time.Second)
	}
	for _, r := range l8Redeems(recs, p.user) {
		a := sub(r, "auth")
		p.arrived = append(p.arrived, l8Arrived{
			method: str(a, "method"),
			reason: str(r, "reason"),
			n:      l8PrefixLen(p.password, str(a, "credential_sha256")),
		})
	}
	return p
}

// l8SSHConfig is dial's configuration, recording what the device says instead
// of only answering it.
func l8SSHConfig(user, password string, p *l8Probe) *ssh.ClientConfig {
	base := labSSHConfig(user, password)
	base.Auth = []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			p.prompts = append(p.prompts, fmt.Sprintf("name=%q instruction=%q questions=%q", name, instruction, questions))
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		}),
	}
	base.BannerCallback = func(msg string) error {
		p.banner += msg
		return nil
	}
	return base
}

func l8Redeems(recs []map[string]any, user string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "event") != "redeem" {
			continue
		}
		if s := sub(r, "session"); s != nil && str(s, "username") == user {
			out = append(out, r)
		}
	}
	return out
}

// l8PrefixLen is the length of the prefix of pw whose SHA-256 is sum, or -1.
func l8PrefixLen(pw, sum string) int {
	for k := len(pw); k >= 0; k-- {
		h := sha256.Sum256([]byte(pw[:k]))
		if hex.EncodeToString(h[:]) == sum {
			return k
		}
	}
	return -1
}

// l8Boundary returns the longest intact length below the shortest length that
// did not arrive intact, and that shortest length; hi is 0 when every length
// arrived intact.
func l8Boundary(probes map[int]l8Probe) (lo, hi int) {
	for n, p := range probes {
		if !p.intact() && (hi == 0 || n < hi) {
			hi = n
		}
	}
	for n, p := range probes {
		if p.intact() && n > lo && (hi == 0 || n < hi) {
			lo = n
		}
	}
	return lo, hi
}

// l8Longest is the longest length that arrived intact below the first one that
// did not; every length is monotone on the images measured so far, so nothing
// above that boundary is counted.
func l8Longest(probes map[int]l8Probe) int {
	lo, _ := l8Boundary(probes)
	return lo
}

// l8Handle logs in with a real minted token, the design's 30-character handle.
func (l *lab) l8Handle(t *testing.T) string {
	t.Helper()
	user, secret := l.nextLogin(t)
	off := l.mark()
	_, err := l.login(user, secret, "show version")
	recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		return redeemFor(rs, user) != nil
	})
	rec := redeemFor(recs, user)
	if rec == nil {
		t.Fatalf("a login with a minted %d-character token produced no redeem record (SSH: %v)", len(secret), err)
	}
	h := sha256.Sum256([]byte(secret))
	intact := str(sub(rec, "auth"), "credential_sha256") == hex.EncodeToString(h[:])
	verdict := "**does not work**"
	if err == nil && str(rec, "reason") == "token_redeemed" && intact {
		verdict = "**works**"
	}
	ssh := "logged in"
	if err != nil {
		ssh = fmt.Sprintf("rejected: `%v`", err)
	}
	return fmt.Sprintf("A token port49d minted for this run (%d characters; not quoted, it is a credential) was "+
		"typed under `%s`. port49 answered `%s` `%s` over `%s`; the credential hash it logged %s the hash of the "+
		"token; SSH %s. The 30-character handle on this platform: %s.",
		len(secret), user, str(rec, "verdict"), str(rec, "reason"), str(sub(rec, "auth"), "method"),
		map[bool]string{true: "equals", false: "does **not** equal"}[intact], ssh, verdict)
}

// l8DeviceLog reads what the device logged about the probes, on the platforms
// where the harness has an admin CLI to read it with. It stops port49d to open
// that CLI (withAdminCLI), so it runs after every probe.
func (l *lab) l8DeviceLog(t *testing.T) string {
	t.Helper()
	var open func(*lab) (*cliConn, error)
	var cmd string
	switch l.p.sel {
	case "nxos":
		open = func(l *lab) (*cliConn, error) { return l.nxosCLI(breakglassUser, breakglassPassword) }
		cmd = "show logging logfile | include l8len"
	case "iosxe":
		open = func(l *lab) (*cliConn, error) { return l.iosxeCLI(breakglassUser, breakglassPassword) }
		cmd = "show logging | include l8len"
	default:
		return "Not read on this platform."
	}
	var out string
	l.withAdminCLI(t, open, func(c *cliConn) error {
		var err error
		out, err = c.sendExpect(cmd, 90*time.Second, c.prompt)
		return err
	})
	out = strings.TrimSpace(strings.ReplaceAll(out, "\r", ""))
	return fmt.Sprintf("Read with port49d stopped, over the break-glass account:\n\n```\n%s\n```", out)
}

// l8MethodNote says what the method column means for PAP. The interactive
// prompt is what an operator types at; which TACACS+ exchange the device turns
// that into is its own choice, and on NX-OS it is PAP.
func l8MethodNote(probes map[int]l8Probe) string {
	methods := map[string]bool{}
	for _, p := range probes {
		for _, a := range p.arrived {
			methods[a.method] = true
		}
	}
	if methods["pap"] {
		return "The `method` column is what the device chose, not this test: this platform carries a password " +
			"typed at the interactive SSH prompt to port49 as a PAP START. So the limit above is also this " +
			"platform's PAP limit **for SSH logins**; whether a PAP client on another path (the console, PPP) " +
			"is bounded the same way is not measured here."
	}
	return "The `method` column is what the device chose, not this test. No exchange from this platform " +
		"arrived as PAP, so this note says nothing about a PAP limit; it measures the interactive SSH prompt only."
}
