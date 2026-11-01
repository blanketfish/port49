//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blanketfish/port49/internal/testpki"
)

// l53Console is, per platform, the console commands that may show the SSH
// host key or its fingerprint. Which one does, and in what form, is what L53
// measures: each runs, its output goes into the note, and l53Shown names the
// form it holds the scanned key in, if any.
var l53Console = map[string][]string{
	"arista_eos": {"show management ssh hostkey ed25519 public", "show management ssh hostkey ecdsa-nistp256 public",
		"show management ssh hostkey rsa public"},
	"cisco_nxos":  {"show ssh key"},
	"cisco_iosxe": {"show ip ssh", "show crypto key mypubkey rsa"},
	"juniper_vjunos-router": {"file show /etc/ssh/ssh_host_ed25519_key.pub", "file show /etc/ssh/ssh_host_ecdsa_key.pub",
		"file show /etc/ssh/ssh_host_rsa_key.pub"},
	"juniper_vsrx": {"file show /etc/ssh/ssh_host_ed25519_key.pub", "file show /etc/ssh/ssh_host_ecdsa_key.pub",
		"file show /etc/ssh/ssh_host_rsa_key.pub"},
}

// l53Reload is, per platform, the lines that save the configuration and
// reload, each with the prompt that may follow it ("" for none expected) and
// the answer to give. A prompt that differs fails the step with the
// transcript in the note: fix the prompt here, never the claim. NX-OS sets
// its boot variable first: the N9Kv was first booted from the loader by the
// vrnetlab launcher and has none, so a reload stopped at `loader >` (measured
// on the first run); the boot variable is what a real switch has. The image
// it names is the one `show version` says the switch booted ({nxos_image}).
var l53Reload = map[string][][3]string{
	"arista_eos": {{"write memory", "", ""}, {"reload now", "", ""}},
	"cisco_nxos": {{"configure terminal", "", ""}, {"boot nxos {nxos_image}", "", ""},
		{"end", "", ""}, {"copy running-config startup-config", "", ""}, {"reload", "(y/n)", "y"}},
	"cisco_iosxe":           {{"write memory", "", ""}, {"reload", "[confirm]", ""}},
	"juniper_vjunos-router": {{"request system reboot", "[yes,no]", "yes"}},
	"juniper_vsrx":          {{"request system reboot", "[yes,no]", "yes"}},
}

// l53Uptime is, per platform, a command whose output says how long the
// device has been up or when it booted. It is read before and after the
// reload, so the note shows the device went down (pre-flight I-6).
var l53Uptime = map[string]string{
	"arista_eos":            "show version",
	"cisco_nxos":            "show version",
	"cisco_iosxe":           "show version",
	"juniper_vjunos-router": "show system uptime",
	"juniper_vsrx":          "show system uptime",
}

var l53UptimeLine = regexp.MustCompile(`(?im)^.*(uptime|booted).*$`)

// l53Log is, per platform, the commands that show the device's own log. Each
// is read before the scan and after it, and the note keeps the lines the
// second read has that the first did not, each with the step it was written
// in. The Junos images log to `messages` through the syslog stanza in
// configs/vjunos-startup.conf; without it vSRX has no such file at all.
var l53Log = map[string][]string{
	"arista_eos":            {"show logging", "bash sudo cat /var/log/secure"},
	"cisco_nxos":            {"show logging logfile"},
	"cisco_iosxe":           {"show logging"},
	"juniper_vjunos-router": {"show log messages"},
	"juniper_vsrx":          {"show log messages"},
}

// l53ControlUser is the user of the log's positive control: a refused SSH
// login as an account that does not exist. A log that does not show it is a
// log that records nothing of a login, so its silence about the scan proves
// nothing (task 8 review I-2).
const l53ControlUser = "l53-control"

// l53ControlLine is, per platform, what the control's line in the log
// matches. The user's name is in it where the log writes one. NX-OS masks
// the name (`Authentication failure for illegal user *****`) and IOS-XE
// writes none (an SSH2_USERAUTH line for an empty user, Failed), so there it is the line
// for a failed login nearest the control's window, and the note says that is
// what was matched. Found by logging in as l53-control and reading each log
// (task 8 fix round 1).
var l53ControlLine = map[string]*regexp.Regexp{
	"arista_eos":            regexp.MustCompile(regexp.QuoteMeta(l53ControlUser)),
	"cisco_nxos":            regexp.MustCompile(`PAM: Authentication failure for illegal user`),
	"cisco_iosxe":           regexp.MustCompile(`SSH2_USERAUTH: User '' .*Failed`),
	"juniper_vjunos-router": regexp.MustCompile(regexp.QuoteMeta(l53ControlUser)),
	"juniper_vsrx":          regexp.MustCompile(regexp.QuoteMeta(l53ControlUser)),
}

// l53Window is a span of host time a step of the test took.
type l53Window struct {
	from, to time.Time
}

// l53Slack is how far outside a step's window a log line may be stamped and
// still be the step's: the logs stamp whole seconds, truncated.
const l53Slack = 2 * time.Second

var l53Clock = regexp.MustCompile(`(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?`)

// l53ClockOf is the time of day of the first HH:MM:SS in line, which is where
// every platform's log stamps it, and whether there is one.
func l53ClockOf(line string) (time.Duration, bool) {
	m := l53Clock.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}
	h, _ := strconv.Atoi(m[1])
	mi, _ := strconv.Atoi(m[2])
	s, _ := strconv.Atoi(m[3])
	d := time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute + time.Duration(s)*time.Second
	if m[4] != "" {
		frac, _ := strconv.ParseFloat("0."+m[4], 64)
		d += time.Duration(frac * float64(time.Second))
	}
	return d, true
}

// l53TimeOfDay is t's time of day in UTC.
func l53TimeOfDay(t time.Time) time.Duration {
	t = t.UTC()
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute +
		time.Duration(t.Second())*time.Second + time.Duration(t.Nanosecond())
}

// l53Wrap folds d into [-12h, 12h): a time of day is compared across midnight.
func l53Wrap(d time.Duration) time.Duration {
	const day = 24 * time.Hour
	d %= day
	switch {
	case d >= day/2:
		d -= day
	case d < -day/2:
		d += day
	}
	return d
}

// l53In reports whether a log stamp t, with the device's clock offset from
// the host's removed, is inside w.
func l53In(t, offset time.Duration, w l53Window) bool {
	d := l53Wrap(t - offset - l53TimeOfDay(w.from))
	return d >= -l53Slack && d <= w.to.Sub(w.from)+l53Slack
}

// l53Step names the step of the test a log line was written in, by its own
// stamp and only by that: "scan" is the scan's window and nothing else, so
// the harness's readiness probes (which fail logins and dial SSH too) are
// never credited to it (task 8 review I-1).
func l53Step(line string, offset time.Duration, scan, control l53Window) string {
	t, ok := l53ClockOf(line)
	switch {
	case !ok:
		return "no time"
	case l53In(t, offset, scan):
		return "scan"
	case l53In(t, offset, control):
		return "control"
	case l53Wrap(t-offset-l53TimeOfDay(scan.from)) < 0:
		return "before the scan"
	case l53Wrap(t-offset-l53TimeOfDay(control.from)) < 0:
		return "between the scan and the control"
	}
	return "after the control"
}

// l53LogNote reads the lines a log gained between its two reads (fresh). It
// finds the control's line, which says whether the log records a refused login
// at all and how far the device's clock is from the host's; it sorts every line
// into its step; and it says whether the log can speak to the scan. The
// second result is false when the control's line is missing: the log clause
// is then unmeasured on this log.
func l53LogNote(cmd string, fresh []string, scan, control l53Window, breakglass string,
	controlRe *regexp.Regexp) (string, bool) {
	// The control's line is the one controlRe matches nearest the window of
	// the login that made it, and within 10s of it: the harness's own failed
	// logins (its probes) come 20s or more before the control, and are not it.
	var ctl string
	near := 10 * time.Second
	mid := l53TimeOfDay(control.from.Add(control.to.Sub(control.from) / 2))
	for _, ln := range fresh {
		t, ok := l53ClockOf(ln)
		if !ok || !controlRe.MatchString(ln) {
			continue
		}
		if d := max(l53Wrap(t-mid), -l53Wrap(t-mid)); d < near {
			ctl, near = ln, d
		}
	}
	win := func(w l53Window) string {
		return w.from.UTC().Format("15:04:05") + "-" + w.to.UTC().Format("15:04:05")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "`%s`: %d lines it has now that it did not before the scan. Host windows (UTC): scan %s, "+
		"control login %s.\n\n", cmd, len(fresh), win(scan), win(control))
	var offset time.Duration
	if ctl == "" {
		fmt.Fprintf(&b, "**The control, a refused login as `%s`, is not in this log** (no line matching `%s` within 10s "+
			"of its window): it records no failed login, so its silence about the scan means nothing, and **the log "+
			"clause is UNMEASURED here**.\n\n", l53ControlUser, controlRe)
	} else {
		t, _ := l53ClockOf(ctl)
		if !l53In(t, 0, control) {
			// The line is somewhere in the login's span: the middle is the
			// best guess, and the slack covers the rest.
			offset = l53Wrap(t - l53TimeOfDay(control.from.Add(control.to.Sub(control.from)/2)))
		}
		clock := "the device's clock agrees with the host's to within 2s"
		if offset != 0 {
			clock = fmt.Sprintf("the device's clock differs from the host's by about %s, which is removed below",
				offset.Round(time.Second))
		}
		fmt.Fprintf(&b, "The control, a refused login as `%s` (host %s), is in the log as the line matching `%s` "+
			"nearest its window, stamped %s (%s), so this log records a failed login:\n\n    %s\n\n", l53ControlUser,
			win(control), controlRe, l53Clock.FindString(ctl), clock, ctl)
	}
	steps := map[string]int{}
	var tagged, inScan []string
	named := false
	for _, ln := range fresh {
		step := l53Step(ln, offset, scan, control)
		steps[step]++
		tagged = append(tagged, "["+step+"] "+ln)
		if step == "scan" {
			inScan = append(inScan, ln)
		}
		named = named || (breakglass != "" && strings.Contains(ln, breakglass))
	}
	fmt.Fprintf(&b, "By step: scan %d, control %d, before the scan %d, between the scan and the control %d, after the "+
		"control %d, no time %d.", steps["scan"], steps["control"], steps["before the scan"],
		steps["between the scan and the control"], steps["after the control"], steps["no time"])
	if named {
		b.WriteString(" The break-glass login that read the log is among the lines.")
	} else {
		b.WriteString(" No line names the break-glass login that read the log.")
	}
	if len(inScan) == 0 {
		b.WriteString("\n\nNo line is stamped inside the scan's window.")
	} else {
		fmt.Fprintf(&b, "\n\nEvery line stamped inside the scan's window (a line there is the scan's only if it is about "+
			"an SSH connection from the scanning address; the rest is the device's own):\n\n```\n%s\n```",
			trimForNote(strings.Join(inScan, "\n")))
	}
	fmt.Fprintf(&b, "\n\nThe last 30 lines, each with its step:\n\n```\n%s\n```", trimForNote(l53Tail(strings.Join(tagged, "\n"), 30)))
	return b.String(), ctl != ""
}

var (
	l53UnitRe   = regexp.MustCompile(`(?i)(\d+)\s*(week|day|hour|minute|second)`)
	l53BootedRe = regexp.MustCompile(`System booted: (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+)`)
)

// l53UpFor is the time the first line of out that names an uptime says the
// device has been up (EOS "Uptime: 1 minute", IOS-XE "xe1 uptime is 1 hour, 5
// minutes", NX-OS "Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 23
// second(s)").
func l53UpFor(out string) (time.Duration, bool) {
	units := map[string]time.Duration{"week": 7 * 24 * time.Hour, "day": 24 * time.Hour, "hour": time.Hour,
		"minute": time.Minute, "second": time.Second}
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToLower(ln), "uptime") {
			continue
		}
		var d time.Duration
		ms := l53UnitRe.FindAllStringSubmatch(ln, -1)
		for _, m := range ms {
			n, _ := strconv.Atoi(m[1])
			d += time.Duration(n) * units[strings.ToLower(m[2])]
		}
		if len(ms) > 0 {
			return d, true
		}
	}
	return 0, false
}

// l53Rebooted reports whether the device rebooted between two reads of its
// uptime command taken elapsed apart: for Junos, its "System booted" time
// changed; for the others, the uptime after is below the uptime before plus
// the time between the reads, by 2 minutes at least (the logs' resolution is
// a minute). A device that never went down, or that only stalled, shows an
// uptime that kept counting. The string says what was compared.
func l53Rebooted(before, after string, elapsed time.Duration) (bool, string) {
	if b := l53BootedRe.FindStringSubmatch(before); b != nil {
		a := l53BootedRe.FindStringSubmatch(after)
		if a == nil {
			return false, "the read after the reload has no System booted line"
		}
		return a[1] != b[1], fmt.Sprintf("System booted %s, then %s", b[1], a[1])
	}
	b, okB := l53UpFor(before)
	a, okA := l53UpFor(after)
	if !okB || !okA {
		return false, "no uptime line in one of the reads"
	}
	return a+2*time.Minute < b+elapsed, fmt.Sprintf("uptime %s, then %s after %s", b, a, elapsed.Round(time.Second))
}

var l53NXOSImage = regexp.MustCompile(`NXOS image file is:\s*(\S+)`)

// l53BootLine is a reload step's line with {nxos_image} replaced by the image
// show version says the switch booted, in the bootflash:/ form `boot nxos`
// takes.
func l53BootLine(line, showVersion string) (string, error) {
	if !strings.Contains(line, "{nxos_image}") {
		return line, nil
	}
	m := l53NXOSImage.FindStringSubmatch(showVersion)
	if m == nil {
		return "", errors.New(`show version has no "NXOS image file is:" line`)
	}
	return strings.ReplaceAll(line, "{nxos_image}", strings.Replace(m[1], "bootflash:///", "bootflash:/", 1)), nil
}

// l53String reads one SSH string (uint32 length, bytes) from b.
func l53String(b []byte) (s, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("short string")
	}
	n := int(binary.BigEndian.Uint32(b))
	if n < 0 || len(b) < 4+n {
		return nil, nil, errors.New("short string")
	}
	return b[4 : 4+n], b[4+n:], nil
}

// l53KexSignatureAlgorithm is the algorithm name in the signature of the
// first key exchange reply (ECDH or DH, message 31, or group exchange, 33) in
// stream, the bytes a server sent a client: the host-key algorithm the two
// negotiated. The packets before the keys change are not encrypted.
func l53KexSignatureAlgorithm(stream []byte) (string, error) {
	b := stream
	for {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return "", errors.New("no identification line")
		}
		line := b[:i+1]
		b = b[i+1:]
		if bytes.HasPrefix(line, []byte("SSH-")) {
			break
		}
	}
	for len(b) >= 5 {
		n := int(binary.BigEndian.Uint32(b))
		if n < 2 || n > 1<<16 || len(b) < 4+n {
			break
		}
		pad := int(b[4])
		if 1+pad > n {
			break
		}
		payload := b[5 : 4+n-pad]
		b = b[4+n:]
		if len(payload) == 0 || (payload[0] != 31 && payload[0] != 33) {
			continue
		}
		p := payload[1:]
		var err error
		for range 2 { // the host key, then the server's key share
			if _, p, err = l53String(p); err != nil {
				break
			}
		}
		if err != nil {
			continue // a group exchange's group message, not a reply
		}
		sig, _, err := l53String(p)
		if err != nil {
			continue
		}
		alg, _, err := l53String(sig)
		if err != nil {
			continue
		}
		return string(alg), nil
	}
	return "", errors.New("no key exchange reply in the stream")
}

// l53Tap keeps what a connection reads.
type l53Tap struct {
	net.Conn
	mu  sync.Mutex
	got bytes.Buffer
}

func (t *l53Tap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.mu.Lock()
	t.got.Write(p[:n])
	t.mu.Unlock()
	return n, err
}

func (t *l53Tap) bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.got.Bytes())
}

// l53HostKeyAlgorithm is the host-key algorithm the device at addr signs
// with when offered what labScan offers (the same lists; if labScan's
// change, change these), read off the wire. The key type is not it: an RSA
// key is signed with rsa-sha2-512, rsa-sha2-256 or ssh-rsa, and which the
// scan gets is what the row's first clause asks (task 8 review M9).
func l53HostKeyAlgorithm(addr string) (string, error) {
	sup, weak := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	hostKeys := slices.DeleteFunc(append(slices.Clone(sup.HostKeys), weak.HostKeys...), func(a string) bool {
		return strings.Contains(a, "-cert-v01@") || a == ssh.InsecureKeyAlgoDSA
	})
	nc, err := net.DialTimeout("tcp", addr, 20*time.Second)
	if err != nil {
		return "", err
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(20 * time.Second))
	tap := &l53Tap{Conn: nc}
	cfg := &ssh.ClientConfig{
		User:              "port49-scan",
		HostKeyCallback:   func(string, net.Addr, ssh.PublicKey) error { return errors.New("algorithm probe") },
		HostKeyAlgorithms: hostKeys,
		Config: ssh.Config{
			KeyExchanges: append(slices.Clone(sup.KeyExchanges), weak.KeyExchanges...),
			Ciphers:      append(slices.Clone(sup.Ciphers), weak.Ciphers...),
			MACs:         append(slices.Clone(sup.MACs), weak.MACs...),
		},
		Timeout: 20 * time.Second,
	}
	_, _, _, _ = ssh.NewClientConn(tap, addr, cfg)
	return l53KexSignatureAlgorithm(tap.bytes())
}

// l53NewLines is the lines of after that before does not have, in order.
func l53NewLines(before, after string) []string {
	seen := map[string]bool{}
	for _, ln := range strings.Split(before, "\n") {
		seen[strings.TrimSpace(ln)] = true
	}
	var out []string
	for _, ln := range strings.Split(after, "\n") {
		if s := strings.TrimSpace(ln); s != "" && !seen[s] {
			out = append(out, s)
		}
	}
	return out
}

// l53Limits is, for each platform the L53 row names a login-attempt limit
// for, the configuration lines that set a limit of two failures in 60s, and
// the lines that remove it. A prompt that differs fails the step: fix the
// lines here, never the claim.
var l53Limits = map[string][2][]string{
	"cisco_iosxe": {{"configure terminal", "login block-for 60 attempts 2 within 60", "end"},
		{"configure terminal", "no login block-for", "end"}},
	"cisco_nxos": {{"configure terminal", "aaa authentication rejected 2 in 60 ban 60", "end"},
		{"configure terminal", "no aaa authentication rejected 2 in 60 ban 60", "end"}},
}

var l53Space = regexp.MustCompile(`\s+`)

// l53Shown is the form out holds k in: "base64 key" (the OpenSSH blob, a
// terminal's line wrapping removed), "SHA256 fingerprint", "hex DER key"
// (the key's DER as hex, in any case and grouping, as IOS-XE prints an RSA
// key), "MD5 fingerprint" (with colons or without), or "".
func l53Shown(out string, k ssh.PublicKey) string {
	flat := l53Space.ReplaceAllString(out, "")
	upper := strings.ToUpper(flat)
	md5 := ssh.FingerprintLegacyMD5(k)
	switch {
	case strings.Contains(flat, base64.StdEncoding.EncodeToString(k.Marshal())):
		return "base64 key"
	case strings.Contains(out, ssh.FingerprintSHA256(k)):
		return "SHA256 fingerprint"
	}
	for _, der := range l53DER(k) {
		if strings.Contains(upper, der) {
			return "hex DER key"
		}
	}
	if strings.Contains(strings.ToLower(out), md5) ||
		strings.Contains(upper, strings.ToUpper(strings.ReplaceAll(md5, ":", ""))) {
		return "MD5 fingerprint"
	}
	return ""
}

// l53DER is k's DER as upper-case hex: the PKIX SubjectPublicKeyInfo, and for
// RSA the PKCS #1 key it wraps, which a device may print alone.
func l53DER(k ssh.PublicKey) []string {
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return nil
	}
	var out []string
	if der, err := x509.MarshalPKIXPublicKey(ck.CryptoPublicKey()); err == nil {
		out = append(out, strings.ToUpper(hex.EncodeToString(der)))
	}
	if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
		out = append(out, strings.ToUpper(hex.EncodeToString(x509.MarshalPKCS1PublicKey(rk))))
	}
	return out
}

// l53Tail is the last n lines of s.
func l53Tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// l53WaitDown waits until addr has twice in a row refused a connection or
// accepted one and sent no SSH banner, within bound: the device went down. A
// VM still answering SSH right after its reload command would otherwise be
// scanned before it reloaded, and its old key reported as surviving
// (pre-flight I-6). The banner is the test because the vrnetlab container
// forwards port 22 and accepts the connection whether or not the VM is up.
func l53WaitDown(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	failed := 0
	for time.Now().Before(deadline) {
		up := false
		if c, err := net.DialTimeout("tcp", addr, 3*time.Second); err == nil {
			c.SetReadDeadline(time.Now().Add(4 * time.Second))
			b := make([]byte, 4)
			n, _ := io.ReadFull(c, b)
			up = string(b[:n]) == "SSH-"
			c.Close()
		}
		if up {
			failed = 0
		} else if failed++; failed == 2 {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s still accepted connections %s after the reload command: the device never went down", addr, within)
}

// l53Admin opens the platform's break-glass CLI: the operator's own view of
// the device, at the privilege the console commands and the reload need.
func l53Admin(l *lab) (*cliConn, error) {
	if strings.HasPrefix(l.p.name, "juniper") {
		return l.junosCLI(breakglassUser, breakglassPassword)
	}
	return adminCLI(l)
}

// l53Show runs one command on the break-glass CLI c.
func l53Show(l *lab, c *cliConn, cmd string) (string, error) {
	if strings.HasPrefix(l.p.name, "juniper") {
		return junosShow(c, cmd)
	}
	return l.adminShow(c, cmd)
}

// l53Configure sends lines in one break-glass CLI session, each answered by a
// prompt; a line the device refuses fails the step.
func l53Configure(t *testing.T, admin func(func(*cliConn) error), lines []string) {
	t.Helper()
	admin(func(c *cliConn) error {
		for _, line := range lines {
			out, err := c.sendExpect(line, 30*time.Second, "#")
			if err != nil {
				return fmt.Errorf("%q: %v\n%s", line, err, trimForNote(out))
			}
			if strings.Contains(out, "% Invalid") || strings.Contains(out, "Invalid command") ||
				strings.Contains(out, "% Incomplete") {
				return fmt.Errorf("%q was refused by the device:\n%s", line, trimForNote(out))
			}
		}
		return nil
	})
}

// l53Limit measures whether scans count against the login-attempt limit
// lim[0] sets: three scans, then a login with a fresh token. Then the
// control, two refused logins and a login with a fresh token, which the
// limit must refuse for the measurement to mean anything. It waits out the
// limit's 60s, then removes it with lim[1].
func l53Limit(t *testing.T, l *lab, admin func(func(*cliConn) error), token func() string, addr string,
	lim [2][]string) (note string, inForce bool) {
	t.Helper()
	l53Configure(t, admin, lim[0])
	// The daemon's restart after the configuration session probes the device
	// with logins that fail until port49d answers, and with the limit set
	// those can trip it. Wait out its 60s so the scans meet a limit in force
	// and not yet tripped.
	time.Sleep(70 * time.Second)
	for i := range 3 {
		if _, err := labScan(context.Background(), addr); err != nil {
			t.Errorf("scan %d with the limit set: %v", i+1, err)
		}
	}
	_, afterScans := l.login(sliceUser, token(), "show version")
	for range 2 {
		if c, err := l.dial(sliceUser, "not-a-token", 30*time.Second); err == nil {
			c.Close()
		}
	}
	_, afterControl := l.login(sliceUser, token(), "show version")
	time.Sleep(75 * time.Second)
	l53Configure(t, admin, lim[1])
	outcome := func(err error) string {
		if err == nil {
			return "it succeeded"
		}
		return fmt.Sprintf("it was refused (%v)", err)
	}
	return fmt.Sprintf("With `%s` set (and 70s waited, so the harness's own failed probe logins after the daemon's "+
		"restart were out of its window): three scans, then a login with a fresh token: %s. The control, two refused "+
		"logins as `"+sliceUser+"`, the user the login uses, and then a login with a fresh token: %s.", lim[0][1],
		outcome(afterScans), outcome(afterControl)), afterControl != nil
}

// TestL53HostKeyScan measures L53 on each selected platform: the scan and
// what it leaves, the console's view of the key, the login-attempt limit
// where the row names one, and the key after a reload, in that order (the
// reload last, since it takes the device away for its boot budget). L54's
// half, port49 ssh against a pinned key, went with port49 devices trust in
// plan 9d.
func TestL53HostKeyScan(t *testing.T) {
	if os.Getenv("PORT49_LAB_SSH") != "1" {
		t.Skip("L53 reloads each device: run it with `make lab-ssh` (PORT49_LAB_SSH=1)")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		// The broker's PKI and a port49d with the broker block, as the slice
		// test starts them; the standing daemon is put back afterwards.
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
		sock, stopAgent := l29Agent(t)
		defer func() { stopAgent() }()
		token := func() string { return mustToken(t, sock, l.p.node) }
		// admin runs fn on the break-glass CLI. The device takes the local
		// password only while port49d is down, so the daemon is stopped for
		// the session and the broker daemon and a new agent put back after.
		admin := func(fn func(c *cliConn) error) {
			t.Helper()
			if err := l.stopDaemon(); err != nil {
				t.Fatalf("could not stop port49d before the admin CLI: %v", err)
			}
			var fnErr error
			c, err := l53Admin(l)
			if err != nil {
				fnErr = fmt.Errorf("no admin CLI: %w", err)
			} else {
				fnErr = fn(c)
				c.Close()
			}
			stopAgent()
			if err := l.startDaemonWith(cfg, true); err != nil {
				t.Fatalf("port49d would not start again: %v", err)
			}
			if err := l.awaitTACACS(); err != nil {
				t.Fatal(err)
			}
			sock, stopAgent = l29Agent(t)
			if fnErr != nil {
				t.Fatalf("break-glass session: %v", fnErr)
			}
		}
		addr := l.p.addr + ":22"
		var l53 []string
		say := func(note *[]string, format string, args ...any) { *note = append(*note, fmt.Sprintf(format, args...)) }

		// One capture for the run, so each note points at device traffic;
		// each step counts the TACACS+ packets in its own window of it.
		stopCap := l.capture(t, "L53L54")
		defer stopCap()
		tacacsIn := func(from, to time.Time) int {
			l.flushCapture(t)
			pkts, err := l29Packets(l.capAbs, l.p.addr)
			if err != nil {
				t.Fatalf("reading the capture: %v", err)
			}
			n := 0
			for _, p := range pkts {
				if !p.at.Before(from) && !p.at.After(to) {
					n++
				}
			}
			return n
		}

		// L53: the host-key algorithm the scan's offer negotiates. It is a
		// scan of its own, so it is made before the log is read for the
		// scan's: whatever it writes is in the log's "before".
		alg, algErr := l53HostKeyAlgorithm(addr)
		if algErr != nil {
			t.Errorf("reading the negotiated host-key algorithm: %v", algErr)
		}

		// L53: the device's log before the scan, to tell the scan's lines
		// from the rest.
		logBefore := map[string]string{}
		admin(func(c *cliConn) error {
			for _, cmd := range l53Log[l.p.name] {
				out, err := l53Show(l, c, cmd)
				if err != nil {
					return fmt.Errorf("%q: %v\n%s", cmd, err, trimForNote(out))
				}
				logBefore[cmd] = out
			}
			return nil
		})

		// L53: the scan, and what it leaves behind. A device that has just
		// booted or been reconfigured talks to port49d on its own, so the
		// scan waits for a window of 10s in which it does not, and that
		// window is the baseline the scan's own is read against.
		quiet := func() (recs, pkts int) {
			from, off := time.Now(), l.mark()
			time.Sleep(10 * time.Second)
			return len(l.recordsSince(off)), tacacsIn(from, time.Now())
		}
		baseRecs, basePkts := quiet()
		for i := 0; i < 18 && baseRecs+basePkts != 0; i++ {
			baseRecs, basePkts = quiet()
		}
		say(&l53, "The window of 10s before the scan, its baseline: %d decision records, and %d TACACS+ packets to or "+
			"from the device in the capture.", baseRecs, basePkts)
		off := l.mark()
		scanFrom := time.Now()
		key, err := labScan(context.Background(), addr)
		if err != nil {
			t.Fatalf("scan %s: %v", addr, err)
		}
		scan := l53Window{scanFrom, time.Now()}
		say(&l53, "The scan (%s-%s UTC) read a `%s` key, %s. The host-key algorithm the device signed with when offered "+
			"what the scan offers: `%s`.", scan.from.UTC().Format("15:04:05"), scan.to.UTC().Format("15:04:05"), key.Type(),
			labFingerprint(key), alg)
		time.Sleep(10 * time.Second)
		say(&l53, "Within 10s of the scan: %d decision records, and %d TACACS+ packets to or from the device in the "+
			"capture.", len(l.recordsSince(off)), tacacsIn(scanFrom, time.Now()))

		// L53: the control for the log. A refused SSH login as an account
		// that does not exist: if the log does not show it, it records no
		// login, and its silence about the scan is not a measurement.
		controlFrom := time.Now()
		if c, err := l.dial(l53ControlUser, "not-a-token", 30*time.Second); err == nil {
			c.Close()
			t.Errorf("a login as %s succeeded; it must be refused", l53ControlUser)
		}
		control := l53Window{controlFrom, time.Now()}
		// The admin session that reads the log logs in too: its lines must
		// fall outside the control's window and its slack.
		time.Sleep(5 * time.Second)

		// L53: the console, as an operator with privilege sees it (the
		// break-glass CLI): every candidate command, the uptime, and the
		// device's log after the scan.
		cmds := append(append([]string{}, l53Console[l.p.name]...), l53Uptime[l.p.name])
		cmds = append(cmds, l53Log[l.p.name]...)
		var outs []string
		var uptimeBeforeAt time.Time
		admin(func(c *cliConn) error {
			for _, cmd := range cmds {
				out, err := l53Show(l, c, cmd)
				if err != nil {
					return fmt.Errorf("%q: %v\n%s", cmd, err, trimForNote(out))
				}
				outs = append(outs, out)
				if cmd == l53Uptime[l.p.name] {
					uptimeBeforeAt = time.Now()
				}
			}
			return nil
		})
		for i, cmd := range l53Console[l.p.name] {
			form := l53Shown(outs[i], key)
			if form == "" {
				form = "not this key"
			}
			say(&l53, "`%s`: %s.\n\n```\n%s\n```", cmd, form, trimForNote(outs[i]))
		}
		nc := len(l53Console[l.p.name])
		say(&l53, "Before the reload, `%s` says: %q.", l53Uptime[l.p.name], l53UptimeLine.FindAllString(outs[nc], -1))
		logMeasured := false
		for i, cmd := range l53Log[l.p.name] {
			note, sawControl := l53LogNote(cmd, l53NewLines(logBefore[cmd], outs[nc+1+i]), scan, control, breakglassUser,
				l53ControlLine[l.p.name])
			say(&l53, "%s", note)
			logMeasured = logMeasured || sawControl
		}
		if logMeasured {
			say(&l53, "The log clause is measured here: the control login is in the log, so what the log holds for the "+
				"scan's window is what the scan wrote.")
		} else {
			say(&l53, "**The log clause is UNMEASURED on %s**: no log read showed the control login, so none of them "+
				"can show that the scan left no line. L53 stays open on this clause.", l.p.name)
			t.Logf("L53 %s: the log clause is unmeasured (the control is not in the log)", l.p.name)
		}

		// L53: the device's login-attempt limit, where the row names one.
		if lim, ok := l53Limits[l.p.name]; ok {
			note, inForce := l53Limit(t, l, admin, token, addr, lim)
			say(&l53, "%s", note)
			if !inForce {
				t.Errorf("%s: the control did not trip the limit, so whether a scan counts against it is unmeasured "+
					"here", l.p.name)
			}
		}

		// L53: the key after a reload, with the configuration saved. The
		// device must be seen to go down before it is waited for.
		// The wait for the device to go down starts with the reload line, not
		// after the admin session: putting the daemon back waits for the device
		// to ask it something, and a device that reloads in under a minute
		// would be down and back before a later wait began.
		var reloadAt, downAt time.Time
		downErr := make(chan error, 1)
		steps := slices.Clone(l53Reload[l.p.name])
		for i := range steps {
			if steps[i][0], err = l53BootLine(steps[i][0], outs[nc]); err != nil {
				t.Fatalf("the reload steps: %v", err)
			}
		}
		admin(func(c *cliConn) error {
			for i, step := range steps {
				// The reload line itself is not waited on for a prompt: the
				// console of a reloading VM may stay open for minutes, long
				// enough for the device to be down and back before the wait
				// for it to go down starts. Its confirmation is answered.
				last := i == len(steps)-1
				if last {
					reloadAt = time.Now()
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
					t.Logf("reload step %q: sent, no prompt waited for", step[0])
					if err := c.send(step[0]); err != nil {
						return err
					}
					time.Sleep(3 * time.Second)
					continue
				}
				out, err := c.sendExpect(step[0], 90*time.Second, want...)
				t.Logf("reload step %q: err %v; the device said:\n%s", step[0], err, trimForNote(out))
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
						t.Logf("after the answer %q, the device said:\n%s", step[2], trimForNote(c.transcript()[answered:]))
					}
				}
			}
			return nil
		})
		if err := <-downErr; err != nil {
			admin(func(c *cliConn) error {
				up, _ := l53Show(l, c, l53Uptime[l.p.name])
				t.Logf("the device, asked after the failed wait, `%s`: %s", l53Uptime[l.p.name], trimForNote(up))
				return nil
			})
			t.Fatalf("after the reload command: %v", err)
		}
		if err := l.waitDeviceReady(l.p.boot); err != nil {
			t.Fatalf("after the reload: %v", err)
		}
		say(&l53, "The reload command was sent at %s; the device was seen down (no SSH banner on two connections in a "+
			"row) at %s, and was serving SSH authentication again no later than %s after that: an upper bound, since "+
			"it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after "+
			"the readiness wait.", reloadAt.UTC().Format("15:04:05"), downAt.UTC().Format("15:04:05"),
			time.Since(downAt).Round(time.Second))
		var uptimeAfter string
		var uptimeAfterAt time.Time
		admin(func(c *cliConn) error {
			up, err := l53Show(l, c, l53Uptime[l.p.name])
			if err != nil {
				return err
			}
			uptimeAfter, uptimeAfterAt = up, time.Now()
			say(&l53, "After the reload, `%s` says: %q.", l53Uptime[l.p.name], l53UptimeLine.FindAllString(up, -1))
			return nil
		})
		rebooted, rebootedWhy := l53Rebooted(outs[nc], uptimeAfter, uptimeAfterAt.Sub(uptimeBeforeAt))
		say(&l53, "The device rebooted: %v (%s).", rebooted, rebootedWhy)
		if !rebooted {
			t.Errorf("the uptime does not show a reboot: %s", rebootedWhy)
		}
		after, err := labScan(context.Background(), addr)
		switch {
		case err != nil:
			say(&l53, "**The scan after the reload failed**: %v", err)
		case labFingerprint(after) == labFingerprint(key):
			say(&l53, "After a reload with the configuration saved, the device seen down and back, the key is the "+
				"same (%s).", labFingerprint(after))
		default:
			say(&l53, "**After a reload the key changed**: %s, then %s.", labFingerprint(key), labFingerprint(after))
		}

		l.result(t, "L53", "The SSH host key the device presents to a scan, the console's view of "+
			"it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).", strings.Join(l53, "\n\n"))
	})
}

// mustToken mints one token for device through the agent at sock.
func mustToken(t *testing.T, sock, device string) string {
	t.Helper()
	said, tok := l29Mint(sock, device)
	if tok == "" {
		t.Fatalf("no token for %s: %s", device, said)
	}
	return tok
}
