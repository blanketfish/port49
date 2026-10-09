//go:build lab

package lab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rhwendt/port49/internal/hostkeys"
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
// transcript in the note: fix the prompt here, never the claim.
var l53Reload = map[string][][3]string{
	"arista_eos":            {{"write memory", "", ""}, {"reload now", "", ""}},
	"cisco_nxos":            {{"copy running-config startup-config", "", ""}, {"reload", "(y/n)", "y"}},
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

// l53Log is, per platform, the command that shows the device's own log. It
// is read after the scan, and the note keeps its last 30 lines, so a line the
// scan wrote is there to see.
var l53Log = map[string]string{
	"arista_eos":            "show logging",
	"cisco_nxos":            "show logging logfile",
	"cisco_iosxe":           "show logging",
	"juniper_vjunos-router": "show log messages",
	"juniper_vsrx":          "show log messages",
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

// l53WaitDown waits until addr has refused or dropped two connection
// attempts in a row, within bound: the device went down. A VM still
// answering SSH right after its reload command would otherwise be scanned
// before it reloaded, and its old key reported as surviving (pre-flight I-6).
func l53WaitDown(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	failed := 0
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			if failed++; failed == 2 {
				return nil
			}
		} else {
			c.Close()
			failed = 0
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s still accepted connections %s after the reload command: the device never went down", addr, within)
}

// l53Configure sends lines in one CLI session, each answered by a prompt.
func l53Configure(t *testing.T, l *lab, sock string, lines []string) {
	t.Helper()
	c, err := l.sshCLI(sliceUser, mustToken(t, sock, l.p.node))
	if err != nil {
		t.Fatalf("configuration session: %v", err)
	}
	defer c.Close()
	for _, line := range lines {
		if out, err := c.sendExpect(line, 30*time.Second, "#"); err != nil {
			t.Fatalf("%q: %v\n%s", line, err, trimForNote(out))
		}
	}
}

// l53Limit measures whether scans count against the login-attempt limit
// lim[0] sets: three scans, then a login with a fresh token. Then the
// control, two refused logins and a login with a fresh token, which the
// limit must refuse for the measurement to mean anything. It waits out the
// limit's 60s, then removes it with lim[1].
func l53Limit(t *testing.T, l *lab, sock, addr string, lim [2][]string) (note string, inForce bool) {
	t.Helper()
	l53Configure(t, l, sock, lim[0])
	for i := range 3 {
		if _, err := hostkeys.Scan(context.Background(), addr); err != nil {
			t.Errorf("scan %d with the limit set: %v", i+1, err)
		}
	}
	_, afterScans := l.login(sliceUser, mustToken(t, sock, l.p.node), "show version")
	for range 2 {
		if c, err := l.dial("l53-control", "not-a-token", 30*time.Second); err == nil {
			c.Close()
		}
	}
	_, afterControl := l.login(sliceUser, mustToken(t, sock, l.p.node), "show version")
	time.Sleep(75 * time.Second)
	l53Configure(t, l, sock, lim[1])
	outcome := func(err error) string {
		if err == nil {
			return "it succeeded"
		}
		return fmt.Sprintf("it was refused (%v)", err)
	}
	return fmt.Sprintf("With `%s` set: three scans, then a login with a fresh token: %s. The control, two refused "+
		"logins as `l53-control` and then a login with a fresh token: %s.", lim[0][1], outcome(afterScans),
		outcome(afterControl)), afterControl != nil
}

// TestL53L54PortSSH measures L53 and L54 on each selected platform: the
// scan and what it leaves, the console's view of the key, the login-attempt
// limit where the row names one, port49 ssh with the key pinned through
// port49 devices trust, port49 ssh against a wrong pin, and the key after a
// reload, in that order (the reload last, since it takes the device away
// for its boot budget). Once both notes are written, it asserts each claim
// decision 42 relies on (pre-flight I-8), so "the lab test passed" means
// they held.
func TestL53L54PortSSH(t *testing.T) {
	if os.Getenv("PORT49_LAB_SSH") != "1" {
		t.Skip("L53 and L54 reload each device: run them with `make lab-ssh` (PORT49_LAB_SSH=1)")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		port49 := filepath.Join(root, "bin", "port49")
		sock, stopAgent := l29Agent(t)
		defer stopAgent()
		xdg := t.TempDir()
		// Only this user may write above the pins file, whatever the
		// lab host's umask (decision 42 ruling 6).
		if err := os.Chmod(xdg, 0o700); err != nil {
			t.Fatal(err)
		}
		env := append(os.Environ(), "XDG_CONFIG_HOME="+xdg)
		// An empty ssh_config: the lab host's own ~/.ssh/config does not
		// shape what is measured.
		sshConfig := filepath.Join(xdg, "ssh_config")
		if err := os.WriteFile(sshConfig, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		addr := l.p.addr + ":22"
		var l53, l54 []string
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

		// L53: the scan, and what it leaves behind.
		off := l.mark()
		scanFrom := time.Now()
		key, err := hostkeys.Scan(context.Background(), addr)
		if err != nil {
			t.Fatalf("scan %s: %v", addr, err)
		}
		say(&l53, "The scan read a `%s` key, %s.", key.Type(), hostkeys.Fingerprint(key))
		time.Sleep(10 * time.Second)
		say(&l53, "Within 10s of the scan: %d decision records, and %d TACACS+ packets to or from the device in the "+
			"capture.", len(l.recordsSince(off)), tacacsIn(scanFrom, time.Now()))

		// L53: the console. One minted token, one login: every candidate
		// command, the uptime, and the device's log after the scan.
		cmds := append(append([]string{}, l53Console[l.p.name]...), l53Uptime[l.p.name], l53Log[l.p.name])
		outs, err := l.login(sliceUser, mustToken(t, sock, l.p.node), cmds...)
		if err != nil || len(outs) != len(cmds) {
			t.Fatalf("console session: %v (%d of %d outputs)", err, len(outs), len(cmds))
		}
		consoleFP := ""
		for i, cmd := range l53Console[l.p.name] {
			form := l53Shown(outs[i], key)
			if form == "" {
				form = "not this key"
			} else if consoleFP == "" {
				consoleFP = hostkeys.Fingerprint(key)
			}
			say(&l53, "`%s`: %s.\n\n```\n%s\n```", cmd, form, trimForNote(outs[i]))
		}
		say(&l53, "Before the reload, `%s` says: %q.", l53Uptime[l.p.name], l53UptimeLine.FindAllString(outs[len(cmds)-2], -1))
		say(&l53, "The device's log after the scan, `%s`, its last 30 lines:\n\n```\n%s\n```", l53Log[l.p.name],
			trimForNote(l53Tail(outs[len(cmds)-1], 30)))

		// L53: the device's login-attempt limit, where the row names one.
		if lim, ok := l53Limits[l.p.name]; ok {
			note, inForce := l53Limit(t, l, sock, addr, lim)
			say(&l53, "%s", note)
			if !inForce {
				t.Errorf("%s: the control did not trip the limit, so whether a scan counts against it is unmeasured "+
					"here", l.p.name)
			}
		}

		// L54: port49 devices trust, then port49 ssh with a command.
		fp := consoleFP
		if fp == "" {
			fp = hostkeys.Fingerprint(key) // no console form matched: the scan's own, and the note says so
			say(&l53, "No console command showed this key; the trust step below used the scan's fingerprint.")
		}
		trust := exec.Command(port49, "devices", "trust", "--socket", sock, "--fingerprint", fp, l.p.node)
		trust.Env = env
		if out, err := trust.CombinedOutput(); err != nil {
			t.Fatalf("port49 devices trust: %v\n%s", err, out)
		}
		off = l.mark()
		run := exec.Command(port49, "ssh", "-v", "--socket", sock, "--ssh-config", sshConfig, l.p.node, "--",
			"show version")
		run.Env = env
		var stdout, stderr strings.Builder
		run.Stdout, run.Stderr = &stdout, &stderr
		err = run.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		methods := regexp.MustCompile(`Next authentication method: (\S+)`).FindAllStringSubmatch(stderr.String(), -1)
		var tried []string
		for _, m := range methods {
			tried = append(tried, m[1])
		}
		asked := strings.Count(stderr.String(), "read_passphrase: requested to askpass")
		version := strings.Contains(strings.ToLower(stdout.String()), "version")
		say(&l54, "`port49 ssh %s -- show version` exited %d; methods ssh tried: %v; askpass asked %d times; "+
			"`show version` output %s.", l.p.node, code, tried, asked,
			map[bool]string{true: "present", false: "absent"}[version])
		redeems := 0
		for _, r := range l.recordsSince(off) {
			if str(r, "event") == "redeem" {
				redeems++
			}
		}
		say(&l54, "Redeem records for the login: %d.", redeems)

		// L54: a wrong pin, never presented. The session above has ended
		// and its accounting landed before the window opens.
		wrong, _, _ := ed25519.GenerateKey(rand.Reader)
		wk, _ := ssh.NewPublicKey(wrong)
		if err := hostkeys.Pin(filepath.Join(xdg, "port49", "known_hosts"), l.p.node, wk, true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Second)
		off = l.mark()
		wrongFrom := time.Now()
		bad := exec.Command(port49, "ssh", "--socket", sock, "--ssh-config", sshConfig, l.p.node, "--", "show version")
		bad.Env = env
		badOut, _ := bad.CombinedOutput()
		time.Sleep(10 * time.Second)
		wrongTACACS := tacacsIn(wrongFrom, time.Now())
		var wrongOther []string
		for _, r := range l.recordsSince(off) {
			if e := str(r, "event"); e != "mint" && e != "blob" {
				wrongOther = append(wrongOther, e)
			}
		}
		say(&l54, "Against a wrong pin: %d TACACS+ packets to or from the device in the capture; records other than "+
			"mint and blob: %v. port49 ssh said:\n\n```\n%s\n```", wrongTACACS, wrongOther, trimForNote(string(badOut)))

		// L53: the key after a reload, with the configuration saved. The
		// device must be seen to go down before it is waited for.
		c, err := l.sshCLI(sliceUser, mustToken(t, sock, l.p.node))
		if err != nil {
			t.Fatalf("reload session: %v", err)
		}
		for _, step := range l53Reload[l.p.name] {
			want := []string{"#", ">", step[1]}
			if step[1] == "" {
				want = []string{"#", ">"}
			}
			out, _ := c.sendExpect(step[0], 3*time.Minute, want...)
			if step[1] != "" && strings.Contains(out, step[1]) {
				_ = c.send(step[2])
			}
		}
		c.Close()
		if err := l53WaitDown(addr, 10*time.Minute); err != nil {
			t.Fatalf("after the reload command: %v", err)
		}
		if err := l.waitDeviceReady(l.p.boot); err != nil {
			t.Fatalf("after the reload: %v", err)
		}
		if up, err := l.login(sliceUser, mustToken(t, sock, l.p.node), l53Uptime[l.p.name]); err == nil && len(up) == 1 {
			say(&l53, "After the reload, `%s` says: %q.", l53Uptime[l.p.name], l53UptimeLine.FindAllString(up[0], -1))
		}
		after, err := hostkeys.Scan(context.Background(), addr)
		switch {
		case err != nil:
			say(&l53, "**The scan after the reload failed**: %v", err)
		case hostkeys.Fingerprint(after) == hostkeys.Fingerprint(key):
			say(&l53, "After a reload with the configuration saved, the device seen down and back, the key is the "+
				"same (%s).", hostkeys.Fingerprint(after))
		default:
			say(&l53, "**After a reload the key changed**: %s, then %s.", hostkeys.Fingerprint(key), hostkeys.Fingerprint(after))
		}

		l.result(t, "L53", "The SSH host key the device presents to port49 devices trust's scan, the console's view of "+
			"it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).", strings.Join(l53, "\n\n"))
		l.result(t, "L54", "port49 ssh against the device: the method, the askpass, the command, and a wrong pin "+
			"(policy engine spec §15, L54).", strings.Join(l54, "\n\n"))

		// The claims decision 42 rests on, asserted once the notes are written.
		if code != 0 || !version {
			t.Errorf("port49 ssh -- show version: exit %d, show version %v; want 0 and present", code, version)
		}
		if asked != 1 {
			t.Errorf("the askpass was asked %d times; want once", asked)
		}
		if wrongTACACS != 0 || len(wrongOther) != 0 {
			t.Errorf("a wrong pin reached the device's authentication: %d TACACS+ packets, records %v", wrongTACACS,
				wrongOther)
		}
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
