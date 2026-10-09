//go:build lab

package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshString is one SSH string: a uint32 length, then the bytes.
func sshString(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

// sshPacket is an unencrypted binary packet holding payload, 4 bytes of padding.
func sshPacket(payload []byte) []byte {
	const pad = 4
	out := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
	out = append(out, pad)
	out = append(out, payload...)
	return append(out, make([]byte, pad)...)
}

// The negotiated host-key algorithm is the one named in the signature of the
// first key exchange reply, whatever the key's type is.
func TestL53KexSignatureAlgorithmReadsTheReply(t *testing.T) {
	kexinit := sshPacket(append([]byte{20}, make([]byte, 16)...))
	reply := func(typ byte, alg string) []byte {
		p := []byte{typ}
		p = append(p, sshString("ssh-rsa-key-blob")...)
		p = append(p, sshString("server-share")...)
		p = append(p, sshString(string(append(sshString(alg), sshString("sig")...)))...)
		return sshPacket(p)
	}
	banner := []byte("welcome\r\nSSH-2.0-OpenSSH_9.0\r\n")
	stream := func(parts ...[]byte) []byte { return append(append([]byte{}, banner...), bytes_join(parts)...) }
	for name, c := range map[string]struct {
		in   []byte
		want string
		fail bool
	}{
		"ecdh reply":         {stream(kexinit, reply(31, "rsa-sha2-512")), "rsa-sha2-512", false},
		"legacy name":        {stream(kexinit, reply(31, "ssh-rsa")), "ssh-rsa", false},
		"group exchange":     {stream(kexinit, sshPacket(append([]byte{31}, sshString("p")...)), reply(33, "rsa-sha2-256")), "rsa-sha2-256", false},
		"no reply yet":       {stream(kexinit), "", true},
		"cut off in a reply": {stream(kexinit, reply(31, "ssh-rsa")[:20]), "", true},
		"no banner":          {kexinit, "", true},
	} {
		got, err := l53KexSignatureAlgorithm(c.in)
		if (err != nil) != c.fail || got != c.want {
			t.Errorf("%s: got %q, %v; want %q (fail %v)", name, got, err, c.want, c.fail)
		}
	}
}

func bytes_join(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The reboot is asserted from the uptime in each platform's own words, and a
// device whose uptime kept counting is not a reboot.
func TestL53RebootedReadsEachPlatformsUptime(t *testing.T) {
	for _, c := range []struct {
		name, before, after string
		elapsed             time.Duration
		want                bool
	}{
		{"eos", "Uptime: 1 minute\r\n", "Uptime: 0 minutes\r\n", 4 * time.Minute, true},
		{"eos kept counting", "Uptime: 1 minute\r\n", "Uptime: 5 minutes\r\n", 4 * time.Minute, false},
		{"iosxe", "xe1 uptime is 1 minute\r\nUptime for this control processor is 2 minutes\r\n",
			"xe1 uptime is 0 minutes\r\nUptime for this control processor is 1 minute\r\n", 8 * time.Minute, true},
		{"iosxe kept counting", "xe1 uptime is 1 hour, 5 minutes\r\n", "xe1 uptime is 1 hour, 14 minutes\r\n", 8 * time.Minute, false},
		{"nxos", "Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 23 second(s)\r\n",
			"Kernel uptime is 0 day(s), 0 hour(s), 0 minute(s), 56 second(s)\r\n", 6 * time.Minute, true},
		{"nxos days", "Kernel uptime is 2 day(s), 1 hour(s), 3 minute(s), 23 second(s)\r\n",
			"Kernel uptime is 2 day(s), 1 hour(s), 9 minute(s), 23 second(s)\r\n", 6 * time.Minute, false},
		{"junos", "show system uptime \r\nSystem booted: 2026-10-09 17:56:28 UTC (00:01:33 ago)\r\n",
			"show system uptime \r\nSystem booted: 2026-10-09 17:58:56 UTC (00:01:00 ago)\r\n", 3 * time.Minute, true},
		{"junos same boot", "System booted: 2026-10-09 17:56:28 UTC (00:01:33 ago)\r\n",
			"System booted: 2026-10-09 17:56:28 UTC (00:04:33 ago)\r\n", 3 * time.Minute, false},
		{"unreadable", "nothing\r\n", "nothing\r\n", time.Minute, false},
	} {
		if got, why := l53Rebooted(c.before, c.after, c.elapsed); got != c.want {
			t.Errorf("%s: rebooted %v (%s), want %v", c.name, got, why, c.want)
		}
	}
}

// The NX-OS boot variable names the image show version says is running.
func TestL53BootLineNamesTheRunningImage(t *testing.T) {
	sv := "Software\n  NXOS image file is: bootflash:///nxos64-cs.10.4.2.F.bin\r\n  NXOS compile time: x\n"
	got, err := l53BootLine("boot nxos {nxos_image}", sv)
	if err != nil || got != "boot nxos bootflash:/nxos64-cs.10.4.2.F.bin" {
		t.Errorf("got %q, %v", got, err)
	}
	if got, err := l53BootLine("reload", ""); err != nil || got != "reload" {
		t.Errorf("a line without the placeholder is unchanged: %q, %v", got, err)
	}
	if _, err := l53BootLine("boot nxos {nxos_image}", "no image here"); err == nil {
		t.Error("a show version without the image line must be an error")
	}
}

// A log line is the scan's only by its own stamp inside the scan's window; the
// readiness probe before it is not, and a log without the control login says
// the clause is unmeasured. The sample is IOS-XE's, from the first run set.
func TestL53LogNoteAttributesByStampAndNeedsTheControl(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse("15:04:05", s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	scan := l53Window{at("18:13:47"), at("18:13:48")}
	control := l53Window{at("18:13:59"), at("18:14:01")}
	fresh := []string{
		"Console logging: level debugging, 132 messages logged, xml disabled,",
		"*Oct  9 18:13:31.496: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) Succeeded",
		"*Oct  9 18:13:37.004: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session Failed",
		"*Oct  9 18:13:47.370: %SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived.",
		"*Oct  9 18:14:00.100: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: l53-control] [Source: 172.100.100.1]",
	}
	for line, want := range map[string]string{
		fresh[0]: "no time", fresh[1]: "before the scan", fresh[2]: "before the scan", fresh[3]: "scan",
		fresh[4]: "control",
	} {
		if got := l53Step(line, 0, scan, control); got != want {
			t.Errorf("l53Step(%q) = %q, want %q", line, got, want)
		}
	}
	re := regexp.MustCompile("l53-control")
	note, seen := l53LogNote("show logging", fresh, scan, control, "breakglass", re)
	for _, want := range []string{"scan 1, control 1, before the scan 2", "is in the log", "[scan] *Oct  9 18:13:47.370",
		"[before the scan] *Oct  9 18:13:31.496", "No line names the break-glass login"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note lacks %q:\n%s", want, note)
		}
	}
	if !seen {
		t.Error("the control is in the log, so the clause is measured")
	}
	note, seen = l53LogNote("show log messages", fresh[:4], scan, control, "breakglass", re)
	if seen || !strings.Contains(note, "UNMEASURED") {
		t.Errorf("a log without the control must be unmeasured: seen %v\n%s", seen, note)
	}
	// IOS-XE names no user: the control is the failed-login line nearest its window. The harness's probe
	// failed 22s before is not within 10s, so without the control's own line the clause is unmeasured.
	iosxe := regexp.MustCompile(`SSH2_USERAUTH: User '' .*Failed`)
	if _, seen = l53LogNote("show logging", fresh[:4], scan, control, "breakglass", iosxe); seen {
		t.Error("a probe's failed login 22s before the control is not the control")
	}
	nameless := append(slices.Clone(fresh[:4]), "*Oct  9 18:14:00.100: %SSH-5-SSH2_USERAUTH: User '' authentication Failed")
	if _, seen = l53LogNote("show logging", nameless, scan, control, "breakglass", iosxe); !seen {
		t.Error("a failed login in the control's window is the control where the log names no user")
	}
	note, _ = l53LogNote("show logging", append(fresh, "*Oct  9 18:14:10.000: Login Success [user: breakglass]"), scan, control, "breakglass", re)
	if !strings.Contains(note, "The break-glass login that read the log is among the lines.") {
		t.Errorf("the break-glass line is among them:\n%s", note)
	}
	// A device clock 5s ahead is removed using the control's stamp.
	skewed := "Oct  9 18:14:06 srx1 sshd[1]: Failed password for invalid user l53-control from 172.100.100.1"
	if got := l53Step("Oct  9 18:13:52 srx1 sshd[1]: Connection closed [preauth]", 5*time.Second, scan, control); got != "scan" {
		t.Errorf("a stamp 5s ahead of the host is the scan's once the offset is removed, got %q", got)
	}
	if note, seen := l53LogNote("show log messages", []string{skewed}, scan, control, "", re); !seen ||
		!strings.Contains(note, "differs from the host's by about 6s") {
		t.Errorf("the offset comes from the control's stamp: seen %v\n%s", seen, note)
	}
}

func TestL53NewLinesAreTheOnesTheLogGained(t *testing.T) {
	before := "a\r\nb\n  c  \n"
	after := "a\nb\nc\nscan line\r\n\nd\n"
	got := l53NewLines(before, after)
	if len(got) != 2 || got[0] != "scan line" || got[1] != "d" {
		t.Errorf("l53NewLines = %q, want [scan line d]", got)
	}
}

// l53Shown recognises the key in a console command's output: its OpenSSH
// base64 blob, its SHA256 fingerprint, its DER as hex (IOS-XE's `show crypto
// key mypubkey rsa`), its MD5 fingerprint, or none of them.
func TestL53ShownReadsEachForm(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	blob := base64.StdEncoding.EncodeToString(k.Marshal())
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := ssh.NewPublicKey(&rk.PublicKey)
	spki, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	var grouped strings.Builder // IOS-XE's form: upper-case hex, 8 digits a group, 8 groups a line
	for i, c := range strings.ToUpper(hex.EncodeToString(spki)) {
		if i > 0 && i%8 == 0 {
			grouped.WriteString(map[bool]string{true: "\n  ", false: " "}[i%64 == 0])
		}
		grouped.WriteRune(c)
	}
	md5 := ssh.FingerprintLegacyMD5(r)
	for _, c := range []struct {
		out  string
		k    ssh.PublicKey
		want string
	}{
		{"ssh-ed25519 " + blob + " root@leaf1\n", k, "base64 key"},
		{"Fingerprint: " + ssh.FingerprintSHA256(k) + "\n", k, "SHA256 fingerprint"},
		{"ssh-ed25519 " + blob[:20] + "\n" + blob[20:] + "\n", k, "base64 key"},
		{"Key name: leaf1.lab\n Key Data:\n  " + grouped.String() + "\n", r, "hex DER key"},
		{"bitcount:2048 fingerprint:\n" + md5 + "\n", r, "MD5 fingerprint"},
		{"fingerprint " + strings.ToUpper(strings.ReplaceAll(md5, ":", "")) + "\n", r, "MD5 fingerprint"},
		{"RSA key fingerprint is 9b:2a:..., other key\n", k, ""},
		{strings.Repeat("x", 100), k, ""},
		{"Key Data:\n  " + grouped.String() + "\n", k, ""},
	} {
		if got := l53Shown(c.out, c.k); got != c.want {
			t.Errorf("l53Shown(%q) = %q, want %q", c.out, got, c.want)
		}
	}
}
