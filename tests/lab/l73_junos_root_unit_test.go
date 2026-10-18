//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
)

// rootDevice is a fake vJunos break-glass CLI with a lab-only root shell. It
// echoes everything typed, including the root password (the worst a real
// terminal could do), and logs each line the shell ran.
type rootDevice struct {
	out         *syncBuf
	mode        string // op, cfg, pw, shell
	hash        string // the encrypted-password the device was given
	pw          string // the password the device expects
	refuseHash  bool
	noOpenSSL   bool
	rootHasAuth bool
	shellRan    []string
	tailPW      string
	shown       string
}

func (d *rootDevice) say(s string) { d.out.Write([]byte(s)) }

func (d *rootDevice) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == 0x15 {
		return len(p), nil
	}
	s := string(p)
	if strings.HasSuffix(s, "?") && !strings.HasSuffix(s, "\n") {
		d.say(s + "\nPossible completions:\n  <[Enter]>  Execute this command\n  root  Start a shell as root\nbreakglass@vj> ")
		return len(p), nil
	}
	for _, ln := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		d.line(ln)
	}
	return len(p), nil
}

func (d *rootDevice) line(ln string) {
	switch d.mode {
	case "pw":
		d.say("\r\n") // a tty does not echo a password
		if ln == d.pw {
			d.mode = "shell"
			d.say("root@vj:~ # ")
		} else {
			d.mode = "op"
			d.say("su: Sorry\nbreakglass@vj> ")
		}
		return
	case "shell":
		d.say(ln + "\n")
		d.shellRan = append(d.shellRan, ln)
		switch {
		case ln == "exit":
			d.mode = "op"
			d.say("breakglass@vj> ")
			return
		case ln == "which openssl" && d.noOpenSSL:
			d.say("openssl: Command not found.\n")
		case ln == "which openssl":
			d.say("/usr/bin/openssl\n")
		case strings.HasPrefix(ln, "openssl x509 -noout -subject_hash_old"):
			d.say(map[bool]string{true: "bbbbbbbb", false: "dddddddd"}[strings.HasSuffix(ln, "root.pem")] + "\n")
		case strings.HasPrefix(ln, "openssl x509 -noout -subject_hash"):
			d.say(map[bool]string{true: "aaaaaaaa", false: "cccccccc"}[strings.HasSuffix(ln, "root.pem")] + "\n")
		case strings.HasPrefix(ln, "ls -l"):
			d.say("-rw-r--r-- 1 root wheel 700 Oct 18 aaaaaaaa.0 client.crt\n-- listing as root " + d.pw + "\n")
		}
		d.say("root@vj:~ # ")
		return
	}
	d.say(ln + "\n")
	switch {
	case ln == "show configuration system root-authentication | display set":
		if d.rootHasAuth {
			d.say("set system root-authentication encrypted-password \"$6$abc$def\"\n")
		}
		d.say("breakglass@vj> ")
	case strings.HasPrefix(ln, "file show "):
		d.shown = strings.TrimPrefix(ln, "file show ")
		d.say("-----BEGIN CERTIFICATE REQUEST-----\nMIIBfake\n-----END CERTIFICATE REQUEST-----\nbreakglass@vj> ")
	case ln == "configure":
		d.mode = "cfg"
		d.say("[edit]\nbreakglass@vj# ")
	case d.mode == "cfg" && strings.HasPrefix(ln, "set system root-authentication encrypted-password "):
		if d.refuseHash {
			d.say("error: syntax error\n[edit]\nbreakglass@vj# ")
			return
		}
		d.hash = ln
		d.say("\n[edit]\nbreakglass@vj# ")
	case d.mode == "cfg" && ln == "commit":
		d.say("commit complete\n\n[edit]\nbreakglass@vj# ")
	case d.mode == "cfg" && ln == "exit":
		d.mode = "op"
		d.say("breakglass@vj> ")
	case ln == "start shell user root":
		d.mode = "pw"
		d.say("Password:")
	default:
		d.say("breakglass@vj> ")
	}
}

func newRootDevice() (*cliConn, *rootDevice) {
	out := &syncBuf{}
	d := &rootDevice{out: out, mode: "op"}
	return &cliConn{name: "fake", prompt: "breakglass@vj>", in: d, out: out}, d
}

var rootCAs = []l73HostCA{{l73RootOnDevice, "aaaaaaaa", "bbbbbbbb"}, {l73InterOnDevice, "cccccccc", "dddddddd"}}

const testPW = "Zk3x9QmPassWordForTestOnly000011"

// leakFree is the rule: the password and the hash body never appear in any
// string the step hands back, nor in the error.
func leakFree(t *testing.T, what string, strs ...string) {
	t.Helper()
	for _, s := range strs {
		for _, bad := range []string{testPW, "HASHBODY"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s holds a secret (%q... %d bytes)", what, bad[:3], len(s))
			}
		}
	}
}

func TestL73JunosRootPlacesTheCAsAndLeaksNothing(t *testing.T) {
	c, d := newRootDevice()
	d.pw = testPW
	out, screen, err := l73JunosRoot(c, l73RootJob{SetHash: true, Group: l73TrustGroup, CAs: rootCAs}, testPW, "$6$salt$HASHBODY")
	if err != nil {
		t.Fatal(oneLine(err.Error()))
	}
	all := fmt.Sprintf("%+v|%s", out, screen)
	leakFree(t, "outcome", all)
	if strings.Contains(all, "$6$salt") {
		t.Error("the crypt hash is not masked")
	}
	if !out.DeviceOpenSSL || out.RootAuthWasSet {
		t.Errorf("outcome %+v", out)
	}
	for _, ran := range d.shellRan {
		if !l73RootCmdAllowed(ran) {
			t.Errorf("the shell ran %q", ran)
		}
	}
	joined := strings.Join(d.shellRan, "\n")
	for _, want := range []string{"cp /var/tmp/l73-root.pem " + l73TrustDir + "/" + l73TrustGroup + "/aaaaaaaa.0", "cp /var/tmp/l73-inter.pem " + l73TrustDir + "/" + l73TrustGroup + "/cccccccc.0", "exit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("shell never ran %q", want)
		}
	}
	if strings.Contains(joined, "bbbbbbbb.0") {
		t.Error("the old hash was placed although the device has openssl")
	}
	if !strings.Contains(d.hash, "$6$salt$HASHBODY") || strings.Contains(d.hash, testPW) {
		t.Error("the device was not given the hash, or was given the password")
	}
	if !strings.Contains(out.Listing, "aaaaaaaa.0") {
		t.Errorf("listing %q", out.Listing)
	}
}

func TestL73JunosRootWithoutDeviceOpenSSLPlacesBothNames(t *testing.T) {
	c, d := newRootDevice()
	d.pw, d.noOpenSSL = testPW, true
	out, screen, err := l73JunosRoot(c, l73RootJob{SetHash: true, Group: l73TrustGroup, CAs: rootCAs}, testPW, "$6$salt$HASHBODY")
	if err != nil {
		t.Fatal(oneLine(err.Error()))
	}
	leakFree(t, "outcome", fmt.Sprintf("%+v|%s", out, screen))
	j := strings.Join(d.shellRan, "\n")
	for _, h := range []string{"aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"} {
		if !strings.Contains(j, h+".0") {
			t.Errorf("%s.0 not placed", h)
		}
	}
	if out.DeviceOpenSSL {
		t.Error("claimed a device openssl")
	}
}

func TestL73JunosRootRefusesWhatItCannotTrust(t *testing.T) {
	for name, tweak := range map[string]func(*rootDevice){
		"hash refused":   func(d *rootDevice) { d.refuseHash = true },
		"wrong password": func(d *rootDevice) { d.pw = "something else" },
	} {
		c, d := newRootDevice()
		d.pw = testPW
		tweak(d)
		out, screen, err := l73JunosRoot(c, l73RootJob{SetHash: true, Group: l73TrustGroup, CAs: rootCAs}, testPW, "$6$salt$HASHBODY")
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		leakFree(t, name, err.Error(), screen, fmt.Sprintf("%+v", out))
		if len(d.shellRan) != 0 {
			t.Errorf("%s: the root shell ran %q", name, d.shellRan)
		}
	}
}

func TestL73JunosRootHashDisagreementIsInvalid(t *testing.T) {
	c, d := newRootDevice()
	d.pw = testPW
	cas := []l73HostCA{{l73RootOnDevice, "99999999", "bbbbbbbb"}} // the device says aaaaaaaa
	_, _, err := l73JunosRoot(c, l73RootJob{SetHash: true, Group: l73TrustGroup, CAs: cas}, testPW, "$6$salt$HASHBODY")
	if err == nil || !strings.Contains(err.Error(), "99999999") {
		t.Fatalf("err %v", err)
	}
	for _, ran := range d.shellRan {
		if strings.HasPrefix(ran, "cp ") {
			t.Errorf("copied despite a mismatch: %q", ran)
		}
	}
}

func TestL73JunosRootRecordsAPresentRootAuthentication(t *testing.T) {
	c, d := newRootDevice()
	d.pw, d.rootHasAuth = testPW, true
	out, screen, err := l73JunosRoot(c, l73RootJob{SetHash: true, Group: l73TrustGroup, CAs: rootCAs}, testPW, "$6$salt$HASHBODY")
	if err != nil {
		t.Fatal(oneLine(err.Error()))
	}
	if !out.RootAuthWasSet {
		t.Error("present root-authentication not recorded")
	}
	if strings.Contains(screen, "$6$abc") || strings.Contains(fmt.Sprintf("%+v", out), "$6$abc") {
		t.Error("the device's own hash was kept")
	}
}

func TestL73JunosRootMakesTheClientKeyInPlaceAndKeepsOnlyTheRequest(t *testing.T) {
	c, d := newRootDevice()
	d.pw = testPW
	out, screen, err := l73JunosRoot(c, l73RootJob{ClientNode: "srx1"}, testPW, "$6$salt$HASHBODY")
	if err != nil {
		t.Fatal(oneLine(err.Error()))
	}
	leakFree(t, "outcome", fmt.Sprintf("%+v|%s", out, screen))
	if d.hash != "" {
		t.Error("a later session set the root hash again")
	}
	if !out.ClientMade || !strings.Contains(out.ClientCSR, "CERTIFICATE REQUEST") {
		t.Errorf("outcome %+v", out)
	}
	j := strings.Join(d.shellRan, "\n")
	for _, want := range []string{"openssl genpkey -algorithm EC", "chmod 600 " + l73ClientDir + "/client.key", "openssl req -new -key"} {
		if !strings.Contains(j, want) {
			t.Errorf("shell never ran %q", want)
		}
	}
	for _, ran := range d.shellRan {
		if !l73RootCmdAllowed(ran) {
			t.Errorf("the shell ran %q", ran)
		}
		if strings.Contains(ran, "cat ") || (strings.Contains(ran, "client.key") && strings.HasPrefix(ran, "cp ")) {
			t.Errorf("the shell read or copied the key: %q", ran)
		}
	}
	// the key file's bytes are never asked for: the CSR comes from `file show` of the request alone
	if d.shown != l73ClientCSR {
		t.Errorf("file show %q", d.shown)
	}
}

func TestL73JunosRootClientNeedsTheDevicesOpenSSL(t *testing.T) {
	c, d := newRootDevice()
	d.pw, d.noOpenSSL = testPW, true
	_, _, err := l73JunosRoot(c, l73RootJob{ClientNode: "srx1"}, testPW, "$6$salt$HASHBODY")
	if err == nil || !strings.Contains(err.Error(), "openssl") {
		t.Fatalf("err %v", err)
	}
	for _, ran := range d.shellRan {
		if strings.Contains(ran, "genpkey") {
			t.Errorf("made a key anyway: %q", ran)
		}
	}
}

func TestL73JunosRootPlacesTheSignedClientCertificate(t *testing.T) {
	c, d := newRootDevice()
	d.pw = testPW
	out, _, err := l73JunosRoot(c, l73RootJob{PlaceClient: true}, testPW, "$6$salt$HASHBODY")
	if err != nil {
		t.Fatal(oneLine(err.Error()))
	}
	if d.hash != "" || out.ClientMade {
		t.Errorf("hash %q outcome %+v", d.hash, out)
	}
	j := strings.Join(d.shellRan, "\n")
	if !strings.Contains(j, "cp "+l73ClientCRT+" "+l73ClientDir+"/client.crt") || !strings.Contains(out.ClientListing, "client") {
		t.Errorf("ran %q listing %q", j, out.ClientListing)
	}
}
