package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A first contact is OpenSSH's accept-new: the login goes on, once, and the
// key is filed under the device's inventory name (decision 46 ruling 2).
func TestFirstContactIsAcceptedAndFiledUnderTheName(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" || len(r.filed(t, "leaf1")) != 1 ||
		!strings.Contains(errb, "Permanently added 'leaf1'") {
		t.Fatalf("code %d stdout %q stderr %q attempts %q filed %q", code, out, errb, dev.attempts(), r.filed(t, "leaf1"))
	}
	tokenNowhere(t, out, errb)
}

// Review Focus 1: an RSA key known under the name, and a host offering only
// Ed25519, is a changed key to OpenSSH, never a new one.
func TestAKeyOfAnotherTypeUnderAKnownNameIsRefused(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive", "password"}, "LOGINTOKEN", 0) // Ed25519
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rpub, _ := ssh.NewPublicKey(&rk.PublicKey)
	r := newSSHRig(t, dev, sshPermit, 0, rpub)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || len(dev.attempts()) != 0 || !strings.Contains(errb, "so it was never sent") ||
		!strings.Contains(errb, "ssh-keygen -f "+r.known+" -R leaf1") {
		t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
	}
	if got := r.filed(t, "leaf1"); len(got) != 1 || !strings.Contains(got[0], "ssh-rsa") {
		t.Fatalf("the known key was replaced or joined: %q", got)
	}
	tokenNowhere(t, out, errb)
}

// Review Focus 2: once a device's key is filed under its name, a mint giving
// that name another host's address ends at the key exchange.
func TestAnAddressMovedToAnotherHostNeverSeesTheToken(t *testing.T) {
	real := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, real, sshPermit, 0, nil)
	if code, _, errb := r.run(t, "leaf1", "--", "show", "version"); code != 0 {
		t.Fatalf("first login: %d %q", code, errb)
	}
	impostor := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0) // another key
	r.flags[len(r.flags)-1] = strconv.Itoa(impostor.port)
	code, out, errb := r.run(t, "leaf1")
	if code != 255 || len(impostor.attempts()) != 0 || !strings.Contains(errb, "is not the device") {
		t.Fatalf("code %d stderr %q impostor attempts %q", code, errb, impostor.attempts())
	}
	tokenNowhere(t, out, errb)
}

// Review Focus 3: the operator's yes stands; everything else is accept-new;
// no is never passed. Their HostKeyAlias stands, and is the name keys are
// filed under; a Host block matches the destination as written, case and all
// (pre-flight M1). Review Focus 7: a known_hosts of /dev/null or none under
// accept-new is refused; under their yes it stands.
func TestSSHPolicyReadsTheOperatorsConfig(t *testing.T) {
	bin := sshTestBin(t)
	// A known_hosts that can keep a key, for the rows that do not name one.
	good := filepath.Join(privateDir(t), "known_hosts")
	for _, tc := range []struct{ cfg, device, strict, alias, keyName, err string }{
		{"", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking yes", "leaf1", "yes", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking no", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking ask", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking accept-new", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"Host leaf1\n  HostKeyAlias Corp-Leaf1", "leaf1", "accept-new", "", "corp-leaf1", ""},
		{"Host leaf1\n  HostKeyAlias Corp-Leaf1", "Leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"Match user alice\n  HostKeyAlias alice-leaf1", "leaf1", "accept-new", "", "alice-leaf1", ""},
		{"UserKnownHostsFile /dev/null", "leaf1", "", "", "", "UserKnownHostsFile"},
		{"UserKnownHostsFile none", "leaf1", "", "", "", "UserKnownHostsFile"},
		{"UserKnownHostsFile /dev/null\nStrictHostKeyChecking yes", "leaf1", "yes", "leaf1", "leaf1", ""},
	} {
		cfg := filepath.Join(privateDir(t), "ssh_config")
		text := tc.cfg + "\n"
		if !strings.Contains(tc.cfg, "UserKnownHostsFile") {
			text = "UserKnownHostsFile " + good + "\n" + text
		}
		if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := sshPolicy(context.Background(), bin, sshOptions{config: cfg, device: tc.device,
			address: "192.0.2.7", username: "alice"})
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: got %+v, %v; want a refusal naming %s", tc.cfg, got, err, tc.err)
			}
			continue
		}
		if err != nil || got.strict != tc.strict || got.alias != tc.alias || got.keyName != tc.keyName {
			t.Errorf("%q %s: got %+v, %v; want strict %s alias %q keyName %s", tc.cfg, tc.device, got, err,
				tc.strict, tc.alias, tc.keyName)
		}
	}
}

// Review Focus 7: an ssh_config that keeps no host keys would make every
// connection a first contact. It is refused before ssh starts, naming the
// setting; the device sees no connection.
func TestAKnownHostsFileOfDevNullIsRefused(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil)
	if err := os.WriteFile(r.config, []byte("UserKnownHostsFile /dev/null\nGlobalKnownHostsFile /dev/null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := r.run(t, "leaf1")
	if code != 1 || dev.connections() != 0 || !strings.Contains(errb, "UserKnownHostsFile /dev/null") ||
		!strings.Contains(errb, "nothing was sent to leaf1") {
		t.Fatalf("code %d conns %d stderr %q", code, dev.connections(), errb)
	}
	tokenNowhere(t, out, errb)
}

// The operator's StrictHostKeyChecking yes refuses a first contact: nothing
// sent, nothing filed, and the message says a key may be missing, not only
// changed (pre-flight M4).
func TestTheOperatorsStrictYesStands(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil, "StrictHostKeyChecking yes")
	code, _, errb := r.run(t, "leaf1")
	if code != 255 || len(dev.attempts()) != 0 || len(r.filed(t, "leaf1")) != 0 ||
		!strings.Contains(errb, "ssh_config says StrictHostKeyChecking yes") ||
		!strings.Contains(errb, "then add the key you verified") || strings.Contains(errb, "connect again") {
		t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
	}
}

// The operator's own HostKeyAlias is the name ssh looks the key up under, and
// the name ssh's prompt carries: the askpass answers it, once (pre-flight I1).
func TestTheOperatorsHostKeyAliasStands(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil, "Host leaf1\n  HostKeyAlias corp-leaf1")
	if err := os.WriteFile(r.known, []byte("corp-leaf1 "+string(ssh.MarshalAuthorizedKey(dev.key))), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" || len(r.filed(t, "leaf1")) != 0 ||
		strings.Contains(errb, "Permanently added") {
		t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
	}
	tokenNowhere(t, out, errb)
}

// The askpass takes the device's prompt under the inventory name or the
// alias, and no other (pre-flight I1).
func TestTheAskpassAnswersThePromptNamingTheAlias(t *testing.T) {
	for prompt, ours := range map[string]bool{
		"(alice@leaf1) Password: ": true, "(alice@corp-leaf1) Password: ": true,
		"alice@corp-leaf1's password: ": true, "(alice@jump1) Password: ": false,
	} {
		s := &askpassServer{token: "LOGINTOKEN", username: "alice", device: "leaf1", keyName: "corp-leaf1"}
		a, b := net.Pipe()
		go s.answer(a)
		_, _ = io.WriteString(b, strconv.Quote(prompt)+"\n")
		reply, _ := bufio.NewReader(b).ReadString('\n')
		b.Close()
		if got := strings.HasPrefix(reply, "T "); got != ours {
			t.Errorf("%q: answered %q", prompt, reply)
		}
	}
}

// The device's prompt is answered only to the ssh port49 started: a ProxyJump
// hop's askpass has the hop's ssh for a parent, and its prompt can carry the same
// alias (pre-flight N3). The test process is the asker, over a real Unix
// socket; its parent is the "ssh" and its own pid is a "hop".
func TestTheAskpassAnswersOnlyTheSSHItStarted(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the asker's parent is read on Linux and macOS only")
	}
	ask := func(t *testing.T, sshPid int) (reply string, killed bool) {
		t.Helper()
		// A short path: a Unix socket's is limited (macOS's is 104).
		dir, err := os.MkdirTemp("", "p49k")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		ln, err := net.Listen("unix", filepath.Join(dir, "a.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		var ended atomic.Bool
		s := &askpassServer{ln: ln, token: "LOGINTOKEN", username: "alice", device: "leaf1", keyName: "corp-leaf1",
			askerParent: askerParent}
		s.setSSHPid(sshPid)
		s.setKill(func() { ended.Store(true) })
		go s.serve()
		c, err := net.Dial("unix", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = io.WriteString(c, strconv.Quote("(alice@corp-leaf1) Password: ")+"\n")
		reply, _ = bufio.NewReader(c).ReadString('\n')
		return reply, ended.Load()
	}
	if reply, _ := ask(t, os.Getppid()); reply != "T LOGINTOKEN\n" {
		t.Errorf("the asker's parent is the ssh: answered %q", reply)
	}
	if reply, killed := ask(t, os.Getpid()); reply != "N\n" || killed {
		t.Errorf("a hop (the asker's parent is another process): answered %q, killed %v", reply, killed)
	}
}

// A hop's prompt through a fake ssh: the askpass is run by a shell the "ssh"
// script started (the trailing echo keeps sh from exec'ing it), not by the
// script, so its parent is not the ssh pid port49 holds, and the token does
// not leave (pre-flight N3). TestTheTokenIsNeverInArgvOrTheEnvironment, whose
// fake forks the askpass itself, is the control: there the token is answered.
// setsid leaves the askpass no controlling terminal, so the "N" it is answered
// never reaches for /dev/tty at a terminal.
func TestAProxyJumpHopsPromptNeverGetsTheToken(t *testing.T) {
	setsid, err := exec.LookPath("setsid")
	if err != nil {
		t.Skip("no setsid: the askpass would ask the terminal this test runs at")
	}
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	dir := t.TempDir()
	answer := filepath.Join(dir, "answer")
	script := fakeSSHHead(r.known) +
		"sh -c '" + setsid + " -w \"$SSH_ASKPASS\" \"$1\" < /dev/null > \"$2\" 2>&1; echo' _ \"(alice@leaf1) Password: \" '" + answer + "'\n" +
		"exit 255\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = filepath.Join(dir, "ssh")
	_, out, errb := r.run(t, "leaf1")
	b, err := os.ReadFile(answer)
	if err != nil {
		t.Fatalf("the hop's askpass never ran: %v; stderr %q", err, errb)
	}
	if strings.Contains(string(b), "LOGINTOKEN") {
		t.Fatalf("a hop's askpass was answered with the token: %q", b)
	}
	tokenNowhere(t, out, errb)
}

// When the asker's pid or its parent cannot be read (a net.Pipe has no peer
// credentials; neither does an OS this reads none on), nothing is sent and
// ssh is ended, as refuse ends it: never the token, never "not ours".
func TestAnAskerWhoseParentCannotBeReadGetsNothing(t *testing.T) {
	var killed bool
	s := &askpassServer{token: "LOGINTOKEN", username: "alice", device: "leaf1", keyName: "leaf1",
		askerParent: askerParent}
	s.setSSHPid(os.Getppid())
	s.setKill(func() { killed = true })
	a, b := net.Pipe()
	go s.answer(a)
	_, _ = io.WriteString(b, strconv.Quote("(alice@leaf1) Password: ")+"\n")
	reply, _ := bufio.NewReader(b).ReadString('\n')
	b.Close()
	if reply != "X\n" || !killed || s.unverified == "" {
		t.Errorf("answered %q, killed %v, unverified %q", reply, killed, s.unverified)
	}
}

// Decision 42 ruling 8, moved with sshName from hostkeys.ValidName
// (pre-flight M2).
func TestSSHName(t *testing.T) {
	for name, ok := range map[string]bool{
		"leaf1": true, "core-sw01.dc1": true, "srx_fw_04": true, strings.Repeat("a", 253): true,
		"": false, "*": false, "leaf*": false, "a,b": false, "!x": false, "@cert-authority": false,
		"|1|abc": false, "[leaf1]:22": false, "-leaf": false, ".leaf": false, "leaf 1": false,
		"leaf?": false, "leaf1\n": false, strings.Repeat("a", 254): false,
	} {
		if sshName(name) != ok {
			t.Errorf("sshName(%q) = %v", name, !ok)
		}
	}
}

// --known-hosts named port49's own pins file, which is gone.
func TestTheKnownHostsFlagIsRefused(t *testing.T) {
	var out, errb lockedBuffer
	if code := run([]string{"ssh", "--known-hosts", "/k", "leaf1"}, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "UserKnownHostsFile") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// Plan 9a's pins file is named, never read: a pins file anyone can write
// stops nothing, and its keys are not used.
func TestThe9aPinsFileIsNamedNotRead(t *testing.T) {
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "port49"), 0o777); err != nil {
		t.Fatal(err)
	}
	pins := filepath.Join(xdg, "port49", "known_hosts")
	if err := os.WriteFile(pins, []byte("leaf1 not-a-key\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	code, _, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Count(errb, pins) != 2 || !strings.Contains(errb, "no longer reads it") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}

// Plan 9b pre-flight 2, m5: Ubuntu's 0775 ~/.config refused port49 ssh with no
// fix to run. Nothing port49 ssh reads is under it now.
func TestAGroupWritableConfigStopsNothing(t *testing.T) {
	home := t.TempDir()
	// Under umask 002 the TempDir is 0775 too: HOME must be private, so that
	// ~/.config is the only group-writable component.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config", "port49"), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, ".config"), 0o775); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	if code, _, errb := r.run(t, "leaf1", "--", "show", "version"); code != 0 {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}
