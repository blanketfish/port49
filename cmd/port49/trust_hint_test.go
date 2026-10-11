package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/hostkeys"
)

// A follow-up command carries a flag only when the operator's value differs
// from its default, so it runs against the same pins file, socket, address and
// port the command that printed it did (final review M-1).
func TestTrustCommandCarriesOnlyWhatDiffersFromTheDefaults(t *testing.T) {
	defaults := trustHint{knownHosts: hostkeys.Path(), socket: agent.SocketPath(), port: 22}
	if got := trustCommand(defaults, "leaf1"); got != "port49 devices trust leaf1" {
		t.Errorf("defaults: %q", got)
	}
	if got := trustCommand(trustHint{knownHosts: hostkeys.Path(), socket: agent.SocketPath()}, "leaf1"); got != "port49 devices trust leaf1" {
		t.Errorf("an unset port: %q", got)
	}
	all := trustHint{knownHosts: "/k/pins", socket: "/s/a.sock", address: "10.0.0.1", port: 2222,
		fingerprint: "SHA256:abc", replace: true}
	want := "port49 devices trust --known-hosts /k/pins --socket /s/a.sock --address 10.0.0.1 --port 2222 " +
		"--fingerprint SHA256:abc --replace leaf1"
	if got := trustCommand(all, "leaf1"); got != want {
		t.Errorf("everything: %q, want %q", got, want)
	}
	if got := trustCommand(trustHint{knownHosts: "/my pins/k", socket: agent.SocketPath()}, "leaf1"); !strings.Contains(got, "--known-hosts '/my pins/k' ") {
		t.Errorf("a path with a space is quoted for the shell: %q", got)
	}
}

// ssh's no-pin hint names the pins file and socket the operator gave.
func TestTheNoPinHintCarriesTheOperatorsFlags(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil)
	code, _, errb := r.run(t, "leaf1")
	want := "port49 devices trust --known-hosts " + r.known + " --socket " + r.sock + " --port " + strconv.Itoa(dev.port) + " leaf1'"
	if code != 1 || !strings.Contains(errb, want) {
		t.Fatalf("code %d stderr %q, want it to contain %q", code, errb, want)
	}
}

// trust's replace hint keeps --address, --port and --socket as well.
func TestTheReplaceHintCarriesTheOperatorsFlags(t *testing.T) {
	old, key := testHostKey(t), testHostKey(t)
	known, scans, _ := trustRig(t, key, false, "")
	if err := hostkeys.Pin(known, "leaf1", old, false); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "a.sock")
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--known-hosts", known, "--socket", sock, "--address", "192.0.2.7",
		"--port", "2222", "leaf1"}, &out, &errb)
	want := "port49 devices trust --known-hosts " + known + " --socket " + sock + " --address 192.0.2.7 --port 2222 --replace leaf1"
	if code != 1 || scans.Load() != 0 || !strings.Contains(errb.String(), want) {
		t.Fatalf("code %d scans %d stderr %q, want it to contain %q", code, scans.Load(), errb.String(), want)
	}
}

// A scan that cannot dial says that trust connects directly and gives the
// forwarded-port route, with the operator's own device and flags (final review
// I-1). A handshake failure is not a dial failure and gets no such advice.
func TestADialFailureNamesTheForwardedPortRoute(t *testing.T) {
	known, _, _ := trustRig(t, testHostKey(t), false, "")
	trustScan = func(context.Context, string) (ssh.PublicKey, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")}
	}
	sock := filepath.Join(t.TempDir(), "a.sock")
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--known-hosts", known, "--socket", sock, "--address", "10.1.2.3",
		"leaf1"}, &out, &errb)
	for _, want := range []string{
		"connects directly, not through your ssh_config's ProxyJump or Port",
		"`ssh -N -L 2222:10.1.2.3:22 <jump>`",
		"`port49 devices trust --known-hosts " + known + " --socket " + sock +
			" --address 127.0.0.1 --port 2222 --fingerprint SHA256:… leaf1`",
	} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q: %q", want, errb.String())
		}
	}
	if code != 1 {
		t.Fatalf("code %d", code)
	}

	trustScan = func(context.Context, string) (ssh.PublicKey, error) {
		return nil, errors.New("10.1.2.3:22 presented no host key: handshake failed")
	}
	errb.Reset()
	if code := run([]string{"devices", "trust", "--known-hosts", known, "--address", "10.1.2.3", "leaf1"}, &out, &errb); code != 1 ||
		strings.Contains(errb.String(), "ProxyJump") {
		t.Fatalf("a handshake failure: code %d stderr %q", code, errb.String())
	}
}

// A pins directory port49 would refuse is refused before the mint and the
// scan, not after the operator has typed yes (final review M-2).
func TestTrustRefusesAPinsDirectoryBeforeItMints(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	known, scans, _ := trustRig(t, testHostKey(t), false, "")
	known = filepath.Join(dir, "port49", "known_hosts")
	var mints int
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { mints++ }))
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint", "SHA256:x",
		"leaf1"}, &out, &errb)
	if code != 1 || mints != 0 || scans.Load() != 0 || !strings.Contains(errb.String(), "writable by its owner alone") {
		t.Fatalf("code %d mints %d scans %d stderr %q", code, mints, scans.Load(), errb.String())
	}
}

// The replace path proposes: it lists every old pin, and says nothing of
// replacing until the fingerprint check has passed (final review M-8).
func TestReplaceProposesAfterTheFingerprintCheck(t *testing.T) {
	a, b, key := testHostKey(t), testHostKey(t), testHostKey(t)
	known, _, _ := trustRig(t, key, false, "")
	line := func(k ssh.PublicKey) string {
		return "leaf1 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n"
	}
	if err := os.WriteFile(known, []byte(line(a)+line(b)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "trust", "--known-hosts", known, "--address", "192.0.2.7", "--replace",
		"--fingerprint", "SHA256:wrong", "leaf1"}, &out, &errb); code != 1 ||
		strings.Contains(errb.String(), "would replace") {
		t.Fatalf("a wrong fingerprint: code %d stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"devices", "trust", "--known-hosts", known, "--address", "192.0.2.7", "--replace",
		"--fingerprint", hostkeys.Fingerprint(key), "leaf1"}, &out, &errb); code != 0 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	want := "leaf1's pins: " + hostkeys.Fingerprint(a) + ", " + hostkeys.Fingerprint(b) + "; the new key " +
		hostkeys.Fingerprint(key) + " would replace them"
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr lacks %q: %q", want, errb.String())
	}
}
