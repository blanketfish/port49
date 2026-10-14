package main

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// Re-review I1: the real run is `ssh ... leaf1 show version`, and OpenSSH
// evaluates `Match sessiontype exec` and `Match command` against the command.
// `ssh -G` is run with the command too, so the file it reads is the file the
// run uses; a /dev/null that only the command's run sees is refused, and nothing
// reaches the device.
func TestAMatchBlockOnTheCommandIsEvaluated(t *testing.T) {
	for name, match := range map[string]string{
		"sessiontype exec": "Match sessiontype exec",
		"command":          `Match command "show*"`,
		// Round 2 R2: ssh -G has the environment the real run gets. printenv
		// needs no nested quotes, which OpenSSH before 10 does not parse.
		"exec on the askpass environment": `Match exec "printenv SSH_ASKPASS_REQUIRE"`,
	} {
		t.Run(name, func(t *testing.T) {
			dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
			r := newSSHRig(t, dev, sshPermit, 0, nil)
			cfg := match + "\n  UserKnownHostsFile /dev/null\nMatch all\n  UserKnownHostsFile " + r.known +
				"\nGlobalKnownHostsFile /dev/null\n"
			if err := os.WriteFile(r.config, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errb := r.run(t, "leaf1", "--", "show", "version")
			if strings.Contains(errb, "Bad configuration") || strings.Contains(errb, "Unsupported") {
				t.Skipf("this ssh does not read %s: %s", match, errb)
			}
			if code != 1 || dev.connections() != 0 || !strings.Contains(errb, "UserKnownHostsFile /dev/null") {
				t.Fatalf("code %d conns %d stderr %q", code, dev.connections(), errb)
			}
			tokenNowhere(t, out, errb)
		})
	}
}

// Re-review I2: ssh -G prints a path with a space unquoted, so the first of
// several cannot be told from a path that holds a space. A value that does not
// split unambiguously (any field not starting with '/') is refused.
func TestAKnownHostsPathWithASpaceIsRefused(t *testing.T) {
	dir := privateDir(t)
	cfg := filepath.Join(dir, "ssh_config")
	text := `UserKnownHostsFile "` + filepath.Join(dir, "x y", "kh") + `"` + "\n"
	if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := sshPolicy(context.Background(), sshTestBin(t), sshOptions{config: cfg, device: "leaf1",
		address: "192.0.2.7", username: "alice"})
	if err == nil || !strings.Contains(err.Error(), "UserKnownHostsFile") || !strings.Contains(err.Error(), "space") {
		t.Fatalf("got %v", err)
	}
}

// Re-review N1: ssh makes ~/.ssh only in the passwd home. A $HOME that is not
// the passwd home, with .ssh missing, does not get the exception.
func TestTheSSHDirectoryExceptionIsThePasswdHome(t *testing.T) {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skip("no passwd home")
	}
	fake := filepath.Join(t.TempDir(), "h")
	if err := os.Mkdir(fake, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fake)
	if why := knownHostsCannotKeep(filepath.Join(fake, ".ssh", "known_hosts")); why == "" {
		t.Fatal("a missing $HOME/.ssh was taken for ssh's own ~/.ssh")
	}
}

// Re-review N3: the ssh-keygen hint names the first file when it is not the
// default, since the command alone edits ~/.ssh/known_hosts. (The 255 tests
// assert the -f in the messages.) For the default it stays plain.
func TestKeygenHintNamesANonDefaultFile(t *testing.T) {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skip("no passwd home")
	}
	def := filepath.Join(u.HomeDir, ".ssh", "known_hosts")
	if got := keygenCommand(sshTrust{keyName: "leaf1", known: def}); got != "ssh-keygen -R leaf1" {
		t.Errorf("default: %q", got)
	}
	kh := filepath.Join(t.TempDir(), "kh")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := keygenCommand(sshTrust{keyName: "a b", known: kh}); got != "ssh-keygen -f "+shellWord(kh)+" -R 'a b'" {
		t.Errorf("other: %q", got)
	}
}

// Round 2 R3: a first file that holds no key (the managed-GlobalKnownHostsFile
// shape under the operator's yes, `/dev/null`; `none`; a split value) is never
// named with -f; the hint points at the file ssh names instead.
func TestKeygenHintNeverNamesAFileThatKeepsNothing(t *testing.T) {
	for _, known := range []string{"/dev/null", "none", "y/kh"} {
		got := keygenCommand(sshTrust{keyName: "leaf1", known: known, strict: "yes"})
		if got != "" {
			t.Errorf("%q: got %q, want no command", known, got)
		}
	}
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, testHostKey(t), "StrictHostKeyChecking yes")
	if err := os.WriteFile(r.config, []byte("UserKnownHostsFile /dev/null\nGlobalKnownHostsFile "+r.known+
		"\nStrictHostKeyChecking yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errb := r.run(t, "leaf1")
	if code != 255 || strings.Contains(errb, "-f /dev/null") || strings.Contains(errb, "-f none") ||
		!strings.Contains(errb, "from the file ssh names above") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}
