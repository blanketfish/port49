package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Task 3 review C1: under accept-new, ssh writes a first contact's key to the
// FIRST UserKnownHostsFile, and connects anyway when it cannot. A file that
// cannot keep the key makes every connection a first contact, so a second host
// at the address gets the token. Each config here is refused before ssh starts
// (nothing sent, the device sees no connection); the control keeps a key.
func TestAKnownHostsThatCannotKeepAKeyIsRefused(t *testing.T) {
	root := os.Getuid() == 0
	for name, c := range map[string]struct {
		cfg     func(t *testing.T, r *sshRig) string // the ssh_config's UserKnownHostsFile line
		refused bool
	}{
		"control: a normal file": {func(t *testing.T, r *sshRig) string { return r.known }, false},
		"control: a missing file in a directory the user can write": {func(t *testing.T, r *sshRig) string {
			return filepath.Join(filepath.Dir(r.known), "fresh_known_hosts")
		}, false},
		"a symlink to /dev/null": {func(t *testing.T, r *sshRig) string {
			link := filepath.Join(filepath.Dir(r.known), "kh_link")
			if err := os.Symlink("/dev/null", link); err != nil {
				t.Fatal(err)
			}
			return link
		}, true},
		"/dev/null first, a real file second": {func(t *testing.T, r *sshRig) string {
			return "/dev/null " + r.known
		}, true},
		"a directory that does not exist": {func(t *testing.T, r *sshRig) string {
			return filepath.Join(filepath.Dir(r.known), "nope", "kh")
		}, true},
		"/dev//null": {func(t *testing.T, r *sshRig) string { return "/dev//null" }, true},
		"a dangling symlink": {func(t *testing.T, r *sshRig) string {
			link := filepath.Join(filepath.Dir(r.known), "kh_dangling")
			if err := os.Symlink(filepath.Join(filepath.Dir(r.known), "nope", "kh"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}, true},
		"a file the user cannot write": {func(t *testing.T, r *sshRig) string {
			if root {
				t.Skip("root can write any file")
			}
			if err := os.Chmod(r.known, 0o400); err != nil {
				t.Fatal(err)
			}
			return r.known
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
			r := newSSHRig(t, dev, sshPermit, 0, nil)
			line := c.cfg(t, r)
			if err := os.WriteFile(r.config, []byte("UserKnownHostsFile "+line+"\nGlobalKnownHostsFile /dev/null\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errb := r.run(t, "leaf1", "--", "show", "version")
			if c.refused {
				if code != 1 || dev.connections() != 0 || !strings.Contains(errb, "UserKnownHostsFile "+line) ||
					!strings.Contains(errb, "nothing was sent to leaf1") {
					t.Fatalf("code %d conns %d stderr %q", code, dev.connections(), errb)
				}
			} else if code != 0 || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" {
				t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
			}
			tokenNowhere(t, out, errb)
		})
	}
}

// The refusal names where the first file really resolves, when that is not
// the setting as written.
func TestTheRefusalNamesTheResolvedKnownHosts(t *testing.T) {
	dir := privateDir(t)
	link := filepath.Join(dir, "kh_link")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte("UserKnownHostsFile "+link+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := sshPolicy(context.Background(), sshTestBin(t), sshOptions{config: cfg, device: "leaf1",
		address: "192.0.2.7", username: "alice"})
	if err == nil || !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), "/dev/null") {
		t.Fatalf("got %v", err)
	}
}

// Review M1: OpenSSH 8.5p1 prints no userknownhostsfile line for `none`. No
// line is no file that keeps a key, and is refused under accept-new.
func TestAnAbsentKnownHostsLineIsRefused(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "ssh")
	script := "#!/bin/sh\nif [ \"$1\" = -G ]; then echo 'stricthostkeychecking ask'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := sshPolicy(context.Background(), fake, sshOptions{device: "leaf1", address: "192.0.2.7", username: "alice"})
	if err == nil || !strings.Contains(err.Error(), "UserKnownHostsFile") {
		t.Fatalf("got %v", err)
	}
}

// Review M2: an operator's StrictHostKeyChecking no never reaches ssh as
// anything but the command line's accept-new, which wins over the config, in
// any block: a changed key still stops ssh before the token is sent.
func TestAnOperatorsStrictNoDoesNotWin(t *testing.T) {
	for name, extra := range map[string]string{
		"top":   "StrictHostKeyChecking no",
		"match": "Match all\n  StrictHostKeyChecking no",
		"host":  "Host *\n  StrictHostKeyChecking no",
	} {
		t.Run(name, func(t *testing.T) {
			dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
			r := newSSHRig(t, dev, sshPermit, 0, testHostKey(t), extra)
			code, out, errb := r.run(t, "leaf1", "--", "show", "version")
			if code != 255 || len(dev.attempts()) != 0 {
				t.Fatalf("code %d attempts %q stderr %q", code, dev.attempts(), errb)
			}
			tokenNowhere(t, out, errb)
		})
	}
}

// Review M5: the ssh-keygen hint for an alias that needs quoting is one
// pasteable command, quoted once.
func TestTheKeygenHintForAQuotedAliasPastes(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	fake := filepath.Join(t.TempDir(), "ssh")
	script := "#!/bin/sh\nif [ \"$1\" = -V ]; then echo 'OpenSSH_10.2p1, OpenSSL 3.5.5' >&2; exit 0; fi\n" +
		"if [ \"$1\" = -G ]; then echo 'hostkeyalias a b'; echo 'userknownhostsfile " + r.known + "'; exit 0; fi\nexit 255\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = fake
	code, _, errb := r.run(t, "leaf1")
	if code != 255 || !strings.Contains(errb, "run ssh-keygen -R 'a b' and") || strings.Contains(errb, "'ssh-keygen -R") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}
