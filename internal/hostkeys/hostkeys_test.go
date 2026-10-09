package hostkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func same(a, b ssh.PublicKey) bool { return string(a.Marshal()) == string(b.Marshal()) }

// privateDir is a fresh directory only this user can write, whatever the
// umask: under umask 002 a t.TempDir is group-writable, and the pins are
// never read or written below one.
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// A pin is read back by its device's name alone; a second pin is refused
// without replace; replace removes the old key; other lines stay.
func TestPinThenLookup(t *testing.T) {
	path := filepath.Join(privateDir(t), "port49", "known_hosts")
	_, k1 := newKey(t)
	_, k2 := newKey(t)
	_, other := newKey(t)
	if err := Pin(path, "spine1", other, false); err != nil {
		t.Fatal(err)
	}
	if err := Pin(path, "leaf1", k1, false); err != nil {
		t.Fatal(err)
	}
	if got, err := Lookup(path, "leaf1"); err != nil || len(got) != 1 || !same(got[0], k1) {
		t.Fatalf("lookup: %v %v", got, err)
	}
	if err := Pin(path, "leaf1", k2, false); !errors.Is(err, ErrPinned) {
		t.Fatalf("a second pin without replace: %v", err)
	}
	if err := Pin(path, "leaf1", k2, true); err != nil {
		t.Fatal(err)
	}
	got, _ := Lookup(path, "leaf1")
	spine, _ := Lookup(path, "spine1")
	if len(got) != 1 || !same(got[0], k2) || len(spine) != 1 || !same(spine[0], other) {
		t.Fatalf("after replace: leaf1 %v spine1 %v", got, spine)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
}

// A pattern, a marker or a hashed line never pins a device by its name.
func TestLookupReadsExactNamesAndNoMarkers(t *testing.T) {
	_, k := newKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	dir := privateDir(t)
	path := filepath.Join(dir, "known_hosts")
	body := "# the operator's comment\nleaf* " + line + "\n@revoked leaf1 " + line + "\nleaf1,leaf2 " + line + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Lookup(path, "leaf1"); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := Lookup(filepath.Join(dir, "none"), "leaf1"); err != nil || got != nil {
		t.Fatalf("a missing file pins nothing: %v %v", got, err)
	}
}

// Two trust runs at once both keep their pin: Pin holds a lock across its
// read and its write.
func TestConcurrentPinsLoseNothing(t *testing.T) {
	path := filepath.Join(privateDir(t), "port49", "known_hosts")
	var wg sync.WaitGroup
	for i := range 8 {
		_, k := newKey(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Pin(path, fmt.Sprintf("leaf%d", i), k, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i := range 8 {
		if got, err := Lookup(path, fmt.Sprintf("leaf%d", i)); err != nil || len(got) != 1 {
			t.Errorf("leaf%d: %v %v", i, got, err)
		}
	}
}

// A directory the walk refuses gets nothing: no lock file, no known_hosts,
// and no directory made below it (plan re-review R-N6).
func TestPinInARefusedDirectoryLeavesNothing(t *testing.T) {
	top := privateDir(t)
	if err := os.Chmod(top, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(top, 0o700) })
	_, k := newKey(t)
	// Missing below a refused directory.
	if err := Pin(filepath.Join(top, "port49", "known_hosts"), "leaf1", k, false); err == nil ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a world-writable parent: %v", err)
	}
	if ents, err := os.ReadDir(top); err != nil || len(ents) != 0 {
		t.Fatalf("left behind: %v %v", ents, err)
	}
	// An existing refused directory.
	if err := os.Chmod(top, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(top, "bad")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o700) })
	if err := Pin(filepath.Join(bad, "known_hosts"), "leaf1", k, false); err == nil {
		t.Fatal("pinned under a world-writable directory")
	}
	if ents, _ := os.ReadDir(bad); len(ents) != 0 {
		t.Fatalf("left behind: %v", ents)
	}
	if _, err := os.Lstat(filepath.Join(bad, "known_hosts.lock")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a lock file in a refused directory: %v", err)
	}
}

func TestValidName(t *testing.T) {
	for name, ok := range map[string]bool{
		"leaf1": true, "core-sw01.dc1": true, "srx_fw_04": true, strings.Repeat("a", 253): true,
		"": false, "*": false, "leaf*": false, "a,b": false, "!x": false, "@cert-authority": false,
		"|1|abc": false, "[leaf1]:22": false, "-leaf": false, ".leaf": false, "leaf 1": false,
		"leaf?": false, strings.Repeat("a", 254): false,
	} {
		if ValidName(name) != ok {
			t.Errorf("ValidName(%q) = %v", name, !ok)
		}
	}
}

// Scan reads the key the server presents and offers no credential: no
// authentication callback of the server's ever runs.
func TestScanReadsTheKeyAndSendsNoCredential(t *testing.T) {
	signer, pub := newKey(t)
	var auths atomic.Int32
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			auths.Add(1)
			return nil, errors.New("no")
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			auths.Add(1)
			return nil, errors.New("no")
		},
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { auths.Add(1) },
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _, _, _ = ssh.NewServerConn(c, cfg)
		c.Close()
	}()
	got, err := Scan(context.Background(), ln.Addr().String())
	<-done
	if err != nil || !same(got, pub) || auths.Load() != 0 {
		t.Fatalf("key %v err %v, %d auth attempts", got, err, auths.Load())
	}
}
