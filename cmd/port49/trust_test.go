package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hostkeys"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// trustRig swaps the scan for one that presents key and counts its calls,
// the terminal for tty and answer, and returns the pins file to use.
func trustRig(t *testing.T, key ssh.PublicKey, tty bool, answer string) (known string, scans *atomic.Int32, addr *string) {
	t.Helper()
	scans, addr = new(atomic.Int32), new(string)
	prevScan, prevTTY, prevAnswer := trustScan, trustIsTerminal, trustAnswer
	trustScan = func(_ context.Context, a string) (ssh.PublicKey, error) {
		scans.Add(1)
		*addr = a
		if key == nil {
			return nil, errors.New("connection refused")
		}
		return key, nil
	}
	trustIsTerminal = func() bool { return tty }
	trustAnswer = strings.NewReader(answer)
	t.Cleanup(func() { trustScan, trustIsTerminal, trustAnswer = prevScan, prevTTY, prevAnswer })
	return filepath.Join(privateDir(t), "known_hosts"), scans, addr
}

var leafPermit = api.MintItem{Device: "leaf1", Verdict: "permit", Username: "alice", Login: "LOGINTOKEN",
	Address: "172.100.100.11", Platform: "arista_eos"}

func pinnedFor(t *testing.T, known, device string) []ssh.PublicKey {
	t.Helper()
	keys, err := hostkeys.Lookup(known, device)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// With the fingerprint the operator verified, trust pins it; the address is
// the mint's (decision 42 ruling 9).
func TestTrustPinsTheFingerprintYouVerified(t *testing.T) {
	key := testHostKey(t)
	known, _, addr := trustRig(t, key, false, "")
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint",
		hostkeys.Fingerprint(key), "leaf1"}, &out, &errb)
	if code != 0 || *addr != "172.100.100.11:22" || len(pinnedFor(t, known, "leaf1")) != 1 ||
		!strings.Contains(out.String(), "pinned ssh-ed25519 "+hostkeys.Fingerprint(key)+" for leaf1") {
		t.Fatalf("code %d addr %q stdout %q stderr %q", code, *addr, out.String(), errb.String())
	}
	if strings.Contains(out.String()+errb.String(), "LOGINTOKEN") {
		t.Fatal("the mint's token was printed")
	}
}

// A different fingerprint pins nothing, and says the address may be wrong.
func TestTrustRefusesAFingerprintThatDiffers(t *testing.T) {
	known, _, _ := trustRig(t, testHostKey(t), false, "")
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint",
		hostkeys.Fingerprint(testHostKey(t)), "leaf1"}, &out, &errb)
	if code != 1 || len(pinnedFor(t, known, "leaf1")) != 0 || !strings.Contains(errb.String(), "nothing pinned") ||
		!strings.Contains(errb.String(), "check inventory's address for leaf1") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// In a script, without --fingerprint, nothing is pinned: a key is never
// pinned unseen.
func TestTrustOnAScriptWithoutAFingerprintPinsNothing(t *testing.T) {
	known, _, _ := trustRig(t, testHostKey(t), false, "yes\n")
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "leaf1"}, &out, &errb); code != 2 ||
		len(pinnedFor(t, known, "leaf1")) != 0 || !strings.Contains(errb.String(), "pass --fingerprint") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// On a terminal it asks, and pins on yes alone.
func TestTrustAsksOnATerminal(t *testing.T) {
	for answer, pinned := range map[string]bool{"yes\n": true, "no\n": false, "y\n": false, "": false} {
		known, _, _ := trustRig(t, testHostKey(t), true, answer)
		sock := fakeAgent(t, http.StatusOK, leafPermit)
		var out, errb bytes.Buffer
		code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "leaf1"}, &out, &errb)
		if (code == 0) != pinned || (len(pinnedFor(t, known, "leaf1")) == 1) != pinned ||
			!strings.Contains(out.String(), "Pin it? [yes/no]: ") {
			t.Errorf("answer %q: code %d stdout %q stderr %q", answer, code, out.String(), errb.String())
		}
	}
}

// An existing pin is replaced only with --replace, and is never scanned for
// without it.
func TestTrustNeverReplacesWithoutReplace(t *testing.T) {
	old, key := testHostKey(t), testHostKey(t)
	known, scans, _ := trustRig(t, key, false, "")
	if err := hostkeys.Pin(known, "leaf1", old, false); err != nil {
		t.Fatal(err)
	}
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	args := []string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint", hostkeys.Fingerprint(key)}
	var out, errb bytes.Buffer
	if code := run(append(args, "leaf1"), &out, &errb); code != 1 || scans.Load() != 0 ||
		!strings.Contains(errb.String(), "already pinned") {
		t.Fatalf("without --replace: code %d stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := run(append(args, "--replace", "leaf1"), &out, &errb); code != 0 {
		t.Fatalf("with --replace: code %d stderr %q", code, errb.String())
	}
	if got := pinnedFor(t, known, "leaf1"); len(got) != 1 || hostkeys.Fingerprint(got[0]) != hostkeys.Fingerprint(key) {
		t.Fatalf("pinned %v", got)
	}
}

// A device the caller holds no grant on is refused at the mint, and is never
// scanned: trust is no oracle.
func TestTrustWithoutAGrantLearnsNothing(t *testing.T) {
	known, scans, _ := trustRig(t, testHostKey(t), false, "")
	sock := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint", "SHA256:x",
		"leaf1"}, &out, &errb); code != 1 || scans.Load() != 0 ||
		!strings.Contains(errb.String(), "port49 devices trust: leaf1: deny no_grants_matched") {
		t.Fatalf("code %d scans %d stderr %q", code, scans.Load(), errb.String())
	}
}

// --address skips the mint: no agent needed.
func TestTrustWithAnAddressMintsNothing(t *testing.T) {
	key := testHostKey(t)
	known, _, addr := trustRig(t, key, false, "")
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--socket", filepath.Join(t.TempDir(), "none.sock"), "--known-hosts", known,
		"--address", "192.0.2.7", "--port", "2222", "--fingerprint", hostkeys.Fingerprint(key), "leaf1"}, &out, &errb)
	if code != 0 || *addr != "192.0.2.7:2222" {
		t.Fatalf("code %d addr %q stderr %q", code, *addr, errb.String())
	}
}

// A name known_hosts would read as a pattern is refused before anything.
func TestTrustRefusesANameThatIsAPattern(t *testing.T) {
	known, scans, _ := trustRig(t, testHostKey(t), false, "")
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "trust", "--known-hosts", known, "leaf*"}, &out, &errb); code != 2 ||
		scans.Load() != 0 || !strings.Contains(errb.String(), "letters, digits") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
