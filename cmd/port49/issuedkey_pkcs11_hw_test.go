//go:build hwkey && hwkey_dlopen && linux

package main

import (
	"crypto"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/hwkey/hwtest"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/userconfig"
)

// tokenKey is a SoftHSM token with a key `%10` on it, as the user made once
// with `ykman piv keys generate`: the harness makes it, and the test sees
// that port49 does not, by the module's counters and the token's object list.
func tokenKey(t *testing.T) (ref, label string) {
	t.Helper()
	module, label := hwtest.SoftHSMBare(t)
	u := pkcs11.URI{Token: label, ID: []byte{0x10}, ModulePath: module}
	s, err := pkcs11.Generate(u, []byte(hwtest.SoftHSMUserPIN))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return "pkcs11:token=" + label + ";id=%10?module-path=" + module, label
}

// issuedKeyConfig is a config file naming the issued key's store and key.
func issuedKeyConfig(t *testing.T, ref string) string {
	t.Helper()
	cfg := filepath.Join(privateDir(t), "config.yaml")
	if err := os.WriteFile(cfg, []byte("issued_key_store: pkcs11\nissued_key: \""+ref+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// issued_key_store: pkcs11 signs the CSR with the key the user made and
// writes the certificate alone: no key file, and nothing to the token. The PIN
// is asked once, before the browser, and travels to the agent on a descriptor.
func TestLoginOIDCSignsWithTheTokensKeyAndWritesNothingToIt(t *testing.T) {
	ref, label := tokenKey(t)
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	prompts, shown := pinPty(t, hwtest.SoftHSMUserPIN, hwtest.SoftHSMUserPIN) // the second is the later login's
	before, gen, create := hwtest.SoftHSMObjects(t, label), pkcs11.GenerateKeyPairCalls(), pkcs11.CreateObjectCalls()
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	code, out, errb := o.loginOn(t, sock, "--config", issuedKeyConfig(t, ref))
	if code != 0 || !strings.Contains(out, "port49: signed in at "+o.iss.URL) ||
		!strings.Contains(out, "  leaf1 (alice)  extended to ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errb)
	}
	if prompts.Load() != 1 {
		t.Fatalf("the PIN was asked %d times", prompts.Load())
	}
	_, keyPath := o.issuedPaths(t)
	certPath, err := userconfig.IssuedTokenPaths(o.url, tokenKeyName(ref))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(keyPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a key file was written: %v", err)
	}
	tpmCert, tpmKey, _ := userconfig.IssuedTPMPaths(o.url)
	for _, p := range []string{tpmCert, tpmKey} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s was written", p)
		}
	}
	if after := hwtest.SoftHSMObjects(t, label); after != before {
		t.Fatalf("the token's objects changed:\nbefore\n%s\nafter\n%s", before, after)
	}
	if g, c := pkcs11.GenerateKeyPairCalls(), pkcs11.CreateObjectCalls(); g != gen || c != create {
		t.Fatalf("the login generated %d keys and created %d objects on the token", g-gen, c-create)
	}
	// The certificate is for the token's key.
	s, err := pkcs11.Open(mustURI(t, ref), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(leafAt(t, certPath).PublicKey) {
		t.Fatal("the certificate's key is not the token's")
	}
	// Nothing the PIN typed is anywhere the login wrote.
	for _, text := range []string{out, errb, agentLog(sock), shown.String()} {
		if strings.Contains(text, hwtest.SoftHSMUserPIN+"\n") && text != shown.String() {
			t.Fatal("the PIN reached the terminal output or the agent's log")
		}
	}
	o.credentialsNowhere(t, out, errb, agentLog(sock))
	// A new agent over the held pair: the PIN once more, no second sign-in.
	stopAgentAt(sock)
	o.step(11 * time.Second)
	code, out, errb = o.loginOn(t, sock, "--config", issuedKeyConfig(t, ref))
	if code != 0 || !strings.HasPrefix(out, "port49: using your certificate for user:alice@example.com") ||
		prompts.Load() != 2 || n(o) != 1 {
		t.Fatalf("code %d stdout %q stderr %q (%d prompts, %d sign-ins)", code, out, errb, prompts.Load(), n(o))
	}
}

func mustURI(t *testing.T, ref string) pkcs11.URI {
	t.Helper()
	u, err := pkcs11.ParseURI(ref)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// An issued_key that names no key refuses before the browser, saying to make
// one with the token's own tool, and makes none.
func TestAnIssuedKeyThatNamesNoKeyRefusesBeforeTheBrowser(t *testing.T) {
	made, label := tokenKey(t)
	ref := strings.Replace(made, "id=%10", "id=%77", 1) // the token holds %10 alone
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	prompts, _ := pinPty(t, hwtest.SoftHSMUserPIN)
	before, gen, create := hwtest.SoftHSMObjects(t, label), pkcs11.GenerateKeyPairCalls(), pkcs11.CreateObjectCalls()
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	code, out, errb := o.loginOn(t, sock, "--config", issuedKeyConfig(t, ref))
	if code == 0 || !strings.Contains(errb, "make one with the token's own tool") ||
		!strings.Contains(errb, "ykman piv keys generate") || n(o) != 0 || prompts.Load() != 0 {
		t.Fatalf("code %d stdout %q stderr %q (%d sign-ins, %d prompts)", code, out, errb, n(o), prompts.Load())
	}
	if hwtest.SoftHSMObjects(t, label) != before || pkcs11.GenerateKeyPairCalls() != gen || pkcs11.CreateObjectCalls() != create {
		t.Fatal("a refused login wrote to the token")
	}
}

// A token that is not plugged in says to insert it, and never to generate a
// key: `ykman piv keys generate` on a slot that holds the key replaces it.
func TestAnIssuedKeyOnATokenThatIsOutSaysToInsertIt(t *testing.T) {
	ref, label := tokenKey(t)
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	hwtest.SoftHSMUnplug(t, label) // no token is present
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	code, stdout, errb := o.loginOn(t, sock, "--config", issuedKeyConfig(t, ref))
	if code == 0 || !strings.Contains(errb, "insert the token holding pkcs11:token="+label) ||
		strings.Contains(errb, "ykman") || strings.Contains(errb, "(present:") || n(o) != 0 {
		t.Fatalf("code %d stdout %q stderr %q (%d sign-ins)", code, stdout, errb, n(o))
	}
}

// With other tokens in and none matching, the error names what is present
// (label, serial, manufacturer: no PIN, no object) and says the reference may
// be wrong, instead of only "insert the token": a typo pushed to a fleet reads
// as a missing token otherwise.
func TestAnIssuedKeyMatchingNoPresentTokenNamesThePresentOnes(t *testing.T) {
	ref, label := tokenKey(t)
	typo := strings.Replace(ref, "token="+label, "token="+label+"-typo", 1)
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	code, stdout, errb := o.loginOn(t, sock, "--config", issuedKeyConfig(t, typo))
	if code == 0 || !strings.Contains(errb, "no token present matches pkcs11:token="+label+"-typo") ||
		!strings.Contains(errb, "present: token="+label+" serial=") || !strings.Contains(errb, "reference may be wrong") ||
		strings.Contains(errb, hwtest.SoftHSMUserPIN) || strings.Contains(errb, "ykman") || n(o) != 0 {
		t.Fatalf("code %d stdout %q stderr %q (%d sign-ins)", code, stdout, errb, n(o))
	}
}

// A token host (`pkcs11`) and a file host sharing a home each sign in once and
// log in again with neither forced to sign in again: the token's certificate
// is named for its key, so the file host's is not overwritten (decision 45
// ruling 7, amended).
func TestATokenHostAndAFileHostSharingAHomeSignInOnce(t *testing.T) {
	ref, _ := tokenKey(t)
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	pinPty(t, hwtest.SoftHSMUserPIN, hwtest.SoftHSMUserPIN, hwtest.SoftHSMUserPIN)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	tokenCfg := issuedKeyConfig(t, ref)
	fileCfg := filepath.Join(privateDir(t), "file.yaml")
	if err := os.WriteFile(fileCfg, []byte("issued_key_store: file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	login := func(cfg string, signIns int, wantStore string) {
		t.Helper()
		stopAgentAt(sock)
		o.step(11 * time.Second)
		code, out, errb := o.loginOn(t, sock, "--config", cfg)
		if code != 0 || n(o) != signIns {
			t.Fatalf("%s: code %d stdout %q stderr %q (%d sign-ins, want %d)", wantStore, code, out, errb, n(o), signIns)
		}
		sf := &sessionFlags{broker: o.url, issuedKeyStore: wantStore, issuedKey: ref}
		if pair, _, _, err := findHeld(sf); err != nil || pair.store != wantStore {
			t.Fatalf("%s: the held pair %+v %v", wantStore, pair, err)
		}
	}
	login(tokenCfg, 1, "pkcs11")
	login(fileCfg, 2, "file")
	login(tokenCfg, 2, "pkcs11")
	login(fileCfg, 2, "file")
	login(tokenCfg, 2, "pkcs11")
}

// A login while the agent holds the issued token key reads the agent's key
// state first and never opens the token (spec decision 45 ruling 8): a key
// that came back Locked is asked its PIN, unlocked through the agent and
// refreshed, where it looped on the agent's "run `port49 login`" before; one
// that is out says to insert it. No sign-in either way (final review client
// I2).
func TestALoginToAnAgentHoldingTheIssuedTokenKeyUnlocksThroughIt(t *testing.T) {
	ref := "pkcs11:token=held;id=%10?module-path=/nonexistent/module.so"
	o := newOIDCLab(t, true)
	sock := privateSocket(t)
	h := serveHeldAgent(t, o.labBroker, sock, ref, "a-fingerprint", "locked")
	cfg := issuedKeyConfig(t, ref)
	prompts, _ := pinPty(t, hwtest.SoftHSMUserPIN)
	opens, logins := pkcs11.OpenCalls(), pkcs11.LoginCalls()
	code, out, errb := o.loginOn(t, sock, "--config", cfg)
	h.mu.Lock()
	pins, refreshes := h.pins, h.refresh
	h.mu.Unlock()
	if code != 0 || prompts.Load() != 1 || pins != 1 || refreshes != 1 || n(o) != 0 {
		t.Fatalf("locked: code %d prompts %d unlocks %d refreshes %d sign-ins %d stdout %q stderr %q",
			code, prompts.Load(), pins, refreshes, n(o), out, errb)
	}
	if pkcs11.OpenCalls() != opens || pkcs11.LoginCalls() != logins {
		t.Fatal("the login opened the token though the agent held the key")
	}

	h.mu.Lock()
	h.state = "absent"
	h.mu.Unlock()
	code, out, errb = o.loginOn(t, sock, "--config", cfg)
	if code != 1 || !strings.Contains(errb, "insert your key and run `port49 login` again") || n(o) != 0 {
		t.Fatalf("absent: code %d stdout %q stderr %q (%d sign-ins)", code, out, errb, n(o))
	}
	if pkcs11.OpenCalls() != opens || pkcs11.LoginCalls() != logins {
		t.Fatal("the login opened the token though the agent held the key")
	}
}

// A wrong PIN is found before the browser, costs one try, is not retried, and
// leaves no certificate.
func TestAWrongPINForTheIssuedKeyEndsTheLoginBeforeTheSignIn(t *testing.T) {
	ref, _ := tokenKey(t)
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	prompts, shown := pinPty(t, "000000")
	logins := hwtest.SoftHSMLoginAttempts(t)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	code, out, errb := o.loginOn(t, sock, "--config", issuedKeyConfig(t, ref))
	if code != 1 || !strings.Contains(errb, "the token refused the PIN") || n(o) != 0 || prompts.Load() != 1 ||
		hwtest.SoftHSMLoginAttempts(t) != logins+1 {
		t.Fatalf("code %d stdout %q stderr %q (%d sign-ins, %d prompts, %d logins)", code, out, errb, n(o), prompts.Load(),
			hwtest.SoftHSMLoginAttempts(t)-logins)
	}
	for _, text := range []string{out, errb, shown.String()} {
		if strings.Contains(text, "000000") {
			t.Fatal("the PIN was shown")
		}
	}
	certPath, _ := userconfig.IssuedTokenPaths(o.url, tokenKeyName(ref))
	if _, err := os.Lstat(certPath); err == nil {
		t.Fatal("a certificate was kept")
	}
}
