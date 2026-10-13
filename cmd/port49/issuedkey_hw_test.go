//go:build hwkey && linux

package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/tpm"
	"github.com/rhwendt/port49/internal/userconfig"
)

// loginTo runs `port49 login --oidc` against o on sock and returns what it
// said.
func (o *oidcLab) loginOn(t *testing.T, sock string, extra ...string) (code int, out, errb string) {
	t.Helper()
	t.Setenv(runCLIEnv, "1")
	var so, se bytes.Buffer
	code = run(append([]string{"login"}, o.flags(sock, extra...)...), &so, &se)
	return code, so.String(), se.String()
}

func readPair(t *testing.T, paths ...string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// certKey is the public key of the PEM certificate at path.
func leafAt(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		t.Fatalf("%s holds no PEM", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// On a TPM: `port49 login --oidc` makes its key there. Its file is
// <host>_<port>.<machine>.tpmkey, 0600, with no .key beside it; the
// certificate's key is the TPM's; the agent it starts, a process of its own
// that dials the same TPM, refreshes with it; and a later login finds the pair
// and signs in no more.
func TestLoginOIDCKeepsItsKeyInTheTPM(t *testing.T) {
	hwtest.SWTPM(t)
	machineIs(t, "aaaaaaaa")
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	code, out, errb := o.loginOn(t, sock)
	if code != 0 || !strings.Contains(errb, "the key is made in this machine's TPM") ||
		!strings.Contains(out, "port49: signed in at "+o.iss.URL) || !strings.Contains(out, "\nrefreshed at ") ||
		!strings.Contains(out, "  leaf1 (alice)  extended to ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errb)
	}
	fileCert, fileKey := o.issuedPaths(t)
	tpmCert, tpmKey, err := userconfig.IssuedTPMPaths(o.url)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(tpmKey, ".aaaaaaaa.tpmkey") || !strings.HasSuffix(tpmCert, ".aaaaaaaa.pem") {
		t.Fatalf("the TPM pair is named %s and %s", tpmKey, tpmCert)
	}
	for _, p := range []string{tpmCert, tpmKey} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	for _, p := range []string{fileKey, fileCert, tpmKey + ".new"} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s was written", p)
		}
	}
	s, err := tpm.Open(tpmKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if pub := leafAt(t, tpmCert).PublicKey; !s.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
		t.Fatal("the certificate's key is not the TPM's")
	}
	// The key never was in a file the agent or the log could show.
	o.credentialsNowhere(t, out, errb, agentLog(sock))
	// A new agent over the held pair: no sign-in, a key signature, the TPM
	// dialed again by the agent process.
	stopAgentAt(sock)
	o.step(11 * time.Second)
	code, out, errb = o.loginOn(t, sock)
	if code != 0 || !strings.HasPrefix(out, "port49: using your certificate for user:alice@example.com (signed in at "+o.iss.URL) ||
		!strings.Contains(out, "  leaf1 (alice)  extended to ") || n(o) != 1 {
		t.Fatalf("a new agent: code %d stdout %q stderr %q (%d sign-ins)", code, out, errb, n(o))
	}
}

func n(o *oidcLab) int { return len(o.as.Authorizations()) }

// A held pair is found by the TPM key file with no .key, and loads through
// the TPM.
func TestAHeldTPMPairLoads(t *testing.T) {
	hwtest.SWTPM(t)
	machineIs(t, "aaaaaaaa")
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	if code, out, errb := o.loginOn(t, sock); code != 0 {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errb)
	}
	pair, c, si, err := findHeld(&sessionFlags{broker: o.url})
	if err != nil || pair.store != "tpm" || si.Principal != "user:alice@example.com" || c.Leaf == nil {
		t.Fatalf("the held pair: %+v %+v %v", pair, si, err)
	}
}

// A shared home (pre-flight I12): another machine's pair is no held pair, so
// this machine signs in, writes its own, and leaves the other's byte for byte.
func TestASecondMachineLeavesTheFirstsTPMPairAlone(t *testing.T) {
	hwtest.SWTPM(t)
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	machineIs(t, "bbbbbbbb")
	if code, out, errb := o.loginOn(t, sock); code != 0 {
		t.Fatalf("machine b: code %d stdout %q stderr %q", code, out, errb)
	}
	bCert, bKey, _ := userconfig.IssuedTPMPaths(o.url)
	before := readPair(t, bCert, bKey)
	stopAgentAt(sock)
	machineIs(t, "aaaaaaaa")
	o.step(11 * time.Second)
	code, out, errb := o.loginOn(t, sock)
	if code != 0 || !strings.Contains(out, "port49: signed in at ") || n(o) != 2 {
		t.Fatalf("machine a: code %d stdout %q stderr %q (%d sign-ins)", code, out, errb, n(o))
	}
	aCert, aKey, _ := userconfig.IssuedTPMPaths(o.url)
	if aCert == bCert || aKey == bKey {
		t.Fatalf("both machines name %s", aKey)
	}
	after := readPair(t, bCert, bKey)
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Errorf("machine b's file %d changed", i)
		}
	}
	for _, p := range []string{aCert, aKey} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("machine a wrote no %s: %v", p, err)
		}
	}
}

// A file pair left by an older port49 is replaced: the sign-in makes its key
// in the TPM and the old .key goes, so the held pair is found by one key file.
func TestATPMSignInRemovesTheOlderKeyFile(t *testing.T) {
	hwtest.SWTPM(t)
	machineIs(t, "aaaaaaaa")
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	o.holdCertificate(t, time.Now().Add(-11*time.Hour), 12*time.Hour)
	_, fileKey := o.issuedPaths(t)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	if code, out, errb := o.loginOn(t, sock); code != 0 || n(o) != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errb)
	}
	if _, err := os.Lstat(fileKey); err == nil {
		t.Fatal("the older .key is still there")
	}
	if pair, _, _, err := findHeld(&sessionFlags{broker: o.url}); err != nil || pair.store != "tpm" {
		t.Fatalf("the held pair: %+v %v", pair, err)
	}
}

// A key file the TPM here cannot load (a cleared TPM, a TPM from another
// machine) is said, and the login signs in for a new key; nothing loops on it.
func TestATPMKeyFromAnotherTPMIsReplacedBySigningIn(t *testing.T) {
	hwtest.SWTPM(t)
	machineIs(t, "aaaaaaaa")
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	if code, out, errb := o.loginOn(t, sock); code != 0 {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errb)
	}
	stopAgentAt(sock)
	hwtest.SWTPMFresh(t)
	o.step(11 * time.Second)
	code, out, errb := o.loginOn(t, sock)
	if code != 0 || !strings.Contains(errb, "another TPM") || !strings.Contains(out, "port49: signed in at ") || n(o) != 2 {
		t.Fatalf("code %d stdout %q stderr %q (%d sign-ins)", code, out, errb, n(o))
	}
	_, tk, _ := userconfig.IssuedTPMPaths(o.url)
	if s, err := tpm.Open(tk); err != nil {
		t.Fatalf("the new key does not load: %v", err)
	} else {
		s.Close()
	}
	if _, err := os.Stat(filepath.Dir(tk)); err != nil {
		t.Fatal(err)
	}
}

// A TPM unplugged after the sign-in: the held pair's key is out, and the
// login says to put it back instead of calling the certificate another's.
func TestAHeldTPMKeyThatIsOutSaysToInsertIt(t *testing.T) {
	tp := hwtest.SWTPM(t)
	machineIs(t, "aaaaaaaa")
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	if code, out, errb := o.loginOn(t, sock); code != 0 {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errb)
	}
	stopAgentAt(sock)
	tp.Stop()
	code, out, errb := o.loginOn(t, sock)
	if code != 1 || !strings.Contains(errb, "your key (tpm) is not present: insert it, or `port49 login --sign-in` signs in for a new one") ||
		n(o) != 1 {
		t.Fatalf("code %d stdout %q stderr %q (%d sign-ins)", code, out, errb, n(o))
	}
}
