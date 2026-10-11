//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

// oidcLab is a real OIDC-only broker (newLabBrokerWith), issuing when
// newOIDCLab is told to, trusting an issuer whose authorization server
// signs alice in.
type oidcLab struct {
	*labBroker
	iss   *oidctest.Issuer
	as    *oidctest.AuthServer
	idpCA string
}

func newOIDCLab(t *testing.T, issue bool) *oidcLab {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	l := newLabBrokerWith(t, 12*time.Hour, iss, issue)
	o := &oidcLab{labBroker: l, iss: iss,
		as: iss.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})}
	o.as.Now = l.now
	o.idpCA = filepath.Join(privateDir(t), "idp-ca.pem")
	if err := os.WriteFile(o.idpCA, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o *oidcLab) flags(socket string, extra ...string) []string {
	return append([]string{"--oidc", "--broker", o.url, "--broker-ca", filepath.Join(o.dir, testpki.LabCA),
		"--oidc-ca", o.idpCA, "--socket", socket}, extra...)
}

// issuedPaths is where the login keeps this broker's certificate and key.
func (o *oidcLab) issuedPaths(t *testing.T) (string, string) {
	t.Helper()
	c, k, err := userconfig.IssuedPaths(o.url)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// holdCertificate writes a certificate the broker issued at at, for
// lifetime, and its key, where the login keeps them, as a login at that
// time would have.
func (o *oidcLab) holdCertificate(t *testing.T, at time.Time, lifetime time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.b.Issuer.Issue(key.Public(), issuer.SignIn{Principal: "user:alice@example.com", Issuer: o.iss.URL,
		Subject: "sub-alice", Sid: "s-sub-alice", AuthTime: at, IssuedAt: at}, at, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := o.issuedPaths(t)
	if err := userconfig.WritePrivate(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"test key"); err != nil {
		t.Fatal(err)
	}
	if err := userconfig.WritePrivate(certPath, o.b.Issuer.PEM(c), "test certificate"); err != nil {
		t.Fatal(err)
	}
}

// driveBrowser makes the sign-in's browser the issuer's: it follows the
// provider's redirect to the loopback listener, as a person's does.
func driveBrowser(t *testing.T, iss *oidctest.Issuer) {
	t.Helper()
	saved, savedTerm := openBrowser, stdinIsTerminal
	openBrowser = func(u string) error {
		go func() { _ = iss.Browser()(u) }()
		return nil
	}
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { openBrowser, stdinIsTerminal = saved, savedTerm })
}

// agentLog is the log of the agent listening on sock.
func agentLog(sock string) string {
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(sock), "agent.log"))
	return string(b)
}

// credentialsNowhere fails if any text holds a value the provider issued,
// a PKCE verifier the login sent it, or the first line of the issued key's
// PEM.
func (o *oidcLab) credentialsNowhere(t *testing.T, texts ...string) {
	t.Helper()
	secrets := o.as.Issued()
	for _, g := range o.as.Grants() {
		if v := g.Get("code_verifier"); v != "" {
			secrets = append(secrets, v)
		}
	}
	_, keyPath := o.issuedPaths(t)
	if raw, err := os.ReadFile(keyPath); err == nil {
		if blk, _ := pem.Decode(raw); blk != nil {
			secrets = append(secrets, base64.StdEncoding.EncodeToString(blk.Bytes)[:40])
		}
	}
	for _, text := range texts {
		for _, v := range secrets {
			if strings.Contains(text, v) {
				t.Fatal("a code, a token, a verifier or the key reached the terminal or the agent's log")
			}
		}
	}
}

// peerPid is the pid of the process listening on sock.
func peerPid(t *testing.T, sock string) int {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var cred *syscall.Ucred
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) { cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
	if cred == nil {
		t.Fatal("no peer credentials")
	}
	return int(cred.Pid)
}

// The real path: login signs in with the key's hash as the nonce, the broker
// issues, the key and certificate are kept 0600, the agent starts on them
// and refreshes once (D1: a key signature, no second sign-in), and `port49
// token` mints; the agent is non-dumpable; nothing the provider issued, nor
// the key, reaches the terminal or the log.
func TestLoginOIDCIssuesACertificateAndMints(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: signed in at "+o.iss.URL+" as user:alice@example.com; your "+
			"certificate from "+o.url+" is valid until ") ||
		!strings.Contains(out.String(), "port49: logged in to "+o.url) ||
		!strings.Contains(out.String(), "\nrefreshed at ") || !strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	certPath, keyPath := o.issuedPaths(t)
	held, s, err := heldCertificate(certPath, keyPath)
	if err != nil || s.Principal != "user:alice@example.com" || s.Sid != "s-sub-alice" {
		t.Fatalf("the held certificate: %+v %v", s, err)
	}
	want, _ := api.IssuanceNonce(held.PrivateKey.(crypto.Signer).Public())
	if q := o.as.Authorizations(); len(q) != 1 || q[0].Get("prompt") != "login" || q[0].Get("nonce") != want {
		t.Fatalf("%d sign-ins, the nonce the key's hash: %v", len(q), len(q) == 1 && q[0].Get("nonce") == want)
	}
	for _, p := range []string{certPath, keyPath} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	var tok, terr bytes.Buffer
	if code := run([]string{"token", "--socket", sock, "leaf1"}, &tok, &terr); code != 0 || strings.TrimSpace(tok.String()) == "" {
		t.Fatalf("token: code %d stderr %q", code, terr.String())
	}
	if os.Getuid() != 0 {
		// A non-dumpable process's /proc/<pid> files are root's (proc(5)),
		// which a user namespace with root unmapped shows as the overflow
		// uid: either way, not this user's.
		fi, err := os.Stat(fmt.Sprintf("/proc/%d/environ", peerPid(t, sock)))
		if err != nil {
			t.Fatal(err)
		}
		if uid := fi.Sys().(*syscall.Stat_t).Uid; uid == uint32(os.Getuid()) {
			t.Fatalf("the agent is dumpable: its /proc/<pid>/environ is this user's (uid %d)", uid)
		}
	}
	o.credentialsNowhere(t, out.String(), errb.String(), terr.String(), agentLog(sock))
}

// After the sign-in, no browser: a login with the agent running refreshes by
// the key; a new agent over the held certificate (a reboot) signs in no more
// and extends the device sessions an earlier login left (D1); `port49
// refresh` is a key signature; --sign-in with the agent running is refused.
func TestALoginOverAHeldCertificateSignsInNoMore(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	o.step(11 * time.Second) // past the connection's refresh pacing
	out.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "port49: already logged in to "+o.url+" as user:alice@example.com; refreshing\n") ||
		!strings.Contains(out.String(), "extended to") {
		t.Fatalf("with the agent running: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	stopAgentAt(sock)
	out.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "port49: using your certificate for user:alice@example.com (signed in at "+o.iss.URL) ||
		!strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("a new agent: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	o.step(11 * time.Second)
	out.Reset()
	if code := run([]string{"refresh", "--socket", sock}, &out, &errb); code != 0 || !strings.Contains(out.String(), "extended to") {
		t.Fatalf("refresh: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := run(append([]string{"login"}, o.flags(sock, "--sign-in")...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "stop that agent first") {
		t.Fatalf("--sign-in with the agent running: code %d stderr %q", code, errb.String())
	}
	if n := len(o.as.Authorizations()); n != 1 {
		t.Fatalf("%d sign-ins; one was due", n)
	}
	o.credentialsNowhere(t, out.String(), errb.String(), agentLog(sock))
}

// A held certificate with under a quarter of its life left is replaced by a
// sign-in (ruling 12).
func TestALateCertificateSignsInAgain(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	o.holdCertificate(t, time.Now().Add(-11*time.Hour), 12*time.Hour)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: signed in at ") || len(o.as.Authorizations()) != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// The provider down at 3am, a late certificate still valid: the login says
// the provider did not answer, uses the certificate, and the agent mints
// (rulings 12 and 17).
func TestAProviderOutageUsesAHeldCertificate(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	o.holdCertificate(t, time.Now().Add(-11*time.Hour), 12*time.Hour)
	o.iss.Close()
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), "did not answer") || !strings.Contains(errb.String(), "needs no identity provider") ||
		!strings.Contains(errb.String(), "until your identity provider answers") ||
		!strings.Contains(out.String(), "port49: logged in to "+o.url) {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	var tok, terr bytes.Buffer
	if code := run([]string{"token", "--socket", sock, "leaf1"}, &tok, &terr); code != 0 {
		t.Fatalf("token: code %d stderr %q", code, terr.String())
	}
}

// The provider down, nothing held: said at once, exit 1, no agent started.
func TestAProviderOutageWithNoCertificateSaysSo(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	o.iss.Close()
	sock := privateSocket(t)
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "did not answer") || !strings.Contains(errb.String(), "cannot sign you in until it answers") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("an agent started")
	}
}

// A held certificate whose sign-in a logout ended: the new agent's refresh
// is refused in the broker's words, the login removes the certificate and
// its key, and says the next login signs in (ruling 12; R6).
func TestARevokedHeldCertificateIsRemoved(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	stopAgentAt(sock)
	if _, err := o.b.Logout(context.Background(), oidc.LogoutToken{Issuer: o.iss.URL, Sid: "s-sub-alice",
		IssuedAt: o.now(), Domains: []string{"example.com"}}, "backchannel_logout "+o.iss.URL); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "the broker refused your certificate") ||
		!strings.Contains(errb.String(), "back-channel logout") || !strings.Contains(errb.String(), "it is removed") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	certPath, keyPath := o.issuedPaths(t)
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s is still there: %v", p, err)
		}
	}
}

// A held certificate the broker refuses at the handshake (its clock past the
// certificate's end, this host's not): the login says to sign in again.
func TestABrokerThatRefusesAHeldCertificateSaysToSignIn(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	stopAgentAt(sock)
	o.step(13 * time.Hour)
	errb.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "`port49 login --sign-in` signs you in again") || len(o.as.Authorizations()) != 1 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// With no browser, the address is printed and a pasted one completes the
// sign-in (ruling 5).
func TestLoginOIDCWithAPastedAddress(t *testing.T) {
	o := newOIDCLab(t, true)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	urls := make(chan string, 1)
	saved := [3]any{openBrowser, stdinIsTerminal, readPaste}
	openBrowser = func(u string) error { urls <- u; return fmt.Errorf("no display") }
	stdinIsTerminal = func() bool { return true }
	readPaste = func() (string, error) { return o.iss.Redirected(<-urls) }
	t.Cleanup(func() {
		openBrowser = saved[0].(func(string) error)
		stdinIsTerminal = saved[1].(func() bool)
		readPaste = saved[2].(func() (string, error))
	})
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), "open this address in a browser") ||
		!strings.Contains(errb.String(), "paste it here (it is not shown)") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	o.credentialsNowhere(t, out.String(), errb.String())
}

// No browser and no terminal, with an ephemeral port: said at once, naming
// the two ways that work (ruling 5).
func TestLoginOIDCWithNoWayBackSaysSoAtOnce(t *testing.T) {
	o := newOIDCLab(t, true)
	saved, savedTerm := openBrowser, stdinIsTerminal
	openBrowser = func(string) error { return fmt.Errorf("no display") }
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { openBrowser, stdinIsTerminal = saved, savedTerm })
	var out, errb bytes.Buffer
	start := time.Now()
	if code := run(append([]string{"login"}, o.flags(privateSocket(t))...), &out, &errb); code != 1 ||
		time.Since(start) > 10*time.Second || !strings.Contains(errb.String(), "ssh -t") ||
		!strings.Contains(errb.String(), "--redirect-port") || strings.Contains(errb.String(), "https://") {
		t.Fatalf("code %d after %s, stderr %q", code, time.Since(start), errb.String())
	}
}

// A provider that answers and is refused is not an outage: waiting changes
// nothing, so the login does not say to wait for it.
func TestADiscoveryRefusalIsNotAnOutage(t *testing.T) {
	o := newOIDCLab(t, true)
	o.iss.Discovery(func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} })
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(privateSocket(t))...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "S256") || strings.Contains(errb.String(), "until it answers") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// A broker that issues nothing is said, before any sign-in.
func TestABrokerThatIssuesNothingIsSaid(t *testing.T) {
	o := newOIDCLab(t, false)
	driveBrowser(t, o.iss)
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(privateSocket(t))...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "issues no certificates") || len(o.as.Authorizations()) != 0 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
