package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/brokercrl"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/mfatouch"
	"github.com/rhwendt/port49/internal/oidcclient"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/userconfig"
)

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// loginIssued is `port49 login` on the OIDC path (spec §13 decision 43
// rulings 7, 8, 11, 12 and 17): a certificate the broker issues over a
// sign-in at the provider it lists. A held one with more than a quarter of
// its life left is used with no sign-in; otherwise this process signs in,
// generates a key, and asks the broker for a certificate for it. The agent
// then holds the session as on the certificate path, so a refresh, and a
// new agent's extension of the device sessions an earlier login left, are
// key signatures (ruling 11). With the provider down, a held certificate
// still valid is used, late or not.
func loginIssued(sf *sessionFlags, stdout, stderr io.Writer) int {
	ctx := context.Background()
	if sf.broker == "" {
		fmt.Fprintf(stderr, "port49 login: --broker and --broker-ca are required, as flags or in %s\n", sf.configFile)
		return 2
	}
	pool, err := sf.brokerPool()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	certPath, _, err := userconfig.IssuedPaths(sf.broker)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	// The key kept here is a session: out of backups, on every login, as the
	// first one and as the one after an upgrade (idempotent).
	if err := markIssuedDir(filepath.Dir(certPath)); err != nil {
		fmt.Fprintf(stderr, "port49 login: warning: %v; exclude %s from your backups\n", err, filepath.Dir(certPath))
	}
	// A PIN asked for the agent is zeroed whichever way the login ends.
	defer func() { clear(sf.pin) }()
	pair, heldErr := pickHeldPair(sf)
	if heldErr == nil {
		if code, done := loginToIssuedHeldKey(ctx, sf, pair, stdout, stderr); done {
			return code
		}
	}
	var held tls.Certificate
	var s issuer.SignIn
	if heldErr == nil {
		held, s, heldErr = heldCertificate(pair.cert, pair.key)
	}
	// A held certificate whose key is out (a token unplugged) is still the
	// certificate of the session an agent may hold.
	var keyErr *heldKeyError
	keyOut := errors.As(heldErr, &keyErr)
	if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
		// As on the certificate path: only the session this certificate
		// holds is refreshed; another's is someone else's identity.
		var other string
		switch {
		case strings.TrimRight(sf.broker, "/") != st.Broker:
			other = fmt.Sprintf("an agent logged in to %s", st.Broker)
		case heldErr != nil && !keyOut || agent.CertFingerprint(held) != st.CertFingerprint:
			other = fmt.Sprintf("an agent for %s with another certificate", st.Broker)
		}
		if other != "" {
			fmt.Fprintf(stderr, "port49 login: %s already holds %s; run 'port49 refresh' to extend that session, "+
				"stop that agent first, or use --socket\n", other, sf.socket)
			return 1
		}
		if sf.signIn {
			fmt.Fprintf(stderr, "port49 login: an agent already holds your session at %s, with your certificate for %s "+
				"valid until %s; `port49 refresh` extends it; to sign in again, stop that agent first\n", st.Broker,
				s.Principal, rfc3339(held.Leaf.NotAfter))
			return 1
		}
		fmt.Fprintf(stdout, "port49: already logged in to %s as %s; refreshing\n", st.Broker, s.Principal)
		out, err := agent.NewClient(sf.socket).Refresh(ctx, "")
		if err != nil {
			fmt.Fprintln(stderr, "port49 login: refreshing the running agent's session:", unprefixed(err))
			return 1
		}
		printRefresh(stdout, out)
		if api.LateRenewal(held.Leaf, time.Now()) {
			// The agent ends with the certificate, and --sign-in is refused
			// while it runs: say how to renew before then.
			fmt.Fprintf(stdout, "port49: your certificate ends at %s, and the agent with it; to renew before then, "+
				"stop the agent and run `port49 login`\n", rfc3339(held.Leaf.NotAfter))
		}
		return 0
	}
	now := time.Now()
	switch {
	case keyOut && keyErr.absent():
		fmt.Fprintf(stderr, "port49 login: your key (%s) is not present: insert it, or `port49 login --sign-in` signs "+
			"in for a new one\n", keyErr.store())
		if !sf.signIn {
			return 1
		}
	case errors.Is(heldErr, fs.ErrNotExist) && sf.issuedKeyStore == storeTPM:
		// A file key on this home is not used: the operator named the TPM.
		fmt.Fprintln(stderr, "port49 login: no TPM key for this machine yet")
	case heldErr != nil && !errors.Is(heldErr, fs.ErrNotExist):
		fmt.Fprintf(stderr, "port49 login: your held certificate is not used: %v\n", heldErr)
	}
	usable := heldErr == nil && now.Before(held.Leaf.NotAfter)
	if usable && !sf.signIn && !api.LateRenewal(held.Leaf, now) {
		fmt.Fprintf(stdout, "port49: using your certificate for %s (signed in at %s at %s), valid until %s; "+
			"`port49 login --sign-in` signs in again\n", s.Principal, s.Issuer, rfc3339(s.AuthTime),
			rfc3339(held.Leaf.NotAfter))
		return startIssued(sf, pair, true, stdout, stderr)
	}
	issued, code, err := issueCertificate(ctx, sf, pool, stdout, stderr)
	if err == nil {
		return startIssued(sf, issued, false, stdout, stderr)
	}
	// A held certificate outlives any failure of the sign-in (ruling 17:
	// only a sign-in fails), except a revocation or logout: the broker
	// judges the certificate by the same mark.
	var refused *refusedError
	var unreachable *oidcclient.UnreachableError
	var silent *brokerDownError
	var said saidError
	down := errors.As(err, &unreachable)
	switch {
	case errors.As(err, &said):
		// The PIN prompt has said why; a held certificate is for the same key.
		return code
	case errors.As(err, &silent):
		// The held certificate is judged by this same broker, so there is
		// nothing to start it against; a sign-in would cost a password and
		// MFA and fail at the same place.
		if usable {
			fmt.Fprintf(stderr, "port49 login: the broker at %s did not answer; your certificate is valid until %s; "+
				"try again when it answers\n", sf.broker, rfc3339(held.Leaf.NotAfter))
		} else {
			fmt.Fprintf(stderr, "port49 login: the broker at %s did not answer; try again when it answers\n", sf.broker)
		}
		return 1
	case refusedByCRL(err) != nil:
		// The held certificate would meet the same broker certificate in the
		// agent; going on would only fail one step later.
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	case usable && !sf.signIn && !errors.As(err, &refused):
		why := ""
		if down {
			why = ", until your identity provider answers (a certificate port49 issued needs no identity provider)"
		}
		fmt.Fprintf(stderr, "port49 login: %v; using your certificate for %s until %s%s\n", err, s.Principal,
			rfc3339(held.Leaf.NotAfter), why)
		return startIssued(sf, pair, true, stdout, stderr)
	case down:
		fmt.Fprintf(stderr, "port49 login: %v; port49 cannot sign you in until it answers (anyone already logged "+
			"in keeps working: a certificate port49 issued needs no identity provider)\n", err)
		if usable {
			fmt.Fprintf(stderr, "port49 login: your certificate for %s is valid until %s: `port49 login` without "+
				"--sign-in uses it\n", s.Principal, rfc3339(held.Leaf.NotAfter))
		}
	default:
		fmt.Fprintln(stderr, "port49 login:", err)
	}
	return code
}

// loginToIssuedHeldKey is loginToHeldKey for the issued pair (final review
// client I2): when the running agent holds pair's key, its key state is read
// first and the key is not opened here (spec decision 45 ruling 8), so a key
// that came back Locked is unlocked through the agent instead of the refresh
// answering "run `port49 login`" at every login. A file key has no state and
// is left to the ordinary path. done says the login is settled, with code.
func loginToIssuedHeldKey(ctx context.Context, sf *sessionFlags, pair issuedPair, stdout, stderr io.Writer) (code int,
	done bool) {
	if !hwkey.IsRef(pair.key) {
		return 0, false
	}
	c := agent.NewClient(sf.socket)
	st, err := c.Status(ctx)
	if err != nil || st.KeyState == "" || strings.TrimRight(sf.broker, "/") != st.Broker || st.KeyRef == "" ||
		st.KeyRef != clientkey.CanonicalRef(pair.key) {
		return 0, false
	}
	if sf.signIn {
		fmt.Fprintf(stderr, "port49 login: an agent already holds your session at %s on this key; `port49 refresh` "+
			"extends it; to sign in again, stop that agent first\n", st.Broker)
		return 1, true
	}
	code = loginThroughAgent(ctx, sf, c, st, refLabel(pair.key), stdout, stderr)
	if leaf, err := readLeaf(pair.cert); code == 0 && err == nil && api.LateRenewal(leaf, time.Now()) {
		fmt.Fprintf(stdout, "port49: your certificate ends at %s, and the agent with it; to renew before then, "+
			"stop the agent and run `port49 login`\n", rfc3339(leaf.NotAfter))
	}
	return code, true
}

// refusedError is the broker answering the certificate request 401
// credential_revoked: this person is revoked or logged out, and the held
// certificate, which the broker judges by the same mark, is not the way
// round it. Every other failure of a sign-in, a 401 for a stale or spent
// token included, leaves the held certificate as valid as it was.
type refusedError struct{ msg string }

func (e *refusedError) Error() string { return e.msg }

// brokerDownError is the broker not answering at all (a transport error, not
// an HTTP answer): not a problem with the sign-in, so not one a held
// certificate is started against or a new sign-in is the cure for.
type brokerDownError struct{ err error }

func (e *brokerDownError) Error() string { return e.err.Error() }
func (e *brokerDownError) Unwrap() error { return e.err }

// startIssued starts the agent on the issued certificate and its key, as
// --cert and --key would (ruling 7). A held one the agent could not connect
// with, still there, is said: the broker's clock may be past its end.
func startIssued(sf *sessionFlags, pair issuedPair, held bool, stdout, stderr io.Writer) int {
	sf.cert, sf.key = pair.cert, pair.key
	// A token's key wants its PIN, asked once here and handed to the agent on
	// a descriptor, as for a --key reference (unlockForAgent).
	if !unlockIssuedKey(sf, pair.key, stderr) {
		return 1
	}
	code, down := startAgentDown(sf, true, stdout, stderr)
	if _, err := os.Stat(pair.cert); code != 0 && held && !down && err == nil {
		fmt.Fprintln(stderr, "port49 login: if the broker refused your held certificate, `port49 login --sign-in` "+
			"signs you in again")
	}
	return code
}

// heldCertificate is the certificate a broker issued this user and its key,
// from certPath and keyRef (a path, or a tpm: or pkcs11: reference), with the
// sign-in it carries. A file not there is fs.ErrNotExist. A hardware key is
// opened, to check it is the certificate's, and let go again: no token is held
// while the agent starts. One that cannot be opened (the token is out) comes
// back with the certificate, which is still the held session's, and a
// *heldKeyError.
func heldCertificate(certPath, keyRef string) (tls.Certificate, issuer.SignIn, error) {
	paths := []string{certPath}
	if !hwkey.IsRef(keyRef) {
		paths = append(paths, keyRef)
	}
	for _, p := range paths {
		if _, err := os.Lstat(p); err != nil {
			return tls.Certificate{}, issuer.SignIn{}, err
		}
	}
	// A key file is refused if it is a symlink or readable by anyone but its
	// owner (keyfile; pre-flight F14).
	c, err := clientkey.LoadPair(certPath, keyRef, nil)
	if err != nil && hwkey.IsRef(keyRef) {
		// The key not opening is told from the certificate not being the key's:
		// only the first leaves the certificate the held session's.
		if k, oerr := clientkey.Open(keyRef, nil); oerr != nil {
			leaf, rerr := readLeaf(certPath)
			if rerr != nil {
				return tls.Certificate{}, issuer.SignIn{}, rerr
			}
			s, serr := issuer.ReadSignIn(leaf)
			if serr != nil {
				return tls.Certificate{}, issuer.SignIn{}, fmt.Errorf("%s is not a certificate port49 issued: %v", certPath, serr)
			}
			return tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}, s, &heldKeyError{ref: keyRef, err: oerr}
		} else {
			k.Close()
		}
	}
	if err != nil {
		return tls.Certificate{}, issuer.SignIn{}, err
	}
	if k, ok := c.PrivateKey.(hwkey.Key); ok {
		defer k.Close()
	}
	if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
		return tls.Certificate{}, issuer.SignIn{}, err
	}
	s, err := issuer.ReadSignIn(c.Leaf)
	if err != nil {
		return tls.Certificate{}, issuer.SignIn{}, fmt.Errorf("%s is not a certificate port49 issued: %v", certPath, err)
	}
	return c, s, nil
}

// writeIssuedPair keeps the issued key and certificate, a var so a test fails
// the write.
var writeIssuedPair = userconfig.WritePrivateAll

// issueCertificate signs in at the provider the broker lists and asks the
// broker for a certificate for a key made in the store chooseIssuedStore picks
// (decision 43 rulings 2, 3, 7 and 8; decision 45 ruling 7), and keeps the key
// and then the certificate. It returns the pair it kept. It prints nothing on
// failure but the store's one line: the error, with the exit code, is the
// caller's to say, since a held certificate may carry on past it.
func issueCertificate(ctx context.Context, sf *sessionFlags, pool *x509.CertPool,
	stdout, stderr io.Writer) (kept issuedPair, code int, err error) {
	verify, err := sf.verifyBroker(stderr)
	if err != nil {
		return issuedPair{}, 2, err
	}
	conf, err := fetchBrokerConfig(ctx, sf.broker, pool, verify)
	if err != nil {
		return issuedPair{}, 1, err
	}
	if conf.Issuance == nil {
		return issuedPair{}, 1, fmt.Errorf("the broker at %s issues no certificates (its broker.identity has no "+
			"issuance), so --oidc cannot log in there; log in with a certificate (--cert and --key)", sf.broker)
	}
	if conf.Issuance.Unavailable() {
		// Before the sign-in: a password and MFA for a certain 503 is the
		// 3am cost the config's word spares (ruling 18).
		return issuedPair{}, 1, errors.New("the broker cannot issue certificates now (its issuing CA is unavailable); " +
			"tell its operator")
	}
	prov, err := pickProvider(conf, sf.issuer)
	if err != nil {
		return issuedPair{}, 1, err
	}
	roots, err := sf.oidcRoots()
	if err != nil {
		return issuedPair{}, 2, err
	}
	p := oidcclient.Provider{Issuer: prov.Issuer, ClientID: prov.ClientID, Scopes: prov.Scopes, Roots: roots}
	failed := func(err error) (issuedPair, int, error) { return issuedPair{}, 1, err }
	// Before the provider is asked anything: a store that cannot be used
	// refuses here (decision 45 ruling 7).
	store, err := chooseIssuedStore(sf, stderr)
	if err != nil {
		return failed(err)
	}
	e, err := oidcclient.Discover(ctx, p)
	if err != nil {
		return failed(err)
	}
	// The key is opened or made before the browser: an issued_key naming no
	// key, or a TPM that will not make one, costs no password.
	target, keyFile, err := issuedTarget(store, sf)
	if err != nil {
		return failed(err)
	}
	key, keyBytes, err := newIssuedKey(store, sf, keyFile)
	var refused *tpmRefused
	switch {
	case errors.As(err, &refused) && cmp.Or(sf.issuedKeyStore, storeAuto) == storeAuto:
		// `auto` goes where a key can be made: a TPM that is gone or will
		// not make one (an owner password on its hierarchy) must not stop
		// every login. Any other failure is an error. This is the one line.
		if target, keyFile, err = issuedTarget(storeFile, sf); err != nil {
			return failed(err)
		}
		store = storeFile
		fmt.Fprintf(stderr, "port49 login: %sthe TPM could not make a key (%v); the key is a file (%s)\n",
			ignoredClause(sf), unprefixed(refused.err), keyFile)
		key, keyBytes, err = newIssuedKey(store, sf, keyFile)
	case errors.As(err, &refused):
		return failed(fmt.Errorf("issued_key_store is tpm, and the TPM could not make a key (%v): %s",
			unprefixed(refused.err), tpmRefusalAdvice(refused.err)))
	case err == nil && store == storeTPM && cmp.Or(sf.issuedKeyStore, storeAuto) == storeAuto:
		// Said once the key is made, so it is never contradicted by a second line.
		fmt.Fprintf(stderr, "port49 login: %sthe key is made in this machine's TPM\n", ignoredClause(sf))
	}
	if err != nil {
		return failed(err)
	}
	// The agent opens its own session on a token; this process lets go of its
	// own before the agent starts, whichever way the sign-in ends.
	if k, ok := key.(hwkey.Key); ok {
		defer k.Close()
		if store == storePKCS && !unlockForAgent(sf, k, stderr) {
			return issuedPair{}, 1, saidError{}
		}
	}
	nonce, err := api.IssuanceNonce(key.Public())
	if err != nil {
		return failed(err)
	}
	tokens, err := signIn(ctx, p, e, nonce, "", sf.redirectPort, sf.noBrowser, stderr)
	if err != nil {
		return failed(err)
	}
	warnSkew(stderr, "port49 login", tokens)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return failed(err)
	}
	resp, err := requestCertificate(ctx, sf.broker, pool, tokens.IDRaw, csr, verify)
	if err != nil {
		return failed(err)
	}
	blk, _ := pem.Decode([]byte(resp.Certificate))
	var leaf *x509.Certificate
	if blk != nil {
		leaf, err = x509.ParseCertificate(blk.Bytes)
	}
	same, _ := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if blk == nil || err != nil || same == nil || !same.Equal(leaf.PublicKey) {
		return failed(errors.New("the broker's answer is not a certificate for the key this login sent"))
	}
	// Said from the certificate just checked, not from the broker's JSON.
	// Every check is made before a file is touched: a held pair is only
	// ever replaced by one that will load.
	si, err := issuer.ReadSignIn(leaf)
	if err != nil {
		return failed(fmt.Errorf("the broker's certificate carries no sign-in: %v", err))
	}
	// Both are staged before either is renamed, the key first and the
	// certificate last: a failure to write leaves the held pair as it was,
	// and the one that reads the pair never sees a new key beside an old
	// certificate except across the last rename. A token's key is no file:
	// port49 writes the certificate alone and nothing to the token.
	files := []userconfig.PrivateFile{{Path: target.cert, Data: []byte(resp.Certificate),
		What: "port49-issued certificate"}}
	if keyBytes != nil {
		raw, err := keyBytes()
		if err != nil {
			return failed(err)
		}
		files = append([]userconfig.PrivateFile{{Path: keyFile, Data: raw, What: "port49-issued key"}}, files...)
	}
	if err := writeIssuedPair(files...); err != nil {
		return failed(err)
	}
	// The unnamed .key is never removed here, whatever the store: on a home
	// shared with a file host it is that host's (decision 45 ruling 7), and
	// pickHeldPair looks for this machine's own pair before it.
	fmt.Fprintf(stdout, "port49: signed in at %s as %s; your certificate from %s is valid until %s\n", p.Issuer,
		si.Principal, sf.broker, rfc3339(leaf.NotAfter))
	return target, 0, nil
}

// requestCertificate is POST /v1/certificate, the sign-in's ID token the
// bearer, over TLS 1.3 to the broker's CA alone and never through a proxy.
// The token is in a header, never a URL, and is not kept.
func requestCertificate(ctx context.Context, broker string, pool *x509.CertPool, idToken string,
	csr []byte, verify func(tls.ConnectionState) error) (api.IssueResponse, error) {
	body, err := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(csr)})
	if err != nil {
		return api.IssueResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(broker, "/")+"/v1/certificate",
		bytes.NewReader(body))
	if err != nil {
		return api.IssueResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")
	// No redirect is followed: the ID token and the CSR go to the broker
	// named and nowhere else (final review client I4).
	c := &http.Client{CheckRedirect: mfatouch.NoRedirect, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, VerifyConnection: verify}}}
	resp, err := c.Do(req)
	if err != nil {
		if refused := refusedByCRL(err); refused != nil {
			return api.IssueResponse{}, refused
		}
		return api.IssueResponse{}, &brokerDownError{fmt.Errorf("the broker at %s is unreachable: %w", broker, err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return api.IssueResponse{}, &brokerDownError{fmt.Errorf("the broker at %s: %w", broker, err)}
	}
	if err := agent.Redirected(resp); err != nil {
		return api.IssueResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		_ = json.Unmarshal(raw, &e)
		msg := fmt.Sprintf("the broker did not issue your certificate: %s (%s)",
			printsafe.Line(e.Detail, 400), printsafe.Line(cmp.Or(e.Error, resp.Status), 64))
		if resp.StatusCode == http.StatusUnauthorized && e.Error == string(decision.CredentialRevoked) {
			return api.IssueResponse{}, &refusedError{msg}
		}
		return api.IssueResponse{}, errors.New(msg)
	}
	var out api.IssueResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return api.IssueResponse{}, fmt.Errorf("the broker's answer to the certificate request: %w", err)
	}
	return out, nil
}

// The sign-in's browser and terminal, vars so a test drives them.
var (
	// openBrowser opens a URL in this host's browser (launchBrowser).
	openBrowser = launchBrowser
	// stdinIsTerminal is whether a pasted address can be read.
	stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	// readPaste reads one pasted address with echo off.
	readPaste = func() (string, error) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		return strings.TrimSpace(string(b)), err
	}
)

// signIn runs one sign-in in this process (rulings 3–5): a browser when
// this host has one, the address on stderr always, and on a terminal a
// pasted address, not echoed. The terminal is restored when the sign-in
// ends, and when a signal ends the process while the paste prompt has echo
// off (guardedPaste): Ctrl-C there must not leave the operator's shell
// typing blind.
func signIn(ctx context.Context, p oidcclient.Provider, e oidcclient.Endpoints, nonce, acr string, port int,
	noBrowser bool, stderr io.Writer) (oidcclient.Tokens, error) {
	o := oidcclient.LoginOptions{Nonce: nonce, ACRValues: acr, Port: port, Out: stderr, Now: time.Now}
	if !noBrowser {
		o.Browser = openBrowser
	}
	if stdinIsTerminal() {
		fd := int(os.Stdin.Fd())
		restore := func() {}
		if saved, err := term.GetState(fd); err == nil {
			restore = func() { _ = term.Restore(fd, saved) }
			defer restore()
		}
		o.Paste = func() (string, error) {
			return guardedPaste(readPaste, restore, os.Exit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		}
	}
	t, err := oidcclient.Login(ctx, p, e, o)
	if errors.Is(err, oidcclient.ErrNoWayBack) {
		return t, fmt.Errorf("%w; run the command in a terminal (ssh -t), or log in with --redirect-port N and "+
			"forward that port to this host (ssh -L N:127.0.0.1:N)", err)
	}
	return t, err
}

// guardedPaste is read with sigs caught: a signal that arrives while read
// holds the terminal with echo off restores it first, then ends the process
// as the signal would (exit 128+signal, 130 for SIGINT). Catching stops when
// read returns. When the browser wins, read does not return: it stays in
// ReadPassword, so the signals stay caught for the rest of the login, and one
// still restores the terminal and exits as above.
func guardedPaste(read func() (string, error), restore func(), exit func(int), sigs ...os.Signal) (string, error) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	defer func() {
		signal.Stop(ch)
		close(done)
	}()
	go func() {
		select {
		case s := <-ch:
			restore()
			code := 1
			if n, ok := s.(syscall.Signal); ok {
				code = 128 + int(n)
			}
			exit(code)
		case <-done:
		}
	}()
	return read()
}

// browserCommand is the command that opens url here, or nil for none (ruling
// 5): $BROWSER when set; on Linux and the BSDs xdg-open, only with a display,
// since on a remote shell it falls back to a text browser on the operator's
// own terminal; on macOS open, outside an SSH session.
func browserCommand(goos string, env func(string) string, url string) []string {
	if b := env("BROWSER"); b != "" {
		return []string{b, url}
	}
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd":
		if env("DISPLAY") != "" || env("WAYLAND_DISPLAY") != "" {
			return []string{"xdg-open", url}
		}
	case "darwin":
		if env("SSH_CONNECTION") == "" && env("SSH_TTY") == "" {
			return []string{"open", url}
		}
	}
	return nil
}

// launchBrowser runs browserCommand detached, with no terminal: a browser
// that falls back to text must not take the operator's.
func launchBrowser(url string) error {
	argv := browserCommand(runtime.GOOS, os.Getenv, url)
	if argv == nil {
		return errors.New("no browser on this host")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// pickProvider is the provider a login signs in at (ruling 2): the one the
// broker lists, or the one issuer names exactly.
func pickProvider(c api.Config, issuer string) (api.OIDCProvider, error) {
	var listed []string
	for _, p := range c.OIDC {
		listed = append(listed, p.Issuer)
	}
	switch {
	case len(c.OIDC) == 0:
		return api.OIDCProvider{}, fmt.Errorf("the broker takes no OIDC login: it lists no identity provider "+
			"(its methods: %s)", strings.Join(c.Methods, ", "))
	case issuer != "":
		for _, p := range c.OIDC {
			if p.Issuer == issuer {
				return p, nil
			}
		}
		return api.OIDCProvider{}, fmt.Errorf("the broker does not list %s; it lists %s", issuer, strings.Join(listed, ", "))
	case len(c.OIDC) > 1:
		return api.OIDCProvider{}, fmt.Errorf("the broker lists %d identity providers (%s); name one with --issuer or "+
			"oidc_issuer", len(c.OIDC), strings.Join(listed, ", "))
	}
	return c.OIDC[0], nil
}

// refusedByCRL is err's broker CRL refusal (a revoked broker certificate, or
// one that could not be checked under broker_crl: require), or nil. It is the
// broker's certificate being refused, not the broker being down: a login must
// not treat it as an outage.
func refusedByCRL(err error) error {
	var revoked *brokercrl.RevokedError
	var unchecked *brokercrl.UncheckedError
	switch {
	case errors.As(err, &revoked):
		return revoked
	case errors.As(err, &unchecked):
		return unchecked
	}
	return nil
}

// fetchBrokerConfig is the broker's GET /v1/config, which needs no
// credential (design §17), over TLS 1.3 to the broker's CA alone and never
// through a proxy: the broker is the operator's own.
func fetchBrokerConfig(ctx context.Context, broker string, pool *x509.CertPool,
	verify func(tls.ConnectionState) error) (api.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := &http.Client{CheckRedirect: mfatouch.NoRedirect, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, VerifyConnection: verify}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(broker, "/")+"/v1/config", nil)
	if err != nil {
		return api.Config{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		if refused := refusedByCRL(err); refused != nil {
			return api.Config{}, refused
		}
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			return api.Config{}, fmt.Errorf("the broker's certificate at %s does not verify (%v); check that the broker "+
				"CA (--broker-ca) is the CA that issued it%s", broker, cv.Err, agent.RotatedCA(cv.Err, bundleKept(broker)))
		}
		return api.Config{}, &brokerDownError{fmt.Errorf("the broker at %s is unreachable: %w", broker, err)}
	}
	defer resp.Body.Close()
	if err := agent.Redirected(resp); err != nil {
		return api.Config{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return api.Config{}, fmt.Errorf("%s/v1/config answered %s", broker, resp.Status)
	}
	var conf api.Config
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&conf); err != nil {
		return api.Config{}, fmt.Errorf("%s/v1/config: %w", broker, err)
	}
	return conf, nil
}

// warnSkew says when this host's clock is more than 5 minutes from the
// provider's (ruling 6): never a refusal, since the broker judges every
// token by its own clock.
func warnSkew(stderr io.Writer, what string, t oidcclient.Tokens) {
	skew, dir := oidcclient.Skew(t), "ahead of"
	if skew < 0 {
		skew, dir = -skew, "behind"
	}
	if skew <= 5*time.Minute {
		return
	}
	fmt.Fprintf(stderr, "%s: this host's clock is %s %s your identity provider's; the broker judges every token by "+
		"its own clock, so set this host's clock if the broker refuses yours\n", what, skew.Round(time.Second), dir)
}

// oidcRoots is the provider's TLS anchor (ruling 19): the config file's
// oidc_ca, read through its walk; --oidc-ca's file; or nil, the system's
// roots.
func (s *sessionFlags) oidcRoots() (*x509.CertPool, error) {
	caPEM := s.oidcCAPEM
	if caPEM == nil && s.oidcCA != "" {
		var err error
		if caPEM, err = os.ReadFile(s.oidcCA); err != nil {
			return nil, err
		}
	}
	if caPEM == nil {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no PEM certificate", s.oidcCA)
	}
	return pool, nil
}
