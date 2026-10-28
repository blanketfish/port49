//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/totp"
	"github.com/rhwendt/port49/internal/userconfig"
)

// The directory sign-in's 3am cases, end to end: the real port49 CLI against
// the lab broker (a real broker behind its own Listener, as port49d serves
// it), the directory a fake, the enrollment store a sealed file, and the
// operator's commands the real `port49 directory ...` over the broker API.
// The passwords and keys are fixed fakes, and the codes are computed from
// them; a failure names the case and never the value.

const (
	labDirName      = "alice"
	labDirPassword  = "lab-directory-password " // ends in a space, as a password may
	labDirPrincipal = "user:alice@example.com"
	labDirEntry     = "uuid:alice"
)

// labSecret is the second factor alice is enrolled with when a test does not
// enroll her through the CLI: 20 bytes, as totp.NewSecret makes.
var labSecret = []byte("lab-totp-secret-0001")

// dirLab is a lab broker taking a directory password. Alice is in its
// directory, a new entry (so enrollment is open to her), and the enrollment
// store does not exist until a test creates it.
type dirLab struct {
	*labBroker
	logs  *lockedBuffer // the broker's decision log
	lines *lockedBuffer // the broker's own lines (the standard logger's)

	mu    sync.Mutex
	paths []string // each request the broker served, "METHOD path"
}

func newDirectoryLab(t *testing.T) *dirLab {
	t.Helper()
	dir := &fakeSignInDirectory{people: map[string]fakeDirectoryPerson{labDirName: {password: labDirPassword,
		entry: directory.SignInEntry{
			Identity: directory.Identity{DN: "uid=alice,ou=Staff,dc=example,dc=com", EntryID: labDirEntry,
				Principal: labDirPrincipal, Username: "alice"},
			Server:    directory.Server{URI: "ldaps://dc-01.example.com"},
			CreatedAt: time.Now().Add(-time.Hour)}}}}
	d := &dirLab{logs: &lockedBuffer{}, lines: &lockedBuffer{}}
	// The broker says its enrollment store is lost as it is wired, so the
	// standard logger is the lab's before the broker is.
	prev := log.Writer()
	log.SetOutput(d.lines)
	t.Cleanup(func() { log.SetOutput(prev) })
	d.labBroker = newLabBrokerOpts(t, labOpts{maxAge: 12 * time.Hour, signIn: dir, logs: d.logs,
		spy: func(r *http.Request) {
			d.mu.Lock()
			d.paths = append(d.paths, r.Method+" "+r.URL.Path)
			d.mu.Unlock()
		}})
	return d
}

// served is how many requests of method to path the broker has served.
func (d *dirLab) served(method, path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, p := range d.paths {
		if p == method+" "+path {
			n++
		}
	}
	return n
}

// operator is what the broker's operator does on the broker host or through
// an agent with a touch key (spec §5.1.6): the broker's own operation, called
// directly. The CLI's half is admin_test.go's and directory_linux_test.go's.
func (d *dirLab) operator(t *testing.T, args ...string) (code int, out, errb string) {
	t.Helper()
	ctx := context.Background()
	var text string
	var err error
	switch args[0] {
	case "init-enrollments":
		text, err = d.b.InitEnrollments(ctx, "test")
	case "unlock":
		text, err = d.b.UnlockSignIn(ctx, args[1], "test")
	case "reset-second-factor":
		if args[1] == "--all" {
			text, err = d.b.ResetSecondFactor(ctx, "", true, "test")
		} else {
			text, err = d.b.ResetSecondFactor(ctx, args[1], false, "test")
		}
	default:
		t.Fatalf("operator: %v", args)
	}
	if err != nil {
		return 1, "", err.Error()
	}
	return 0, text + "\n", ""
}

// initEnrollments is `port49 directory init-enrollments`, which must succeed.
func (d *dirLab) initEnrollments(t *testing.T) {
	t.Helper()
	if code, out, errb := d.operator(t, "init-enrollments"); code != 0 ||
		!strings.Contains(out, "created the enrollment store; password sign-in is on") {
		t.Fatalf("init-enrollments: code %d stdout %q stderr %q", code, out, errb)
	}
}

// enrolled creates the enrollment store and enrolls alice in it under
// labSecret, as an earlier enrollment through the CLI would have.
func (d *dirLab) enrolled(t *testing.T) {
	t.Helper()
	d.initEnrollments(t)
	err := d.b.Enrollments.SwapSecondFactor(context.Background(), store.SecondFactor{Principal: labDirPrincipal,
		State: store.SecondFactorActive, EntryID: labDirEntry, Secret: labSecret, EnrolledAt: d.now(),
		EnrolledFrom: "192.0.2.1/32"}, 0)
	if err != nil {
		t.Fatal(err)
	}
}

// nextCode is the code secret shows at the broker's time, with alice's last
// taken step forgotten, so a second login in the same 30 seconds is not a
// replay of the first (the broker's tests hold replay).
func (d *dirLab) nextCode(t *testing.T, secret []byte) string {
	t.Helper()
	ctx := context.Background()
	f, err := d.b.Enrollments.GetSecondFactor(ctx, labDirPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	f.LastStep = 0
	if err := d.b.Enrollments.SwapSecondFactor(ctx, f, f.Rev); err != nil {
		t.Fatal(err)
	}
	return codeAt(t, secret, d.now())
}

// base32NoPad is secret as an authenticator is typed it (RFC 4648, upper case).
func base32NoPad(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func codeAt(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	c, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// setCreated is when the directory says alice's entry was created.
func (d *dirLab) setCreated(t *testing.T, at time.Time) {
	t.Helper()
	d.signIn.mu.Lock()
	defer d.signIn.mu.Unlock()
	p := d.signIn.people[labDirName]
	p.entry.CreatedAt = at
	d.signIn.people[labDirName] = p
}

// prompter answers a prompt of the login, given what the login has printed so
// far.
type prompter func(prompt, screen string) string

// driveLogin makes the prompts a script: the name line answers name, and each
// secret is answered by answer. A terminal on both ends.
func driveLogin(t *testing.T, name string, screen func() string, answer prompter) *[]string {
	t.Helper()
	savedLine, savedSecret, savedIn, savedOut := readLine, readSecret, loginStdinIsTerminal, stdoutIsTerminal
	t.Cleanup(func() {
		readLine, readSecret, loginStdinIsTerminal, stdoutIsTerminal = savedLine, savedSecret, savedIn, savedOut
	})
	var asked []string
	loginStdinIsTerminal = func() bool { return true }
	stdoutIsTerminal = func() bool { return true }
	readLine = func(prompt string, _ io.Writer) (string, error) {
		asked = append(asked, prompt)
		return name, nil
	}
	readSecret = func(prompt string, _ io.Writer) (string, error) {
		asked = append(asked, prompt)
		return answer(prompt, screen()), nil
	}
	return &asked
}

const (
	passwordPrompt  = "password: "
	codePrompt      = "code from your authenticator"
	firstCodePrompt = "first code from your authenticator: "
)

// signingIn answers a login by a person who is enrolled: the password, then
// the code. Any other prompt fails the test: no enrollment was expected.
func signingIn(t *testing.T, password, code string) prompter {
	return func(prompt, _ string) string {
		switch {
		case prompt == passwordPrompt:
			return password
		case strings.HasPrefix(prompt, codePrompt):
			return code
		}
		t.Fatalf("a prompt nobody expected: %q", prompt)
		return ""
	}
}

// refusingAnyPrompt answers none: the login must not ask.
func refusingAnyPrompt(t *testing.T) prompter {
	return func(prompt, _ string) string {
		t.Fatalf("the login asked %q, and should have asked nothing", prompt)
		return ""
	}
}

// enrollingBy answers a login by a person with no second factor: the
// password, no code, and, for each first code asked, first(secret, try) with
// the secret the screen showed and the try's number from 1.
func enrollingBy(t *testing.T, password string, first func(secret []byte, try int) string) prompter {
	tries := 0
	return func(prompt, screen string) string {
		switch {
		case prompt == passwordPrompt:
			return password
		case strings.HasPrefix(prompt, codePrompt):
			return ""
		case prompt == firstCodePrompt:
			tries++
			return first(screenSecret(t, screen), tries)
		}
		t.Fatalf("a prompt nobody expected: %q", prompt)
		return ""
	}
}

// screenSecret is the key the enrollment showed on the terminal, as a person
// types it into an authenticator.
func screenSecret(t *testing.T, screen string) []byte {
	t.Helper()
	for _, line := range strings.Split(screen, "\n") {
		if rest, ok := strings.CutPrefix(line, "key: "); ok {
			secret, err := totp.DecodeSecret(strings.Join(strings.Fields(rest), ""))
			if err != nil {
				t.Fatal("the enrollment's key on the screen is not base32")
			}
			return secret
		}
	}
	t.Fatal("the enrollment showed no key")
	return nil
}

// loginResult is what one `port49 login --directory` did. out is stdout with
// the enrollment's QR code and key taken out, so a failure message never
// prints a secret; screen is the whole of it.
type loginResult struct {
	code     int
	out, err string
	screen   string
	asked    []string
}

// scrubEnrollment is s without the QR code and key an enrollment shows: the
// lines between its header and its "confirm by" line.
func scrubEnrollment(s string) string {
	const header = "Enroll your second factor"
	i := strings.Index(s, header)
	if i < 0 {
		return s
	}
	headerEnd := strings.IndexByte(s[i:], '\n')
	confirm := strings.Index(s[i:], "confirm by ")
	if headerEnd < 0 || confirm < 0 {
		return s[:i+len(header)] + " [the rest is not shown]"
	}
	end := strings.IndexByte(s[i+confirm:], '\n')
	if end < 0 {
		end = len(s) - i - confirm - 1
	}
	return s[:i+headerEnd+1] + "[the QR code and key]\n" + s[i+confirm+end+1:]
}

// dirFlags is `port49 login --directory` for the lab.
func (d *dirLab) dirFlags(sock string, extra ...string) []string {
	return append([]string{"login", "--directory", "--broker", d.url, "--broker-ca", filepath.Join(d.dir, testpki.LabCA),
		"--socket", sock}, extra...)
}

// login runs `port49 login --directory` on sock, the person typing what
// answer says. An agent it starts is stopped at the test's end.
func (d *dirLab) login(t *testing.T, sock string, answer prompter, extra ...string) loginResult {
	t.Helper()
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var so, se bytes.Buffer
	asked := driveLogin(t, labDirName, so.String, answer)
	code := run(d.dirFlags(sock, extra...), &so, &se)
	return loginResult{code: code, out: scrubEnrollment(so.String()), err: se.String(), screen: so.String(), asked: *asked}
}

// mints runs `port49 token leaf1` against the agent on sock, which must mint.
func mints(t *testing.T, sock string) {
	t.Helper()
	var tok, terr bytes.Buffer
	if code := run([]string{"token", "--socket", sock, "leaf1"}, &tok, &terr); code != 0 || strings.TrimSpace(tok.String()) == "" {
		t.Fatalf("token: code %d stderr %q", code, terr.String())
	}
}

func noAgent(t *testing.T, sock string) {
	t.Helper()
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("an agent was started")
	}
}

// heldPaths is where the login keeps this broker's certificate and key.
func (d *dirLab) heldPaths(t *testing.T) (string, string) {
	t.Helper()
	c, k, err := userconfig.IssuedPaths(d.url)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// holdCertificate writes a certificate the broker issued alice at at, for
// lifetime, and its key, where the login keeps them.
func (d *dirLab) holdCertificate(t *testing.T, at time.Time, lifetime time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.b.Issuer.Issue(key.Public(), issuer.SignIn{Method: issuer.MethodDirectoryPassword,
		Principal: labDirPrincipal, Subject: issuer.EntrySubject(labDirEntry), AMR: []string{"pwd", "otp"},
		AuthTime: at, IssuedAt: at}, at, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := d.heldPaths(t)
	if err := userconfig.WritePrivate(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"test key"); err != nil {
		t.Fatal(err)
	}
	if err := userconfig.WritePrivate(certPath, d.b.Issuer.PEM(c), "test certificate"); err != nil {
		t.Fatal(err)
	}
}

// spray is n sign-ins for alice's name from someone who has not her code or
// password, straight to the broker.
func (d *dirLab) spray(t *testing.T, n int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(d.dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	body, err := json.Marshal(api.SignInRequest{Name: labDirName, Password: "not-the-password", Code: "123456",
		CSR: base64.RawURLEncoding.EncodeToString(csr)})
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		status, _, _, err := postJSON(context.Background(), d.url, "/v1/sign-in", pool, nil, body)
		if err != nil || status != http.StatusUnauthorized && status != http.StatusTooManyRequests {
			t.Fatalf("a spray sign-in: status %d, %v", status, err)
		}
	}
}

// nowhere fails if any of secrets is in text. A code is looked for as a
// number on its own, so a time stamp that holds six of its digits is not one.
func nowhere(t *testing.T, where, text string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.TrimSpace(s) == "" {
			continue
		}
		found := strings.Contains(text, strings.TrimSpace(s))
		if len(s) == totp.Digits && strings.Trim(s, "0123456789") == "" {
			found = regexp.MustCompile(`(^|[^0-9])` + s + `([^0-9]|$)`).MatchString(text)
		}
		if found {
			t.Fatalf("a password, a code, a key or an enrollment address reached %s", where)
		}
	}
}

// A first login enrolls (QR, first code), gets a certificate, starts the
// agent, and `port49 token` mints; no password, code, secret or URI reaches
// the terminal's non-prompt output or the agent's log. The key is shown once,
// on the enrollment's screen, in the groups of four a person types it in by:
// that is the one place it is, and the QR code beside it.
func TestLoginDirectoryEnrollsIssuesAndMints(t *testing.T) {
	d := newDirectoryLab(t)
	d.initEnrollments(t)
	sock := privateSocket(t)
	var secret []byte
	var typed string
	r := d.login(t, sock, enrollingBy(t, labDirPassword, func(s []byte, _ int) string {
		secret, typed = s, codeAt(t, s, d.now())
		return typed
	}))
	if r.code != 0 {
		t.Fatalf("code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	// (a) The lines a login says after a real broker issues the certificate.
	for _, want := range []string{
		"Enroll your second factor: scan this with your authenticator app, or type the key",
		"key: " + groupsOfFour(base32NoPad(secret)),
		"port49: signed in with your directory password as " + labDirPrincipal + "; your certificate from " + d.url +
			" is valid until ",
		"port49: logged in to " + d.url,
		"\nrefreshed at ", "  leaf1 (alice)  extended to ",
	} {
		if !strings.Contains(r.screen, want) {
			t.Errorf("stdout lacks %q: %q", want, r.out)
		}
	}
	if !strings.ContainsAny(r.screen, "█▀▄") {
		t.Error("the enrollment drew no QR code")
	}
	if len(r.asked) != 4 || !strings.HasPrefix(r.asked[0], "directory name [") || r.asked[1] != passwordPrompt ||
		!strings.HasPrefix(r.asked[2], codePrompt) || r.asked[3] != firstCodePrompt {
		t.Errorf("the prompts: %q", r.asked)
	}
	certPath, keyPath := d.heldPaths(t)
	held, s, err := heldCertificate(certPath, keyPath)
	if err != nil || s.Method != issuer.MethodDirectoryPassword || s.Principal != labDirPrincipal || held.Leaf == nil {
		t.Fatalf("the held certificate: %+v %v", s, err)
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
	uri := "otpauth://"
	compact := base32NoPad(secret)
	for where, text := range map[string]string{"the terminal": r.screen + r.err, "the token command": tok.String() + terr.String(),
		"the agent's log": agentLog(sock), "the broker's log": d.logs.String(), "the broker's lines": d.lines.String()} {
		nowhere(t, where, text, labDirPassword, typed, uri)
		if where != "the terminal" {
			nowhere(t, where, text, compact, groupsOfFour(compact))
		}
	}
	// On the terminal the key is only in its groups, beside the QR code: on
	// stdout, exactly once, and never on stderr.
	nowhere(t, "the terminal as one word", r.screen+r.err, compact)
	nowhere(t, "stderr", r.err, groupsOfFour(compact))
	if n := strings.Count(r.screen, groupsOfFour(compact)); n != 1 {
		t.Errorf("the key is shown %d times on stdout, want exactly once", n)
	}
	// The enrollment is on the record, and the factor works: the next login with
	// its code signs in.
	if !strings.Contains(d.logs.String(), `"reason":"second_factor_enrolled"`) {
		t.Error("the broker recorded no enrollment")
	}
	stopAgentAt(sock)
	again := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, secret)), "--sign-in")
	if again.code != 0 || !strings.Contains(again.out, "port49: signed in with your directory password as "+labDirPrincipal) {
		t.Fatalf("a login with the enrolled factor: code %d stdout %q stderr %q", again.code, again.out, again.err)
	}
}

// Owner's ruling 4, the 3am case: the directory down. A person holding a
// certificate logs in on it and mints; a person with none is told the
// directory did not answer and that anyone signed in keeps working; exit 1,
// no agent.
func TestTheDirectoryDownAtThreeAM(t *testing.T) {
	t.Run("a holder with a fresh certificate", func(t *testing.T) {
		d := newDirectoryLab(t)
		d.enrolled(t)
		sock := privateSocket(t)
		first := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret)))
		if first.code != 0 {
			t.Fatalf("the first login: code %d stderr %q", first.code, first.err)
		}
		stopAgentAt(sock)
		d.signIn.setDown(true)
		r := d.login(t, sock, refusingAnyPrompt(t))
		if r.code != 0 || len(r.asked) != 0 || !strings.Contains(r.out, "port49: using your certificate for "+labDirPrincipal+
			" (signed in with your directory password at ") || !strings.Contains(r.out, "port49: logged in to "+d.url) {
			t.Fatalf("code %d stdout %q stderr %q", r.code, r.out, r.err)
		}
		mints(t, sock)
	})

	t.Run("a holder whose certificate is nearly over", func(t *testing.T) {
		d := newDirectoryLab(t)
		d.enrolled(t)
		d.holdCertificate(t, time.Now().Add(-11*time.Hour), 12*time.Hour)
		d.signIn.setDown(true)
		sock := privateSocket(t)
		r := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret)))
		if r.code != 0 || !strings.Contains(r.err, "the directory did not answer, so no one can sign in with a password now") ||
			!strings.Contains(r.err, "; using your certificate for "+labDirPrincipal+" until ") ||
			!strings.Contains(r.out, "port49: logged in to "+d.url) {
			t.Fatalf("code %d stdout %q stderr %q", r.code, r.out, r.err)
		}
		mints(t, sock)
	})

	t.Run("a person with none", func(t *testing.T) {
		d := newDirectoryLab(t)
		d.enrolled(t)
		d.signIn.setDown(true)
		sock := privateSocket(t)
		code := d.nextCode(t, labSecret)
		r := d.login(t, sock, signingIn(t, labDirPassword, code))
		if r.code != 1 || r.out != "" ||
			!strings.Contains(r.err, "the directory did not answer, so no one can sign in with a password now; anyone "+
				"already signed in keeps working until their certificate ends (directory_unavailable)") {
			t.Fatalf("code %d stdout %q stderr %q", r.code, r.out, r.err)
		}
		noAgent(t, sock)
		certPath, _ := d.heldPaths(t)
		if _, err := os.Stat(certPath); err == nil {
			t.Fatal("a certificate was kept")
		}
		// The outage spent nothing of the person: the same code, the moment the
		// directory answers, signs them in.
		d.signIn.setDown(false)
		r = d.login(t, sock, signingIn(t, labDirPassword, code))
		if r.code != 0 || !strings.Contains(r.out, "port49: signed in with your directory password as "+labDirPrincipal) {
			t.Fatalf("after the outage: code %d stdout %q stderr %q", r.code, r.out, r.err)
		}
		mints(t, sock)
	})
}

// A phone's clock off by two minutes: refused, saying the clock is about 2
// minutes off; with it fixed, the next login is issued.
func TestAClockOffAtThreeAM(t *testing.T) {
	d := newDirectoryLab(t)
	d.enrolled(t)
	sock := privateSocket(t)
	// Codes in a step of their own, so a step boundary between the phone and the
	// broker moves them by one step and the minutes stay two. The step is taken
	// afresh for each case, so a slow run cannot carry the first over two.
	for _, c := range []struct {
		label string
		steps time.Duration
		words string
	}{
		{"ahead", 4 * totp.Period, "(ahead of the broker's)"},
		{"behind", -3 * totp.Period, "(behind the broker's)"},
	} {
		at := d.now().Truncate(totp.Period).Add(c.steps + time.Second)
		r := d.login(t, sock, signingIn(t, labDirPassword, codeAt(t, labSecret, at)))
		if r.code != 1 || r.out != "" || !strings.Contains(r.err, "your authenticator's clock is about 2 minutes off "+c.words+
			": set it to the network time and run `port49 login` again (sign_in_refused)") {
			t.Fatalf("%s: code %d stdout %q stderr %q", c.label, r.code, r.out, r.err)
		}
		noAgent(t, sock)
	}
	r := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret)))
	if r.code != 0 || !strings.Contains(r.out, "port49: signed in with your directory password as "+labDirPrincipal) {
		t.Fatalf("with the clock fixed: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	mints(t, sock)
}

// Locked out by a spray of the person's name: their login says the time and
// `port49 directory unlock`; their held certificate keeps them working; the
// operator's unlock lets the next login through. The 429 names the account by
// the name the person typed, not "this account" (the broker never names it).
func TestLockedOutAtThreeAM(t *testing.T) {
	d := newDirectoryLab(t)
	d.enrolled(t)
	sock := privateSocket(t)
	if r := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret))); r.code != 0 {
		t.Fatalf("the first login: code %d stderr %q", r.code, r.err)
	}
	stopAgentAt(sock)
	d.spray(t, 6) // 5 failures a principal are allowed in the window

	r := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret)), "--sign-in")
	if r.code != 1 || r.out != "" {
		t.Fatalf("a sign-in while locked out: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	// (c) The typed name replaces "this account", in the one place it stood.
	if !regexp.MustCompile(`too many failed sign-ins for alice; try again after \d{4}-\d\d-\d\dT[0-9:]+Z, or an operator can `+
		"clear it with `port49 directory unlock` for your account \\(retry in [0-9hms]+\\) \\(sign_in_throttled\\)").MatchString(r.err) ||
		strings.Contains(r.err, "this account") {
		t.Fatalf("the lock-out as said: %q", r.err)
	}
	noAgent(t, sock)

	// The certificate they hold keeps them working, locked out or not.
	held := d.login(t, sock, refusingAnyPrompt(t))
	if held.code != 0 || !strings.Contains(held.out, "port49: using your certificate for "+labDirPrincipal) {
		t.Fatalf("the held certificate: code %d stdout %q stderr %q", held.code, held.out, held.err)
	}
	mints(t, sock)
	stopAgentAt(sock)

	if code, out, errb := d.operator(t, "unlock", labDirPrincipal); code != 0 ||
		!strings.Contains(out, "cleared ") || !strings.Contains(out, " failed sign-ins for "+labDirPrincipal) {
		t.Fatalf("unlock: code %d stdout %q stderr %q", code, out, errb)
	}
	r = d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret)), "--sign-in")
	if r.code != 0 || !strings.Contains(r.out, "port49: signed in with your directory password as "+labDirPrincipal) {
		t.Fatalf("after the unlock: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	mints(t, sock)
}

// A lost phone: reset-second-factor, then the login enrolls again; the old
// factor is no way in.
func TestALostPhoneAtThreeAM(t *testing.T) {
	d := newDirectoryLab(t)
	d.enrolled(t)
	d.setCreated(t, d.now().Add(-365*24*time.Hour)) // no new-entry window: only the reset opens enrollment
	sock := privateSocket(t)

	// With no phone there is no code, and nothing else gets in.
	r := d.login(t, sock, signingIn(t, labDirPassword, "abcdef"))
	if r.code != 1 || !strings.Contains(r.err, "did not accept that name, password and code") {
		t.Fatalf("no code: code %d stderr %q", r.code, r.err)
	}
	if code, out, errb := d.operator(t, "reset-second-factor", labDirPrincipal); code != 0 ||
		!strings.Contains(out, "reset "+labDirPrincipal+"'s second factor") || !strings.Contains(out, "they may enroll until ") {
		t.Fatalf("reset-second-factor: code %d stdout %q stderr %q", code, out, errb)
	}
	var fresh []byte
	r = d.login(t, sock, enrollingBy(t, labDirPassword, func(s []byte, _ int) string {
		fresh = s
		return codeAt(t, s, d.now())
	}))
	if r.code != 0 || !strings.Contains(r.out, "Enroll your second factor") ||
		!strings.Contains(r.out, "port49: signed in with your directory password as "+labDirPrincipal) {
		t.Fatalf("the enrollment: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	mints(t, sock)
	stopAgentAt(sock)
	if bytes.Equal(fresh, labSecret) {
		t.Fatal("the new enrollment kept the old secret")
	}
	// The phone that is lost is no way in; the new one is.
	r = d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret)), "--sign-in")
	if r.code != 1 || !strings.Contains(r.err, "did not accept that name, password and code") {
		t.Fatalf("the old phone: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	r = d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, fresh)), "--sign-in")
	if r.code != 0 {
		t.Fatalf("the new phone: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
}

// The broker down with a held certificate: said, try again. The wording is
// the --oidc path's (TestABrokerThatDoesNotAnswerSaysToTryAgain and
// TestAFreshHeldCertificateWithTheBrokerDownSaysToTryAgain pin the same
// phrases), asserted here by the same strings.
func TestTheBrokerDownWithAHeldCertificate(t *testing.T) {
	d := newDirectoryLab(t)
	d.enrolled(t)
	sock := privateSocket(t)
	if r := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret))); r.code != 0 {
		t.Fatalf("the first login: code %d stderr %q", r.code, r.err)
	}
	stopAgentAt(sock)
	d.stop()

	// A certificate with life left starts the agent, which cannot connect.
	r := d.login(t, sock, refusingAnyPrompt(t))
	if r.code != 1 || strings.Contains(r.err, "--sign-in") ||
		!strings.Contains(r.err, "the broker at "+d.url+" did not answer; your certificate is valid until ") ||
		!strings.Contains(r.err, "; try again when it answers") {
		t.Fatalf("a fresh certificate: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	// One nearly over would sign in; the sign-in is not tried, nor a password asked.
	d.holdCertificate(t, time.Now().Add(-11*time.Hour), 12*time.Hour)
	r = d.login(t, sock, refusingAnyPrompt(t))
	if r.code != 1 || r.out != "" || strings.Contains(r.err, "--sign-in") ||
		!strings.Contains(r.err, "the broker at "+d.url+" did not answer; your certificate is valid until ") ||
		!strings.Contains(r.err, "; try again when it answers") {
		t.Fatalf("a late certificate: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	r = d.login(t, sock, refusingAnyPrompt(t), "--sign-in")
	if r.code != 1 || r.out != "" || !strings.Contains(r.err, "did not answer; your certificate is valid until ") {
		t.Fatalf("--sign-in: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	noAgent(t, sock)
}

// D7 at 3am: the enrollments file lost after the rollout. Password login
// says the store is lost and that holders keep working; a held certificate
// mints; the operator's reset-second-factor --all lets the next login
// enroll, and the unreadable file is kept beside the new one.
func TestALostEnrollmentStoreAtThreeAM(t *testing.T) {
	d := newDirectoryLab(t)
	d.enrolled(t)
	d.setCreated(t, d.now().Add(-365*24*time.Hour)) // no new-entry window: only --all opens enrollment
	sock := privateSocket(t)
	if r := d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, labSecret))); r.code != 0 {
		t.Fatalf("the first login: code %d stderr %q", r.code, r.err)
	}
	stopAgentAt(sock)

	// The file is damaged, and the broker starts again.
	const damaged = "not an enrollments file"
	if err := os.WriteFile(d.enrollPath, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	d.reopenEnrollments(t)
	if d.b.EnrollmentStoreLost() == "" {
		t.Fatal("the broker does not find its enrollment store lost")
	}

	r := d.login(t, sock, signingIn(t, labDirPassword, codeAt(t, labSecret, d.now())), "--sign-in")
	if r.code != 1 || r.out != "" || !strings.Contains(r.err, "the broker's store of second factors is missing or "+
		"unreadable, so no one can sign in with a password until an operator creates or restores it (the broker's "+
		"log says which); anyone already signed in keeps working until their certificate ends (enrollment_store_lost)") {
		t.Fatalf("a sign-in with the store lost: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	noAgent(t, sock)
	// Only password sign-in is refused: the held certificate logs in and mints.
	held := d.login(t, sock, refusingAnyPrompt(t))
	if held.code != 0 || !strings.Contains(held.out, "port49: using your certificate for "+labDirPrincipal) {
		t.Fatalf("the held certificate: code %d stdout %q stderr %q", held.code, held.out, held.err)
	}
	mints(t, sock)
	stopAgentAt(sock)

	code, out, errb := d.operator(t, "reset-second-factor", "--all")
	if code != 0 || !strings.Contains(out, "the enrollment store was lost and is replaced by an empty one, so everyone enrolls "+
		"again; the unreadable store was kept at ") {
		t.Fatalf("reset --all: code %d stdout %q stderr %q", code, out, errb)
	}
	kept, _ := filepath.Glob(d.enrollPath + ".unreadable-*")
	if raw, err := os.ReadFile(strings.Join(kept, "")); len(kept) != 1 || err != nil || string(raw) != damaged {
		t.Fatalf("the unreadable file kept beside the new one: %v %v", kept, err)
	}
	if _, err := os.Stat(d.enrollPath); err != nil || d.b.EnrollmentStoreLost() != "" {
		t.Fatalf("the new store: %v lost %q", err, d.b.EnrollmentStoreLost())
	}

	var fresh []byte
	r = d.login(t, sock, enrollingBy(t, labDirPassword, func(s []byte, _ int) string {
		fresh = s
		return codeAt(t, s, d.now())
	}), "--sign-in")
	if r.code != 0 || !strings.Contains(r.out, "Enroll your second factor") ||
		!strings.Contains(r.out, "port49: signed in with your directory password as "+labDirPrincipal) {
		t.Fatalf("the enrollment after --all: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	stopAgentAt(sock)
	// The new store holds the new factor.
	d.reopenEnrollments(t)
	if r = d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, fresh)), "--sign-in"); r.code != 0 {
		t.Fatalf("the factor in the new store: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
}

// D7, I15: a new install. Before `port49 directory init-enrollments` a
// login is refused, saying the store is missing or unreadable and that an
// operator creates or restores it, the broker's log saying which: the broker
// cannot tell a new install from a store lost after rollout, so the person's
// text never says "not initialised" (which would send the operator to
// init-enrollments over a store a restore would have recovered). The broker's
// own line names init-enrollments. After init the first login enrolls. A
// second init-enrollments exits 1, writing nothing.
func TestAFreshInstallNeedsInitEnrollments(t *testing.T) {
	d := newDirectoryLab(t)
	sock := privateSocket(t)
	r := d.login(t, sock, signingIn(t, labDirPassword, "123456"))
	if r.code != 1 || r.out != "" || !strings.Contains(r.err, "the broker's store of second factors is missing or "+
		"unreadable, so no one can sign in with a password until an operator creates or restores it (the broker's "+
		"log says which); anyone already signed in keeps working until their certificate ends (enrollment_store_lost)") {
		t.Fatalf("before init: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	noAgent(t, sock)
	if !strings.Contains(d.lines.String(), "On a new install run `port49 directory init-enrollments` once") {
		t.Fatalf("the broker's line does not name init-enrollments: %q", d.lines.String())
	}
	if _, err := os.Stat(d.enrollPath); err == nil {
		t.Fatal("a refused sign-in created the enrollment store")
	}

	d.initEnrollments(t)
	before, err := os.ReadFile(d.enrollPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(d.enrollPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the new store: %v %v", fi, err)
	}
	var secret []byte
	r = d.login(t, sock, enrollingBy(t, labDirPassword, func(s []byte, _ int) string {
		secret = s
		return codeAt(t, s, d.now())
	}))
	if r.code != 0 || !strings.Contains(r.out, "Enroll your second factor") ||
		!strings.Contains(r.out, "port49: signed in with your directory password as "+labDirPrincipal) {
		t.Fatalf("after init: code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	mints(t, sock)
	stopAgentAt(sock)

	// A second init writes nothing: the store, and the person's factor in it, stay.
	enrolledFile, err := os.ReadFile(d.enrollPath)
	if err != nil || bytes.Equal(before, enrolledFile) {
		t.Fatalf("the enrollment did not reach the store: %v", err)
	}
	if code, out, errb := d.operator(t, "init-enrollments"); code != 1 || out != "" ||
		!strings.Contains(errb, "the enrollment store is already there") {
		t.Fatalf("a second init: code %d stdout %q stderr %q", code, out, errb)
	}
	if after, err := os.ReadFile(d.enrollPath); err != nil || !bytes.Equal(after, enrolledFile) {
		t.Fatalf("a second init changed the store: %v", err)
	}
	if kept, _ := filepath.Glob(d.enrollPath + ".*"); len(kept) != 0 {
		t.Fatalf("a second init left %v", kept)
	}
	if r = d.login(t, sock, signingIn(t, labDirPassword, d.nextCode(t, secret)), "--sign-in"); r.code != 0 {
		t.Fatalf("the enrolled person after a second init: code %d stderr %q", r.code, r.err)
	}
}

// The retry loop, against the real broker: a wrong first code of an
// enrollment is asked again on the same handle (one sign-in, two confirms),
// and the right one issues. This pins wrongCode's reading of the broker's
// refusal: it keys on the broker's "ended" text, so a change to either side's
// wording alone fails this test and TestAnEndedEnrollmentIsNotAskedAgain.
func TestAWrongFirstEnrollmentCodeIsAskedAgainOnTheSameHandle(t *testing.T) {
	d := newDirectoryLab(t)
	d.initEnrollments(t)
	sock := privateSocket(t)
	r := d.login(t, sock, enrollingBy(t, labDirPassword, func(s []byte, try int) string {
		if try == 1 {
			return codeAt(t, labSecret, d.now()) // a code of another secret
		}
		return codeAt(t, s, d.now())
	}))
	if r.code != 0 || !strings.Contains(r.out, "port49: signed in with your directory password as "+labDirPrincipal) ||
		!strings.Contains(r.err, "port49 login: that code was not accepted; type the next one (2 tries left)") {
		t.Fatalf("code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	if n, c := d.served("POST", "/v1/sign-in"), d.served("POST", "/v1/sign-in/confirm"); n != 1 || c != 2 {
		t.Fatalf("%d sign-ins and %d confirms, want 1 and 2: the second code was not tried on the first handle", n, c)
	}
	var firsts int
	for _, a := range r.asked {
		if a == firstCodePrompt {
			firsts++
		}
	}
	if firsts != 2 {
		t.Fatalf("the first code was asked %d times, want 2", firsts)
	}
	mints(t, sock)
}

// The other half of the pin: a refusal that says the enrollment is over (an
// operator reset the person meanwhile) is not asked again, and costs the
// person no more tries.
func TestAnEndedEnrollmentIsNotAskedAgain(t *testing.T) {
	d := newDirectoryLab(t)
	d.initEnrollments(t)
	sock := privateSocket(t)
	r := d.login(t, sock, enrollingBy(t, labDirPassword, func(s []byte, _ int) string {
		if code, out, errb := d.operator(t, "reset-second-factor", labDirPrincipal); code != 0 {
			t.Fatalf("reset-second-factor: code %d stdout %q stderr %q", code, out, errb)
		}
		return codeAt(t, s, d.now())
	}))
	if r.code != 1 || !strings.Contains(r.err, "this enrollment ended or was confirmed; run `port49 login` again (sign_in_refused)") ||
		strings.Contains(r.err, "that code was not accepted") {
		t.Fatalf("code %d stdout %q stderr %q", r.code, r.out, r.err)
	}
	var firsts int
	for _, a := range r.asked {
		if a == firstCodePrompt {
			firsts++
		}
	}
	if firsts != 1 || d.served("POST", "/v1/sign-in/confirm") != 1 {
		t.Fatalf("the first code was asked %d times and confirmed %d, want once", firsts, d.served("POST", "/v1/sign-in/confirm"))
	}
	noAgent(t, sock)
}
