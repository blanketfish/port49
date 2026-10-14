package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/issuer"
)

// The fixed fakes these tests type. A failure names the case, never the value.
const (
	fakePassword = "fake-password-1 " // ends in a space, as a password may
	fakeCode     = "000111"
	fakeCode2    = "000222"
	fakeURI      = "otpauth://totp/port49:alice?secret=ABCDEFGHIJKLMNOP&issuer=port49"
	fakeKey      = "ABCD EFGH IJKL MNOP"
	fakeCertPEM  = "FAKE-CERTIFICATE-PEM"
)

var fakeCSR = []byte("fake-csr")

type sentRequest struct {
	method, path, rawQuery string
	header                 http.Header
	body                   []byte
}

// signInBroker stands in for the broker's /v1/sign-in, /v1/sign-in/confirm and
// /v1/config, over TLS 1.3, recording every request it gets.
type signInBroker struct {
	srv  *httptest.Server
	pool *x509.CertPool
	mu   sync.Mutex
	sent []sentRequest
}

func newSignInBroker(t *testing.T, config, signIn, confirm http.HandlerFunc) *signInBroker {
	t.Helper()
	b := &signInBroker{}
	record := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			b.mu.Lock()
			b.sent = append(b.sent, sentRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
			b.mu.Unlock()
			if h == nil {
				http.NotFound(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			h(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/config", record(config))
	mux.HandleFunc("/v1/sign-in", record(signIn))
	mux.HandleFunc("/v1/sign-in/confirm", record(confirm))
	b.srv = httptest.NewUnstartedServer(mux)
	b.srv.StartTLS()
	t.Cleanup(b.srv.Close)
	b.pool = x509.NewCertPool()
	b.pool.AddCert(b.srv.Certificate())
	return b
}

// to is the requests that reached path.
func (b *signInBroker) to(path string) []sentRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []sentRequest
	for _, s := range b.sent {
		if s.path == path {
			out = append(out, s)
		}
	}
	return out
}

func answerWith(status int, code, detail string, header ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(api.Error{Error: code, Detail: detail})
	}
}

func jsonAnswer(status int, v any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
}

func issuedAnswer() http.HandlerFunc {
	return jsonAnswer(http.StatusOK, api.IssueResponse{Certificate: fakeCertPEM})
}

func enrollAnswer() http.HandlerFunc {
	return jsonAnswer(http.StatusAccepted, api.EnrollResponse{Enroll: api.Enrollment{
		Handle: "fake-handle", URI: fakeURI, ConfirmBy: "2026-10-14T12:00:00Z"}})
}

// typing makes the prompts a script: the name line (empty takes the default),
// then the secrets in order, and says what was asked. A terminal on both ends.
func typing(t *testing.T, line string, secrets ...string) *[]string {
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
		return line, nil
	}
	readSecret = func(prompt string, _ io.Writer) (string, error) {
		asked = append(asked, prompt)
		if len(secrets) == 0 {
			t.Error("a secret was asked for that the test did not type: " + prompt)
			return "", errors.New("nothing typed")
		}
		s := secrets[0]
		secrets = secrets[1:]
		return s, nil
	}
	return &asked
}

func signInFlags(b *signInBroker) *sessionFlags {
	return &sessionFlags{broker: b.srv.URL, directory: true, signInName: "alice-cfg", brokerCRL: "off"}
}

func decodeSignIn(t *testing.T, s sentRequest) api.SignInRequest {
	t.Helper()
	var req api.SignInRequest
	if err := json.Unmarshal(s.body, &req); err != nil {
		t.Fatalf("the sign-in body: %v", err)
	}
	return req
}

// The password and the code go in the body, once, over TLS; never in argv,
// the URL or a header; the name offered is --name, else sign_in_name, else
// the login user's.
func TestTheSignInSendsTheBodyOnce(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no login user")
	}
	for _, c := range []struct{ label, flagName, typed, want, offered string }{
		{"the configured name", "alice-cfg", "", "alice-cfg", "alice-cfg"},
		{"the login user's", "", "", me.Username, me.Username},
		{"the typed name over both", "alice-cfg", "bob", "bob", "alice-cfg"},
	} {
		b := newSignInBroker(t, nil, issuedAnswer(), nil)
		sf := signInFlags(b)
		sf.signInName = c.flagName
		asked := typing(t, c.typed, fakePassword, fakeCode)
		var stdout, stderr bytes.Buffer
		resp, err := directorySignIn(context.Background(), sf, b.pool, nil, fakeCSR, api.Config{SignIn: &api.SignInConfig{}},
			&stdout, &stderr)
		if err != nil || resp.Certificate != fakeCertPEM {
			t.Fatalf("%s: %v", c.label, err)
		}
		got := b.to("/v1/sign-in")
		if len(got) != 1 || len(b.sent) != 1 {
			t.Fatalf("%s: %d sign-ins, %d requests", c.label, len(got), len(b.sent))
		}
		s := got[0]
		req := decodeSignIn(t, s)
		if s.method != http.MethodPost || s.rawQuery != "" || req.Name != c.want || req.Password != fakePassword ||
			req.Code != fakeCode || req.CSR != base64.RawURLEncoding.EncodeToString(fakeCSR) {
			t.Errorf("%s: method %s, query %q, name %q, password as typed %v, code as typed %v, csr %v", c.label, s.method,
				s.rawQuery, req.Name, req.Password == fakePassword, req.Code == fakeCode,
				req.CSR == base64.RawURLEncoding.EncodeToString(fakeCSR))
		}
		for k, v := range s.header {
			if h := strings.Join(v, ","); strings.Contains(h, strings.TrimSpace(fakePassword)) || strings.Contains(h, fakeCode) ||
				k == "Authorization" {
				t.Errorf("%s: the %s header carries a credential", c.label, k)
			}
		}
		if !strings.Contains((*asked)[0], "["+c.offered+"]") {
			t.Errorf("%s: the name prompt %q does not offer the name", c.label, (*asked)[0])
		}
		if all := stdout.String() + stderr.String(); strings.Contains(all, strings.TrimSpace(fakePassword)) ||
			strings.Contains(all, fakeCode) {
			t.Errorf("%s: the terminal output carries a credential", c.label)
		}
	}
	// There is no way to put the password in argv or the environment.
	var fs flag.FlagSet
	(&sessionFlags{}).register(&fs)
	for _, n := range []string{"password", "pass", "code", "totp"} {
		if fs.Lookup(n) != nil {
			t.Errorf("--%s exists", n)
		}
	}
}

// No terminal: refused before anything is sent, naming it.
func TestNoTerminalIsRefused(t *testing.T) {
	b := newSignInBroker(t, nil, issuedAnswer(), nil)
	typing(t, "")
	loginStdinIsTerminal = func() bool { return false }
	readSecret = func(string, io.Writer) (string, error) {
		t.Error("a password was asked for with no terminal")
		return "", errors.New("no")
	}
	_, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "terminal") || !strings.Contains(err.Error(), "ssh -t") {
		t.Fatalf("%v", err)
	}
	if len(b.sent) != 0 {
		t.Fatalf("%d requests were sent", len(b.sent))
	}
}

// An empty password is refused at the prompt, nothing sent (Review Focus 1);
// a password ending in a space is sent as typed (M3).
func TestAnEmptyPasswordIsNotSent(t *testing.T) {
	for _, pw := range []string{"", "   "} {
		b := newSignInBroker(t, nil, issuedAnswer(), nil)
		typing(t, "", pw, fakeCode)
		_, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
			api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "an empty password is never sent") || len(b.sent) != 0 {
			t.Fatalf("%q-long password: %v, %d requests", strings.Repeat("x", len(pw)), err, len(b.sent))
		}
	}
	b := newSignInBroker(t, nil, issuedAnswer(), nil)
	typing(t, "", "typed-with-space ", fakeCode)
	if _, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := b.to("/v1/sign-in"); len(got) != 1 || decodeSignIn(t, got[0]).Password != "typed-with-space " {
		t.Fatal("a password ending in a space was not sent as typed")
	}
}

// 202: the QR code and the key in groups of four on the terminal, the
// confirm-by time; the first code goes to /v1/sign-in/confirm with the
// handle; no secret on stdout when stdout is not a terminal (refused).
func TestEnrollmentIsShownAndConfirmed(t *testing.T) {
	b := newSignInBroker(t, nil, enrollAnswer(), issuedAnswer())
	typing(t, "", fakePassword, "", fakeCode2)
	var stdout, stderr bytes.Buffer
	resp, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, &stdout, &stderr)
	if err != nil || resp.Certificate != fakeCertPEM {
		t.Fatalf("%v", err)
	}
	qr, _ := qrText(fakeURI)
	for _, want := range []string{"Enroll your second factor", qr, fakeKey, "confirm by 2026-10-14T12:00:00Z"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the terminal lacks %q", strings.TrimSpace(strings.SplitN(want, "\n", 2)[0]))
		}
	}
	if strings.Contains(stderr.String(), "ABCDEFGH") || strings.Contains(stderr.String(), "otpauth") ||
		strings.Contains(stderr.String(), fakeKey) {
		t.Error("the second factor's secret reached stderr")
	}
	first := decodeSignIn(t, b.to("/v1/sign-in")[0])
	if first.Code != "" || strings.Contains(string(b.to("/v1/sign-in")[0].body), `"code"`) {
		t.Error("the first request carried a code")
	}
	conf := b.to("/v1/sign-in/confirm")
	if len(conf) != 1 {
		t.Fatalf("%d confirms", len(conf))
	}
	var cr api.ConfirmRequest
	if err := json.Unmarshal(conf[0].body, &cr); err != nil || cr.Handle != "fake-handle" || cr.Code != fakeCode2 ||
		cr.CSR != base64.RawURLEncoding.EncodeToString(fakeCSR) || conf[0].rawQuery != "" {
		t.Errorf("the confirm: %v, handle %q, code as typed %v", err, cr.Handle, cr.Code == fakeCode2)
	}

	// Stdout not a terminal: refused before the secret is shown, no confirm.
	b = newSignInBroker(t, nil, enrollAnswer(), issuedAnswer())
	typing(t, "", fakePassword, "")
	stdoutIsTerminal = func() bool { return false }
	stdout.Reset()
	_, err = directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "run `port49 login` at a terminal") {
		t.Fatalf("%v", err)
	}
	if all := stdout.String() + err.Error(); strings.Contains(all, "ABCDEFGH") || strings.Contains(all, "otpauth") ||
		strings.Contains(all, fakeKey) || strings.Contains(all, qr) {
		t.Error("the secret was shown with no terminal")
	}
	if len(b.to("/v1/sign-in/confirm")) != 0 {
		t.Error("a confirm was sent")
	}
}

// A wrong first code is asked again, up to three times, with the same handle;
// an enrollment that ended is not retried.
func TestAWrongEnrollmentCodeIsAskedAgain(t *testing.T) {
	refused := answerWith(http.StatusUnauthorized, "sign_in_refused", "the broker did not accept that name, password and code")
	var n int
	b := newSignInBroker(t, nil, enrollAnswer(), func(w http.ResponseWriter, r *http.Request) {
		if n++; n == 1 {
			refused(w, r)
			return
		}
		issuedAnswer()(w, r)
	})
	typing(t, "", fakePassword, "", "000333", fakeCode2)
	var stderr bytes.Buffer
	if _, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, &stderr); err != nil {
		t.Fatal(err)
	}
	conf := b.to("/v1/sign-in/confirm")
	if len(conf) != 2 || !strings.Contains(stderr.String(), "did not accept") {
		t.Fatalf("%d confirms, stderr %q", len(conf), stderr.String())
	}

	b = newSignInBroker(t, nil, enrollAnswer(), refused)
	typing(t, "", fakePassword, "", "1", "2", "3")
	if _, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard); err == nil || len(b.to("/v1/sign-in/confirm")) != 3 {
		t.Fatalf("%v, %d confirms", err, len(b.to("/v1/sign-in/confirm")))
	}

	b = newSignInBroker(t, nil, enrollAnswer(), answerWith(http.StatusUnauthorized, "sign_in_refused",
		"this enrollment ended or was confirmed; run `port49 login` again"))
	typing(t, "", fakePassword, "", "1")
	if _, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard); err == nil || len(b.to("/v1/sign-in/confirm")) != 1 {
		t.Fatalf("%v, %d confirms", err, len(b.to("/v1/sign-in/confirm")))
	}
}

// Each refusal in the broker's words: sign_in_refused, sign_in_throttled
// with its time and the typed name, enrollment_closed naming the
// operator's command, directory_unavailable and enrollment_store_lost
// saying holders keep working.
func TestTheBrokersRefusalsAreSaid(t *testing.T) {
	const throttled = "too many failed sign-ins for this account; try again after 2026-10-14T12:00:00Z, or an operator " +
		"can clear it with `port49 directory unlock` for your account"
	for _, c := range []struct {
		label  string
		status int
		code   string
		detail string
		header []string
		want   []string
		not    []string
	}{
		{"a wrong name, password or code", 401, "sign_in_refused", "the broker did not accept that name, password and code; " +
			"check each and run `port49 login` again", nil, []string{"did not accept that name, password and code"}, nil},
		{"the account's state", 401, "sign_in_refused", "your directory account is locked: ask your directory administrator",
			nil, []string{"your directory account is locked: ask your directory administrator"}, nil},
		{"the principal's limit", 429, "sign_in_throttled", throttled, []string{"Retry-After", "300"},
			[]string{"too many failed sign-ins for alice-cfg", "2026-10-14T12:00:00Z", "5m0s", "port49 directory unlock"},
			[]string{"this account"}},
		{"the source's limit", 429, "sign_in_throttled", "too many failed sign-ins from this address; try again after " +
			"2026-10-14T12:00:00Z", []string{"Retry-After", "60"}, []string{"from this address", "2026-10-14T12:00:00Z", "1m0s"},
			[]string{"alice-cfg"}},
		{"enrollment closed", 403, "enrollment_closed", "you have no second factor, and enrollment is closed for you: ask an " +
			"operator to run `port49 directory reset-second-factor` for your account", nil,
			[]string{"enrollment is closed", "port49 directory reset-second-factor"}, nil},
		{"the directory down", 503, "directory_unavailable", "the directory did not answer, so no one can sign in with a " +
			"password now; anyone already signed in keeps working until their certificate ends", nil,
			[]string{"anyone already signed in keeps working"}, nil},
		{"the enrollment store lost", 503, "enrollment_store_lost", "the broker's store of second factors is lost, so no one " +
			"can sign in with a password until an operator restores it; anyone already signed in keeps working until " +
			"their certificate ends", nil, []string{"operator restores it", "keeps working"}, nil},
		{"a principal no certificate carries", 401, "sign_in_not_certifiable", "your account's principal cannot be carried in " +
			"a certificate; tell the operator", nil, []string{"cannot be carried in a certificate", "tell the operator"}, nil},
		{"no directory password at the broker", 404, "not_signing_in", "this broker takes no directory password", nil,
			[]string{"takes no directory password"}, nil},
		{"control characters in the detail", 401, "sign_in_refused", "refused\x1b[31m\nforged line", nil,
			[]string{"refused?[31m"}, []string{"\x1b", "\nforged"}},
	} {
		b := newSignInBroker(t, nil, answerWith(c.status, c.code, c.detail, c.header...), nil)
		typing(t, "", fakePassword, fakeCode)
		_, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
			api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard)
		if err == nil {
			t.Errorf("%s: no error", c.label)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the error lacks %q: %v", c.label, w, err)
			}
		}
		for _, w := range c.not {
			if strings.Contains(err.Error(), w) {
				t.Errorf("%s: the error has %q: %v", c.label, w, err)
			}
		}
		if strings.Contains(err.Error(), strings.TrimSpace(fakePassword)) || strings.Contains(err.Error(), fakeCode) {
			t.Errorf("%s: the error carries a credential", c.label)
		}
	}

	// The enrollment's confirm names the typed name on a throttle too.
	b := newSignInBroker(t, nil, enrollAnswer(), answerWith(429, "sign_in_throttled", throttled, "Retry-After", "300"))
	typing(t, "", fakePassword, "", fakeCode2)
	_, err := directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "too many failed sign-ins for alice-cfg") {
		t.Errorf("a throttled confirm: %v", err)
	}

	// A body that is not the broker's error shape is never printed.
	b = newSignInBroker(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "UNVALIDATED-BODY-TEXT")
	}, nil)
	typing(t, "", fakePassword, fakeCode)
	_, err = directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard)
	if err == nil || strings.Contains(err.Error(), "UNVALIDATED") || !strings.Contains(err.Error(), "500") {
		t.Errorf("an unvalidated body: %v", err)
	}

	// A revoked person is the refusal a held certificate is no way round.
	b = newSignInBroker(t, nil, answerWith(401, "credential_revoked", "you are revoked"), nil)
	typing(t, "", fakePassword, fakeCode)
	_, err = directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard)
	var refused *refusedError
	if !errors.As(err, &refused) {
		t.Errorf("credential_revoked: %T %v", err, err)
	}

	// A broker that does not answer is the broker down, not a refused sign-in.
	b = newSignInBroker(t, nil, issuedAnswer(), nil)
	b.srv.Close()
	typing(t, "", fakePassword, fakeCode)
	_, err = directorySignIn(context.Background(), signInFlags(b), b.pool, nil, fakeCSR,
		api.Config{SignIn: &api.SignInConfig{}}, io.Discard, io.Discard)
	var down *brokerDownError
	if !errors.As(err, &down) {
		t.Errorf("a dead broker: %T %v", err, err)
	}
}

// A broker with no directory_password says so before a password is asked.
func TestABrokerWithoutTheVerifierIsSaidFirst(t *testing.T) {
	b := newSignInBroker(t, jsonAnswer(http.StatusOK, api.Config{Methods: []string{"oidc"},
		Issuance: &api.Issuance{CertificateLifetimeSeconds: 3600}}), issuedAnswer(), nil)
	asked := typing(t, "")
	_, code, err := issueCertificate(context.Background(), signInFlags(b), b.pool, io.Discard, io.Discard)
	if err == nil || code != 1 || !strings.Contains(err.Error(), "takes no directory password") ||
		!strings.Contains(err.Error(), "--oidc") || len(*asked) != 0 || len(b.to("/v1/sign-in")) != 0 {
		t.Fatalf("code %d, %v, %d prompts, %d sign-ins", code, err, len(*asked), len(b.to("/v1/sign-in")))
	}
}

// --directory beside --oidc, --cert or --key is a usage error; method: directory in the file selects it.
func TestTheDirectoryFlags(t *testing.T) {
	cfg := filepath.Join(privateDir(t), "config.yaml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--directory", "--oidc"}, "--directory and --oidc are two logins"},
		{[]string{"--directory", "--cert", "c.pem"}, "--cert and --key are a certificate login's"},
		{[]string{"--directory", "--key", "k.pem"}, "--cert and --key are a certificate login's"},
		{[]string{"--directory", "--issuer", "https://a"}, "--issuer is --oidc's"},
		{[]string{"--directory", "--no-browser"}, "--no-browser is --oidc's"},
		{[]string{"--name", "bob"}, "--name is --directory's"},
	} {
		var out, errb bytes.Buffer
		args := append(append([]string{"login"}, c.args...), "--broker", configBroker, "--broker-ca", "ca.pem", "--config", cfg)
		if code := run(args, &out, &errb); code != 2 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%v: code %d %q", c.args, code, errb.String())
		}
	}

	// method: directory in the file selects it; a flag of the other login wins.
	dir := privateDir(t)
	file := labConfig(t, dir, configBroker)
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("method: directory\nsign_in_name: alice\n")
	f.Close()
	for _, c := range []struct {
		args            []string
		directory, oidc bool
		name            string
	}{
		{nil, true, false, "alice"},
		{[]string{"--name", "bob"}, true, false, "bob"},
		{[]string{"--oidc"}, false, true, "alice"},
	} {
		var sf sessionFlags
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sf.register(fs)
		if err := fs.Parse(append([]string{"--config", file}, c.args...)); err != nil {
			t.Fatal(err)
		}
		if err := sf.fill(fs); err != nil || sf.directory != c.directory || sf.oidc != c.oidc || sf.signInName != c.name {
			t.Errorf("%v: directory %v oidc %v name %q, %v", c.args, sf.directory, sf.oidc, sf.signInName, err)
		}
	}
	var sf sessionFlags
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	sf.register(fs)
	if err := fs.Parse([]string{"--config", file, "--directory", "--cert", "x"}); err != nil {
		t.Fatal(err)
	}
	if err := sf.fill(fs); err != nil || !sf.directory {
		t.Errorf("--directory with a file's cert: %v", err)
	}
	if (&sessionFlags{directory: true, broker: "https://b", cert: "c", key: "k", brokerCA: "ca", brokerCRL: "check"}).complete() {
		t.Error("a directory login is complete without reading the file")
	}
}

// The lines a login says: the method it signed in by, for a new certificate
// and for a held one.
func TestTheSignedInLinesNameTheMethod(t *testing.T) {
	end := time.Date(2026, 10, 14, 20, 0, 0, 0, time.UTC)
	dir := signedInLine(issuer.SignIn{Method: issuer.MethodDirectoryPassword, Principal: "user:alice@example.com"},
		"", "https://broker.example:8443", end)
	if want := "port49: signed in with your directory password as user:alice@example.com; your certificate from " +
		"https://broker.example:8443 is valid until 2026-10-14T20:00:00Z\n"; dir != want {
		t.Errorf("%q", dir)
	}
	oidcLine := signedInLine(issuer.SignIn{Principal: "user:alice@example.com"}, "https://idp.example",
		"https://broker.example:8443", end)
	if want := "port49: signed in at https://idp.example as user:alice@example.com; your certificate from " +
		"https://broker.example:8443 is valid until 2026-10-14T20:00:00Z\n"; oidcLine != want {
		t.Errorf("%q", oidcLine)
	}
	at := time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)
	if got := signedInWhere(issuer.SignIn{Method: issuer.MethodDirectoryPassword, AuthTime: at}); got !=
		"signed in with your directory password at 2026-10-14T08:00:00Z" {
		t.Errorf("%q", got)
	}
	if got := signedInWhere(issuer.SignIn{Issuer: "https://idp.example", AuthTime: at}); got !=
		"signed in at https://idp.example at 2026-10-14T08:00:00Z" {
		t.Errorf("%q", got)
	}
}
