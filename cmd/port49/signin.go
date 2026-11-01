package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/mfatouch"
	"github.com/blanketfish/port49/internal/printsafe"
)

// The directory sign-in's prompts, vars so a test drives them (plan 9e; spec
// §13 decision 47). The password is read only here, at a terminal with echo
// off: there is no flag, environment variable or descriptor that carries it.
var (
	// readSecret reads one line from the terminal on stdin with echo off, as
	// typed: never trimmed, since a password may end in a space.
	readSecret = func(prompt string, stderr io.Writer) (string, error) {
		fmt.Fprint(stderr, prompt)
		fd := int(os.Stdin.Fd())
		restore := func() {}
		if saved, err := term.GetState(fd); err == nil {
			restore = func() { _ = term.Restore(fd, saved) }
			defer restore()
		}
		s, err := guardedPaste(func() (string, error) {
			b, err := term.ReadPassword(fd)
			defer clear(b)
			return string(b), err
		}, restore, os.Exit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		fmt.Fprintln(stderr)
		return s, err
	}
	// readLine reads one line from stdin, echoed.
	readLine = func(prompt string, stderr io.Writer) (string, error) {
		fmt.Fprint(stderr, prompt)
		return readLineFrom(os.Stdin)
	}
	// stdoutIsTerminal is whether the enrollment's secret may be shown.
	stdoutIsTerminal = func() bool { return isTerminal(os.Stdout) }
)

// maxLine is the longest line readLineFrom keeps; the broker refuses a name
// over 256 bytes anyway.
const maxLine = 512

// readLineFrom reads one line from r a byte at a time, so nothing past the
// line is taken from the terminal's buffer, and drains the rest of a line
// longer than maxLine, so it cannot spill into the next prompt (the password's).
func readLineFrom(r io.Reader) (string, error) {
	var line []byte
	for one := make([]byte, 1); ; {
		if _, err := io.ReadFull(r, one); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			break
		}
		if len(line) < maxLine {
			line = append(line, one[0])
		}
	}
	return strings.TrimSpace(string(line)), nil
}

// confirmTries is how many first codes an enrollment is asked for: a mistyped
// one must not cost the person a new secret to scan.
const confirmTries = 3

// errNoDirectoryPassword is the broker listing no directory password sign-in.
func errNoDirectoryPassword(broker string) error {
	return fmt.Errorf("the broker at %s takes no directory password; log in with --oidc or a certificate", broker)
}

// directorySignIn is the sign-in half of issueCertificate for --directory:
// name, password and code to POST /v1/sign-in, the enrollment when the
// broker answers 202, and the certificate. It does not check that the broker
// takes a directory password: its caller, issueCertificate, does that from
// the broker's config before the store, the key or any prompt.
func directorySignIn(ctx context.Context, sf *sessionFlags, pool *x509.CertPool, verify func(tls.ConnectionState) error,
	csr []byte, stdout, stderr io.Writer) (api.IssueResponse, error) {
	if !loginStdinIsTerminal() {
		return api.IssueResponse{}, errors.New("a directory sign-in reads your password at a terminal, and stdin " +
			"is not one; run `port49 login --directory` at a terminal (use `ssh -t` on a remote host)")
	}
	name := sf.signInName
	if u, err := user.Current(); name == "" && err == nil { // as ssh.go reads the login user
		name = u.Username
	}
	if typed, err := readLine(fmt.Sprintf("directory name [%s]: ", name), stderr); err != nil {
		return api.IssueResponse{}, err
	} else if typed != "" {
		name = typed
	}
	if strings.TrimSpace(name) == "" {
		return api.IssueResponse{}, errors.New("a directory name is needed: type it, or give --name or sign_in_name")
	}
	password, err := readSecret("password: ", stderr)
	if err != nil {
		return api.IssueResponse{}, err
	}
	if strings.TrimSpace(password) == "" {
		return api.IssueResponse{}, errors.New("an empty password is never sent")
	}
	code, err := readSecret("code from your authenticator (empty if you have none yet): ", stderr)
	if err != nil {
		return api.IssueResponse{}, err
	}
	if strings.TrimSpace(code) == "" && !stdoutIsTerminal() {
		// No code says no authenticator yet: the broker would start an enrollment
		// and count an attempt, and the secret could not be shown here.
		return api.IssueResponse{}, errors.New("with no code, the broker would start an enrollment, which shows your " +
			"second factor's secret; run `port49 login` at a terminal, or type your authenticator's code")
	}
	resp, enroll, err := postSignIn(ctx, sf.broker, pool, verify, api.SignInRequest{Name: name, Password: password,
		Code: stripSpace(code), CSR: base64.RawURLEncoding.EncodeToString(csr)}, name)
	password, code = "", ""
	if err != nil || enroll == nil {
		return resp, err
	}
	return confirmEnrollment(ctx, sf, pool, verify, name, *enroll, csr, stdout, stderr)
}

// stripSpace is a code as the authenticator shows it ("123 456") without its spaces.
func stripSpace(s string) string { return strings.Join(strings.Fields(s), "") }

// postSignIn is POST /v1/sign-in. The request, and the password in it, is
// not kept: the body is built and the request's copy cleared before it is sent.
func postSignIn(ctx context.Context, broker string, pool *x509.CertPool, verify func(tls.ConnectionState) error,
	req api.SignInRequest, name string) (api.IssueResponse, *api.Enrollment, error) {
	body, err := json.Marshal(req)
	req.Password, req.Code = "", ""
	if err != nil {
		return api.IssueResponse{}, nil, err
	}
	status, header, raw, err := postJSON(ctx, broker, "/v1/sign-in", pool, verify, body)
	clear(body) // hygiene: the password and code were in it
	if err != nil {
		return api.IssueResponse{}, nil, err
	}
	switch status {
	case http.StatusOK:
		out, err := issuedFrom(raw)
		return out, nil, err
	case http.StatusAccepted:
		var e api.EnrollResponse
		if json.Unmarshal(raw, &e) != nil || e.Enroll.Handle == "" || e.Enroll.URI == "" {
			return api.IssueResponse{}, nil, errors.New("the broker started an enrollment this client cannot read; " +
				"tell the operator")
		}
		return api.IssueResponse{}, &e.Enroll, nil
	}
	return api.IssueResponse{}, nil, signInError(status, header, raw, name)
}

// postConfirm is POST /v1/sign-in/confirm.
func postConfirm(ctx context.Context, broker string, pool *x509.CertPool, verify func(tls.ConnectionState) error,
	req api.ConfirmRequest, name string) (api.IssueResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return api.IssueResponse{}, err
	}
	status, header, raw, err := postJSON(ctx, broker, "/v1/sign-in/confirm", pool, verify, body)
	if err != nil {
		return api.IssueResponse{}, err
	}
	if status != http.StatusOK {
		return api.IssueResponse{}, signInError(status, header, raw, name)
	}
	return issuedFrom(raw)
}

func issuedFrom(raw []byte) (api.IssueResponse, error) {
	var out api.IssueResponse
	if json.Unmarshal(raw, &out) != nil || out.Certificate == "" {
		return api.IssueResponse{}, errors.New("the broker's answer to the sign-in is not a certificate")
	}
	return out, nil
}

// postJSON is the broker's POST of body to path over TLS 1.3 to the broker's
// CA alone, never through a proxy and never following a redirect: the
// password goes to the broker named and nowhere else. A transport error is a
// *brokerDownError. The answer is read to 1 MiB.
func postJSON(ctx context.Context, broker, path string, pool *x509.CertPool, verify func(tls.ConnectionState) error,
	body []byte) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(broker, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{CheckRedirect: mfatouch.NoRedirect, Transport: &http.Transport{Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, VerifyConnection: verify}}}
	resp, err := c.Do(req)
	if err != nil {
		if refused := refusedByCRL(err); refused != nil {
			return 0, nil, nil, refused
		}
		return 0, nil, nil, &brokerDownError{fmt.Errorf("the broker at %s is unreachable: %w", broker, err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, nil, &brokerDownError{fmt.Errorf("the broker at %s: %w", broker, err)}
	}
	if err := agent.Redirected(resp); err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, raw, nil
}

// signInAnswer is the broker refusing a sign-in or a confirm. Its words are
// the broker's detail, made printable; nothing else of the body is said.
type signInAnswer struct {
	status int
	code   string
	msg    string
}

func (e *signInAnswer) Error() string { return e.msg }

// signInError says an HTTP refusal of /v1/sign-in or /confirm. The broker's
// detail is fixed text by reason (it never names the account or echoes what
// was typed), so it is the actionable sentence; a 429 adds when to try again
// and names the account by the name typed, which the broker does not (I3). A
// 401 credential_revoked is a *refusedError, as for /v1/certificate.
func signInError(status int, header http.Header, raw []byte, name string) error {
	var e api.Error
	_ = json.Unmarshal(raw, &e)
	detail := printsafe.Line(e.Detail, 400)
	code := printsafe.Line(e.Error, 64)
	if detail == "" {
		detail = fmt.Sprintf("%d %s", status, http.StatusText(status))
	}
	if status == http.StatusTooManyRequests {
		detail = strings.Replace(detail, "for this account", "for "+printsafe.Line(name, 64), 1)
		if n, err := strconv.Atoi(header.Get("Retry-After")); err == nil && n > 0 && n <= 86400 {
			detail += fmt.Sprintf(" (retry in %s)", time.Duration(n)*time.Second)
		}
	}
	msg := fmt.Sprintf("the broker did not sign you in: %s (%s)", detail, cmp.Or(code, strconv.Itoa(status)))
	if status == http.StatusUnauthorized && e.Error == string(decision.CredentialRevoked) {
		return &refusedError{msg}
	}
	return &signInAnswer{status: status, code: e.Error, msg: msg}
}

// wrongCode is a refusal the person may answer with another code: the
// broker's sign_in_refused, but not its word that the enrollment is over. The
// API gives nothing but the detail's words to tell the two apart (both are 401
// sign_in_refused, with no field of their own), so this keys on the "ended"
// of the broker's endedText; a retry of an ended handle costs only a source
// count.
func wrongCode(err error) bool {
	var a *signInAnswer
	return errors.As(err, &a) && a.status == http.StatusUnauthorized && a.code == string(decision.SignInRefused) &&
		!strings.Contains(a.msg, "ended")
}

// confirmEnrollment shows the new secret on the terminal and takes the first
// code of the authenticator that holds it. The secret goes nowhere else:
// not stderr, not a log, not an error. It is refused when stdout is no
// terminal, before it is shown.
func confirmEnrollment(ctx context.Context, sf *sessionFlags, pool *x509.CertPool, verify func(tls.ConnectionState) error,
	name string, enroll api.Enrollment, csr []byte, stdout, stderr io.Writer) (api.IssueResponse, error) {
	if !stdoutIsTerminal() {
		return api.IssueResponse{}, errors.New("enrolling shows your second factor's secret; run `port49 login` at a terminal")
	}
	secret := ""
	if u, err := url.Parse(enroll.URI); err == nil && u.Scheme == "otpauth" {
		secret = u.Query().Get("secret")
	}
	if secret == "" {
		return api.IssueResponse{}, errors.New("the broker's enrollment carries no key this client can show; tell the operator")
	}
	fmt.Fprintln(stdout, "Enroll your second factor: scan this with your authenticator app, or type the key")
	if qr, err := qrText(enroll.URI); err == nil {
		fmt.Fprintln(stdout, qr)
	} else {
		fmt.Fprintln(stdout, "(the QR code could not be drawn; type the key)")
	}
	fmt.Fprintf(stdout, "key: %s\nconfirm by %s\n", groupsOfFour(printsafe.Line(secret, 128)),
		printsafe.Line(enroll.ConfirmBy, 40))
	var last error
	for try := range confirmTries {
		code, err := readSecret("first code from your authenticator: ", stderr)
		if err != nil {
			return api.IssueResponse{}, err
		}
		if code = stripSpace(code); code == "" {
			last = errors.New("no code was typed")
			fmt.Fprintln(stderr, "port49 login: a code is needed to finish the enrollment")
			continue
		}
		resp, err := postConfirm(ctx, sf.broker, pool, verify, api.ConfirmRequest{Handle: enroll.Handle, Code: code,
			CSR: base64.RawURLEncoding.EncodeToString(csr)}, name)
		if err == nil || !wrongCode(err) {
			return resp, err
		}
		last = err
		if left := confirmTries - 1 - try; left > 0 {
			fmt.Fprintf(stderr, "port49 login: that code was not accepted; type the next one (%d tries left)\n", left)
		}
	}
	return api.IssueResponse{}, last
}

// groupsOfFour is s in groups of four characters, as it is typed into an
// authenticator.
func groupsOfFour(s string) string {
	s = strings.Join(strings.Fields(s), "")
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}
