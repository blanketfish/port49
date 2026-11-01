// Package workload is the agentless client a workload mints with (plan 8;
// design §17: "machine workloads require no agent: identity is a file and
// minting is a single request"). It reads its certificate and key from their
// files at each New, so a renewal on disk needs no restart; holds no session
// and writes no socket; pages a sweep by the broker's batch_max, one
// Idempotency-Key per page, and retries a page under its key while the broker
// cannot answer now, until a deadline (spec §13 decision 40 ruling 10). It
// never returns a token in an error.
package workload

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	rand2 "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/clientkey"
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/mfatouch"
)

// DefaultDeadline is how long a run retries a broker that cannot answer now.
const DefaultDeadline = 2 * time.Minute

// ErrTemporary is a run the deadline ended with devices unminted: try again
// later (port49 workload exits 75, EX_TEMPFAIL).
var ErrTemporary = errors.New("workload: the broker could not answer now")

// pairWait is how long LoadCertificate waits before reading a pair that did
// not match again.
const pairWait = 500 * time.Millisecond

// betweenReads is that wait. A test replaces it with the renewer's second
// write, so it races no clock.
var betweenReads = func() { time.Sleep(pairWait) }

// jitter spreads a computed wait; a test replaces it to read exact waits.
var jitter = jittered

// jittered is d within plus or minus 20%, so a fleet started on one cron
// minute does not retry in step.
func jittered(d time.Duration) time.Duration {
	return d + time.Duration((rand2.Float64()*0.4-0.2)*float64(d))
}

// Config is a workload's broker and its certificate files.
type Config struct {
	Broker            string // https://host:port
	BrokerCA          *x509.CertPool
	CertFile, KeyFile string
	// TokenFile, in place of CertFile and KeyFile, is a projected service
	// account token presented as a bearer, read at every request (plan 10;
	// decision 49 ruling 14).
	TokenFile string
	Deadline  time.Duration // 0 is DefaultDeadline
	Now       func() time.Time
	// Warn says a late renewal; nil says nothing.
	Warn func(format string, args ...any)
	// VerifyBroker, when set, is the TLS config's VerifyConnection: it runs
	// after the broker's chain verified and before a request is written
	// (brokercrl.Checker.VerifyConnection). Its error is final.
	VerifyBroker func(tls.ConnectionState) error
	// TouchKey, when set, proves a per-login requirement (decision 45): an
	// item the broker denies per_login_mfa_required is proved with it and
	// minted again. It must sit on the same token as the workload's key, so
	// the token lists both slots' attestations. Without it such an item is
	// reported as the broker answered it.
	TouchKey hwkey.Key
	// Say tells the operator a touch is wanted, while the key waits for it;
	// nil says nothing. It is never given a challenge, token or PIN.
	Say func(format string, args ...any)
}

// MaxTokenFile is the most a token file may hold: a JWS port49 accepts is
// at most 16 KiB (decision 39 ruling 3).
const MaxTokenFile = 16 << 10

// TokenFileError is a token file the client cannot present: unreadable,
// empty, over MaxTokenFile, or holding whitespace inside the token. It never
// carries the file's content.
type TokenFileError struct {
	File string
	Err  error
}

func (e *TokenFileError) Error() string {
	return fmt.Sprintf("the token file %s: %v (a projected service account token, as the pod's volume writes it)",
		e.File, e.Err)
}

func (e *TokenFileError) Unwrap() error { return e.Err }

// readToken reads the file once, as it is now: the kubelet replaces it whole
// (decision 49 ruling 14). One trailing newline is trimmed.
func readToken(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		// The bare errno, so the message does not repeat the path; a fixed
		// text when err is not an *os.PathError (pre-flight M5).
		why := errors.Unwrap(err)
		if why == nil {
			why = errors.New("it could not be opened")
		}
		return "", &TokenFileError{File: file, Err: why}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxTokenFile+1))
	switch {
	case err != nil:
		return "", &TokenFileError{File: file, Err: errors.New("it could not be read")}
	case len(b) > MaxTokenFile:
		return "", &TokenFileError{File: file, Err: fmt.Errorf("it is over %d bytes", MaxTokenFile)}
	}
	tok := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	switch {
	case tok == "":
		return "", &TokenFileError{File: file, Err: errors.New("it is empty")}
	case strings.IndexFunc(tok, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0:
		return "", &TokenFileError{File: file, Err: errors.New("it holds whitespace or a character no token has")}
	}
	return tok, nil
}

// CertError is a certificate the client will not present.
type CertError struct {
	File                string
	NotBefore, NotAfter time.Time
	Expired             bool
}

func (e *CertError) Error() string {
	if e.Expired {
		return fmt.Sprintf("the certificate %s expired at %s: renew it against your CA (only the first enrollment is "+
			"manual)", e.File, e.NotAfter.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("the certificate %s is not valid until %s: check this host's clock", e.File,
		e.NotBefore.UTC().Format(time.RFC3339))
}

// APIError is the broker's final answer: a retry would get it again.
type APIError struct {
	Status       int
	Code, Detail string
}

func (e *APIError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Detail) }

// RedirectError is a broker that answered with a redirect, which the client
// never follows: the certificate and tokens go to the broker named alone. It
// is final, and no broker error code.
type RedirectError struct{ Status int }

func (e *RedirectError) Error() string {
	return fmt.Sprintf("the broker answered %d, a redirect; the client never follows one", e.Status)
}

// TLSError is a TLS verification failure, either way: the broker's certificate
// not under the broker CA, or the broker's alert refusing the workload's
// certificate. No retry mends it, so it is final (decision 40 ruling 10).
type TLSError struct {
	Refused bool // the broker refused our certificate; otherwise we refused its
	Err     error
}

func (e *TLSError) Error() string {
	if e.Refused {
		return fmt.Sprintf("the broker refused this workload's certificate (%v): check that its CA is one the broker "+
			"trusts for workloads, and both clocks", e.Err)
	}
	return fmt.Sprintf("the broker's certificate does not verify against --broker-ca (%v): check that --broker-ca is "+
		"the CA that signed the broker's certificate", e.Err)
}

func (e *TLSError) Unwrap() error { return e.Err }

// BrokerRefusedError is a connection Config.VerifyBroker refused (a revoked
// broker certificate, or one whose revocation could not be checked under
// broker_crl: require). Nothing was sent. It is final: the deadline's retries
// are for a broker that cannot answer, and this one was answered.
type BrokerRefusedError struct{ Err error }

func (e *BrokerRefusedError) Error() string { return e.Err.Error() }
func (e *BrokerRefusedError) Unwrap() error { return e.Err }

// TemporaryError is the deadline passing with Unminted not minted; Last is
// the broker's last answer, or the connection's failure.
type TemporaryError struct {
	Unminted []string
	Last     error
	Deadline time.Duration
}

func (e *TemporaryError) Error() string {
	return fmt.Sprintf("the broker did not answer within %s (the last answer: %v)", e.Deadline, e.Last)
}

func (e *TemporaryError) Unwrap() error { return ErrTemporary }

// LoadCertificate reads the pair, again up to twice more pairWait apart when
// the two do not match (a renewal writes one file, then the other), and
// refuses one outside its validity before anything connects. One with under
// a quarter of its validity left is said through warn (decision 40 ruling 9).
//
// keyFile is a path, or a key reference (pkcs11:, tpm:), opened through
// clientkey.LoadMountedPair (a path under the secret-file rule, within its own directory). A workload has no terminal and no agent to ask for a
// PIN: it comes from the reference's pin-source alone, and a key that wants
// one without it is refused, naming pin-source.
func LoadCertificate(certFile, keyFile string, now time.Time, warn func(string, ...any)) (tls.Certificate, error) {
	var cert tls.Certificate
	var err error
	for i := range 3 {
		if cert, err = clientkey.LoadMountedPair(certFile, keyFile, nil); err == nil ||
			!strings.Contains(err.Error(), "private key does not match public key") {
			break
		}
		if i < 2 {
			betweenReads()
		}
	}
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("the certificate %s and key %s: %w", certFile, keyFile, err)
	}
	if k, ok := cert.PrivateKey.(hwkey.Key); ok && k.State() == hwkey.Locked {
		_ = k.Close()
		return tls.Certificate{}, errors.New("the key needs a PIN and a workload has no terminal to ask for it: add " +
			"pin-source=file:///path (an owner-only file holding the PIN) to the key reference")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("the certificate %s: %w", certFile, err)
	}
	switch {
	case now.After(leaf.NotAfter):
		return tls.Certificate{}, &CertError{File: certFile, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Expired: true}
	case now.Before(leaf.NotBefore):
		return tls.Certificate{}, &CertError{File: certFile, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
	case warn != nil && api.LateRenewal(leaf, now):
		warn("the certificate %s expires %s (in %s) with under a quarter of its validity left: its renewal is late; "+
			"renew it against your CA", certFile, leaf.NotAfter.UTC().Format(time.RFC3339),
			leftIn(leaf.NotAfter.Sub(now)))
	}
	cert.Leaf = leaf
	return cert, nil
}

// leftIn is d for a warning: whole minutes, or whole seconds under a minute so
// it never reads "0s".
func leftIn(d time.Duration) string {
	if d < time.Minute {
		return max(d.Round(time.Second), 0).String()
	}
	return strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
}

// Client is one run's connection to the broker.
type Client struct {
	cfg   Config
	http  *http.Client
	sleep func(ctx context.Context, d time.Duration) error
	// session is the workload certificate's public key: the attestation of
	// its slot is the second one a touch proof carries.
	session crypto.PublicKey
}

// New reads the certificate (LoadCertificate) and makes the run's client.
// The certificate is always presented, whatever CA hint the broker sends.
func New(cfg Config) (*Client, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Deadline == 0 {
		cfg.Deadline = DefaultDeadline
	}
	cfg.Broker = strings.TrimRight(cfg.Broker, "/")
	// The client presents the workload's certificate and takes tokens back, so
	// it talks to the broker the operator named, over https, trusting the
	// broker CA alone (decision 40 ruling 10).
	if u, err := url.Parse(cfg.Broker); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the broker must be an https URL (https://host:port)")
	}
	if cfg.BrokerCA == nil {
		return nil, errors.New("a broker CA is required: the client trusts it alone, never the system's roots")
	}
	if cfg.TokenFile != "" {
		if cfg.CertFile != "" || cfg.KeyFile != "" || cfg.TouchKey != nil {
			return nil, errors.New("a workload presents a certificate or a token file, not both (and a touch key is " +
				"bound to a certificate's key)")
		}
		if _, err := readToken(cfg.TokenFile); err != nil {
			return nil, err
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cfg.BrokerCA,
			VerifyConnection: verifyOf(cfg)}}
		hc := &http.Client{Transport: tr, Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return &Client{cfg: cfg, http: hc, sleep: sleepCtx}, nil
	}
	cert, err := LoadCertificate(cfg.CertFile, cfg.KeyFile, cfg.Now(), cfg.Warn)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cfg.BrokerCA,
		VerifyConnection:     verifyOf(cfg),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}}
	// A redirect is never followed; its 3xx comes back as a RedirectError.
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{cfg: cfg, http: hc, sleep: sleepCtx, session: cert.Leaf.PublicKey}, nil
}

// verifyOf is cfg.VerifyBroker as the TLS config's VerifyConnection, its
// refusal wrapped final; nil when none is set.
func verifyOf(cfg Config) func(tls.ConnectionState) error {
	if cfg.VerifyBroker == nil {
		return nil
	}
	return func(cs tls.ConnectionState) error {
		if err := cfg.VerifyBroker(cs); err != nil {
			return &BrokerRefusedError{Err: err}
		}
		return nil
	}
}

// MintOptions is one run's mint: Devices by name, or every device Scope
// selects that the workload holds a grant on (spec §13 decision 42).
type MintOptions struct {
	Devices []string
	Scope   string
	Enable  bool
	TTL     time.Duration
	Purpose string
}

// Mint mints Devices a page of the broker's batch_max at a time, each page
// under its own Idempotency-Key. It returns every page's results it got;
// when a page was not minted by the deadline, a *TemporaryError naming every
// device from that page on.
func (c *Client) Mint(ctx context.Context, o MintOptions) (api.MintResponse, error) {
	deadline := c.cfg.Now().Add(c.cfg.Deadline)
	if o.Scope != "" {
		return c.sweep(ctx, deadline, o)
	}
	var conf api.Config
	if err := c.do(ctx, deadline, http.MethodGet, "/v1/config", nil, "", &conf); err != nil {
		return api.MintResponse{}, unminted(err, o.Devices)
	}
	page := max(conf.BatchMax, 1)
	var out api.MintResponse
	for i := 0; i < len(o.Devices); i += page {
		devs := o.Devices[i:min(i+page, len(o.Devices))]
		resp, err := c.page(ctx, deadline, api.MintRequest{Devices: devs, Enable: o.Enable,
			TTLSeconds: int(o.TTL / time.Second), Purpose: o.Purpose}, o.Devices[i:])
		if out.Principal == "" {
			out.Principal, out.Subject, out.Subjects = resp.Principal, resp.Subject, resp.Subjects
		}
		out.Results = append(out.Results, resp.Results...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// page posts one mint request under a key of its own, with do's retries. If
// the answer holds items denied per_login_mfa_required and a touch key is
// configured, it proves the one challenge they share and posts just those
// items again under a new key: the same key with a changed body is a 409, and
// the page again would mint the others twice. The response it returns holds
// what was minted whatever the error. rest is what a first request that
// fails leaves unminted.
func (c *Client) page(ctx context.Context, deadline time.Time, req api.MintRequest, rest []string) (api.MintResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return api.MintResponse{}, err
	}
	key, err := newKey()
	if err != nil {
		return api.MintResponse{}, err
	}
	var resp api.MintResponse
	if err := c.do(ctx, deadline, http.MethodPost, "/v1/tokens", body, key, &resp); err != nil {
		return api.MintResponse{}, unminted(err, rest)
	}
	var need []int
	for i, it := range resp.Results {
		if it.Reason == "per_login_mfa_required" && it.PerLoginMFA != nil && it.PerLoginMFA.Challenge != "" {
			need = append(need, i)
		}
	}
	if len(need) == 0 || c.cfg.TouchKey == nil {
		return resp, nil
	}
	challenge := resp.Results[need[0]].PerLoginMFA.Challenge
	var devs []string
	for _, i := range need {
		devs = append(devs, resp.Results[i].Device)
	}
	if err := c.proveTouch(ctx, challenge, devs); err != nil {
		return resp, err
	}
	again := req
	again.Devices, again.Scope, again.After, again.PerLoginMFAChallenge = devs, "", "", challenge
	if body, err = json.Marshal(again); err != nil {
		return resp, err
	}
	if key, err = newKey(); err != nil {
		return resp, err
	}
	var second api.MintResponse
	if err := c.do(ctx, deadline, http.MethodPost, "/v1/tokens", body, key, &second); err != nil {
		return resp, unminted(err, devs)
	}
	for _, it := range second.Results {
		for _, i := range need {
			if resp.Results[i].Device == it.Device {
				resp.Results[i] = it
			}
		}
	}
	return resp, nil
}

// proveTouch proves challenge with the touch key on one held connection: the
// exporter value is read off a GET /v1/config, the key signs it (the touch
// happens here, with no request in flight), and the proof is posted only if
// the connection the transport takes is still that one. A touch not made is
// the key's own error; a connection that changed meanwhile is
// mfatouch.ErrConnectionChanged, with nothing posted. Neither is retried: a
// retry would blink the key again for a touch nobody was there for.
func (c *Client) proveTouch(ctx context.Context, challenge string, devices []string) error {
	ch, err := mfatouch.Challenge(challenge)
	if err != nil {
		return err
	}
	certs, ok := c.cfg.TouchKey.(mfatouch.Certificates)
	if !ok {
		return fmt.Errorf("the touch key: %w", mfatouch.ErrNoAttestation)
	}
	list, err := certs.Certificates()
	if err != nil {
		return fmt.Errorf("reading the token's attestation certificates: %w", err)
	}
	chain, err := mfatouch.Chain(list, c.cfg.TouchKey.Public(), c.session)
	if err != nil {
		return err
	}
	ekm, err := c.exporter(ctx)
	if err != nil {
		return err
	}
	if c.cfg.Say != nil {
		c.cfg.Say("touch the key for %s", safeNames(devices))
	}
	sig, err := mfatouch.Sign(c.cfg.TouchKey, ch, ekm)
	if err != nil {
		return fmt.Errorf("proving the touch for %s: %w", strings.Join(devices, ", "), err)
	}
	body, err := mfatouch.Request(challenge, sig, chain)
	if err != nil {
		return err
	}
	resp, err := mfatouch.Post(ctx, c.http.Do, c.cfg.Broker+"/v1/mfa", body, ekm, func(conn net.Conn) (tls.ConnectionState, bool) {
		tc, ok := conn.(*tls.Conn)
		if !ok {
			return tls.ConnectionState{}, false
		}
		return tc.ConnectionState(), true
	})
	if err != nil {
		return c.connError(ctx, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return &RedirectError{Status: resp.StatusCode}
	}
	var e api.Error
	_ = json.Unmarshal(raw, &e)
	return &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
}

// exporter is the exporter value of the connection a GET /v1/config comes
// back on; the connection stays in the transport's pool for the post.
func (c *Client) exporter(ctx context.Context) ([]byte, error) {
	var state tls.ConnectionState
	var have bool
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if tc, ok := i.Conn.(*tls.Conn); ok {
			state, have = tc.ConnectionState(), true
		}
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, c.cfg.Broker+"/v1/config", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.connError(ctx, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Code: "config_unavailable",
			Detail: "the broker did not answer /v1/config, so there is no connection to prove on"}
	}
	if !have {
		return nil, errors.New("the connection to the broker is not a TLS connection")
	}
	return mfatouch.Exporter(state)
}

// connError is err as the client says a failed connection: the context's, a
// refused broker certificate, a TLS verification failure, or no answer.
func (c *Client) connError(ctx context.Context, err error) error {
	if errors.Is(err, mfatouch.ErrConnectionChanged) {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var refused *BrokerRefusedError
	if errors.As(err, &refused) {
		return refused
	}
	if te := tlsFailure(err); te != nil {
		return te
	}
	return fmt.Errorf("no answer: %w", err)
}

// sweep mints o.Scope's pages, each under its own Idempotency-Key, following
// the broker's next until it names none (decision 42 ruling 3). A next that
// does not advance past the page's after is the broker's fault, a
// *DecodeError, never a loop. A page the deadline ends is a *TemporaryError
// with the pages before it returned; it names no unminted device, since a
// sweep's devices are the broker's to list.
func (c *Client) sweep(ctx context.Context, deadline time.Time, o MintOptions) (api.MintResponse, error) {
	out := api.MintResponse{Results: []api.MintItem{}}
	after := ""
	for {
		resp, err := c.page(ctx, deadline, api.MintRequest{Scope: o.Scope, After: after, Enable: o.Enable,
			TTLSeconds: int(o.TTL / time.Second), Purpose: o.Purpose}, nil)
		if out.Principal == "" {
			out.Principal, out.Subject, out.Subjects = resp.Principal, resp.Subject, resp.Subjects
		}
		out.Results = append(out.Results, resp.Results...)
		if err != nil {
			return out, err
		}
		if resp.Next == "" {
			return out, nil
		}
		if resp.Next <= after || len(resp.Results) == 0 {
			return out, &DecodeError{Msg: fmt.Sprintf("the broker's sweep of %s did not advance past %q", o.Scope, after)}
		}
		after = resp.Next
	}
}

// Identity is what the broker resolves this certificate to.
func (c *Client) Identity(ctx context.Context) (api.Identity, error) {
	var id api.Identity
	err := c.do(ctx, c.cfg.Now().Add(c.cfg.Deadline), http.MethodGet, "/v1/identity", nil, "", &id)
	return id, err
}

func unminted(err error, devices []string) error {
	var te *TemporaryError
	if errors.As(err, &te) {
		te.Unminted = slices.Clone(devices)
	}
	return err
}

// do sends one request, and again under the same key while the broker
// cannot answer now: a 503 (but an uncovered certificate status), a 502, a
// 504, a 429, a 409 idempotency_in_progress after its Retry-After (5s when
// absent, 60s at most), a failed connection after 1s doubling to 30s (the
// computed waits jittered by 20%); until deadline. Any other answer is final,
// as is a TLS verification failure either way (TLSError).
func (c *Client) do(ctx context.Context, deadline time.Time, method, path string, body []byte, key string, out any) error {
	wait := time.Second
	for {
		req, err := http.NewRequestWithContext(ctx, method, c.cfg.Broker+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if c.cfg.TokenFile != "" {
			tok, err := readToken(c.cfg.TokenFile)
			if err != nil {
				return err // final: the file went away under the run
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		var last error
		var pause time.Duration
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var refused *BrokerRefusedError
			if errors.As(err, &refused) {
				return refused
			}
			if te := tlsFailure(err); te != nil {
				return te
			}
			last, pause = fmt.Errorf("no answer: %w", err), jitter(wait)
			wait = min(wait*2, 30*time.Second)
		} else {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if err := json.Unmarshal(raw, out); err != nil {
					return decodeError(path, err)
				}
				return nil
			}
			var e api.Error
			_ = json.Unmarshal(raw, &e)
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				return &RedirectError{Status: resp.StatusCode}
			}
			ae := &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
			if !retriable(resp.StatusCode, e) {
				return ae
			}
			last, pause = ae, retryAfter(resp.Header)
		}
		if !c.cfg.Now().Add(pause).Before(deadline) {
			return &TemporaryError{Last: last, Deadline: c.cfg.Deadline}
		}
		if err := c.sleep(ctx, pause); err != nil {
			return err
		}
	}
}

// tlsFailure is err when it is a TLS verification failure either way, which
// no retry mends: the broker's certificate not verifying (x509 errors from
// the handshake), or a TLS alert from the broker refusing ours (a remote
// error). A dropped, refused or timed-out connection is neither.
func tlsFailure(err error) *TLSError {
	var cv *tls.CertificateVerificationError
	if errors.As(err, &cv) {
		return &TLSError{Err: cv}
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" {
		return &TLSError{Refused: true, Err: op.Err}
	}
	return nil
}

// retriable is an answer a later try may change. A certificate status no
// source covers is not one: the broker answers it 503 with Retry-After, but
// it holds until the operator adds a CRL or OCSP for that issuer, so it is
// final here (decision 40 ruling 7; pre-flight I-2). A CRL past its next
// update is temporary.
func retriable(status int, e api.Error) bool {
	if status == http.StatusServiceUnavailable && e.Error == "certificate_status_unavailable" &&
		strings.Contains(e.Detail, api.UncoveredStatus) {
		return false
	}
	// A 502 or 504 is a proxy that could not reach the broker: a refused
	// connection by another name, and the key makes the retry safe (ruling 10).
	return status == http.StatusServiceUnavailable || status == http.StatusBadGateway ||
		status == http.StatusGatewayTimeout || status == http.StatusTooManyRequests ||
		(status == http.StatusConflict && e.Error == "idempotency_in_progress")
}

func retryAfter(h http.Header) time.Duration {
	if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 {
		return min(time.Duration(s)*time.Second, time.Minute)
	}
	return jitter(5 * time.Second)
}

// decodeError says where a 200 failed to decode and never what was there: a
// mint's body holds tokens, and a decoder's own message can quote a character
// or a number from the input.
func decodeError(path string, err error) error {
	return &DecodeError{Msg: decodeMessage(path, err)}
}

// DecodeError is a 200 that is not the broker's answer (a proxy's page): final.
type DecodeError struct{ Msg string }

func (e *DecodeError) Error() string { return e.Msg }

func decodeMessage(path string, err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("the broker's answer to %s is not valid JSON (offset %d)", path, syn.Offset)
	case errors.As(err, &typ):
		return fmt.Sprintf("the broker's answer to %s has the wrong shape (offset %d)", path, typ.Offset)
	}
	return fmt.Sprintf("the broker's answer to %s cannot be decoded", path)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func newKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
