// Package agent holds the operator's session on the certificate path (design
// §7; §8 "Two credentials, two lifetimes"): one mutual-TLS connection to the
// broker, opened with the operator's certificate, and a unix socket through
// which `port49 token` asks it to mint. The key is used at the handshake;
// every mint for the rest of the session travels over that connection, and
// no broker-issued session token exists (spec §13, decision 17).
//
// It holds no device token and writes none anywhere. Every ask is a mint, so
// a client that reconnects to a device presents a fresh credential rather
// than a spent one — which is what removes most of the receipt idle-gap
// problem the client matrix measured (spec §15, L15); the receipt bounds are
// the fallback, not the answer.
package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
)

// Config is what opens a session.
type Config struct {
	BrokerURL string
	// Cert is the operator's certificate and key. Load it with
	// keyfile.LoadX509KeyPair, which refuses a key file others could read.
	Cert     tls.Certificate
	BrokerCA *x509.CertPool
	Now      func() time.Time
	// Log receives the agent's own lines — reconnects, the session's end.
	// Never a token.
	Log io.Writer
}

// ErrSessionOver is a session that is over: past its ceiling by the agent's
// clock or the broker's, or holding a certificate the broker no longer
// trusts. The answer is `port49 login`.
var ErrSessionOver = errors.New("agent: the session is over; run `port49 login`")

// RevokedError is a session an operator's revocation ended (spec §5.1.4).
// It is ErrSessionOver to errors.Is, but its text does not say to log in:
// a login is refused the same way until the revocation is lifted. Detail is
// the broker's, which says since when and who lifts it.
type RevokedError struct{ Detail string }

func (e *RevokedError) Error() string { return "agent: the session is over: " + e.Detail }

// Is makes a revocation ErrSessionOver, so every caller ends the session.
func (e *RevokedError) Is(target error) bool { return target == ErrSessionOver }

// connectTimeout bounds Connect: the dial and the handshake that is the
// session's one use of the key. It is inside `port49 login`'s 15-second wait,
// so a broker that never answers is reported through the agent's own log
// rather than by login giving up on a silent agent (pre-flight F9). A var so
// a test can shorten it.
var connectTimeout = 10 * time.Second

// inProgressRetries and inProgressDelay bound how long Mint waits for a
// first try still minting under its key: fifteen seconds, past the
// broker's ten-second bound on a mint's store calls. The broker's
// Retry-After, when it sends one, replaces inProgressDelay up to
// inProgressDelayMax, so a broker that asks for an hour cannot park a
// login for one. Vars so a test can shorten them.
var (
	inProgressRetries  = 15
	inProgressDelay    = time.Second
	inProgressDelayMax = 5 * time.Second
)

// retryAfter is how long to wait before asking again: the broker's
// Retry-After in whole seconds, capped at inProgressDelayMax, or
// inProgressDelay when it sends none the agent can read.
func retryAfter(h http.Header) time.Duration {
	n, err := strconv.Atoi(h.Get("Retry-After"))
	if err != nil || n <= 0 {
		return min(inProgressDelay, inProgressDelayMax)
	}
	return min(time.Duration(n)*time.Second, inProgressDelayMax)
}

// Agent is one operator session.
type Agent struct {
	broker     string
	cert       tls.Certificate
	client     *http.Client
	now        func() time.Time
	log        io.Writer
	handshakes atomic.Int64
	// fingerprint is the certificate's, as CertFingerprint gives it.
	fingerprint string

	mu       sync.Mutex
	deadline time.Time
	// ceilingWarning is /v1/config's ceiling_warning_seconds: how near a
	// device's own ceiling `port49 token` warns.
	ceilingWarning time.Duration

	// refreshMu runs one refresh at a time: a second challenge on the
	// connection would replace the first one's nonce under it.
	refreshMu sync.Mutex
	// deadlineChanged is signalled when a refresh moves the deadline, so
	// the agent process re-arms its timer.
	deadlineChanged chan struct{}

	// done is closed when the broker ends the session (end).
	done    chan struct{}
	endOnce sync.Once
}

// New builds an agent. Nothing is dialed until Connect.
//
// The transport holds one connection (MaxConnsPerHost 1, no idle timeout):
// concurrent asks queue on it rather than opening a second handshake. When it
// drops, the next ask dials again, which is one more use of the key.
func New(c Config) *Agent {
	a := &Agent{broker: strings.TrimRight(c.BrokerURL, "/"), now: c.Now, log: c.Log, done: make(chan struct{}),
		deadlineChanged: make(chan struct{}, 1)}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = io.Discard
	}
	a.cert = c.Cert
	a.fingerprint = CertFingerprint(c.Cert)
	cert := c.Cert
	dialer := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.BrokerCA,
		// Always presented. Go's default presents a certificate only when the
		// broker's CA hint names its issuer, and otherwise sends none — so a
		// certificate from the wrong CA would log in with no identity at all
		// and fail at the first mint instead of here (plan 3, Decided 3).
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if n := a.handshakes.Add(1); n > 1 {
				fmt.Fprintf(a.log, "port49 agent: reconnected to the broker (handshake %d)\n", n)
			}
			return &watchedConn{Conn: conn}, nil
		},
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	a.client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return a
}

// CertFingerprint is "sha256:" and the hex SHA-256 of the certificate's leaf
// DER, as the broker's records name a certificate; "" for none. It is a
// public certificate's hash, not a credential: `port49 login` compares it to
// tell whether a running agent holds the session of the certificate it was
// given.
func CertFingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Connect opens the session: the handshake, which is the one use of the key
// (design §7), and GET /v1/config on the new connection. The broker stamped
// that connection's auth_time when it accepted it. The session ends
// max_session_age from now, however many reconnects happen in between (plan 3,
// Decided 11). It logs where it is connecting first and gives up after
// connectTimeout, so a broker that never answers leaves a line in the log.
func (a *Agent) Connect(ctx context.Context) (api.Config, error) {
	fmt.Fprintf(a.log, "port49 agent: connecting to %s\n", a.broker)
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.broker+"/v1/config", nil)
	if err != nil {
		return api.Config{}, err
	}
	resp, err := a.do(req)
	if err != nil {
		if refused := a.refusal(err); refused != nil {
			return api.Config{}, refused
		}
		var hup *hangUpError
		if errors.As(err, &hup) {
			return api.Config{}, hup
		}
		return api.Config{}, fmt.Errorf("agent: connecting to the broker at %s: %w", a.broker, err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if over := sessionOver(resp.StatusCode, e); over != nil {
			// A revoked principal or certificate is answered so as its
			// connection binds (spec §5.1.4): say why, and since when.
			return api.Config{}, over
		}
		if busy := unavailable(resp, e); busy != nil {
			return api.Config{}, busy
		}
		return api.Config{}, fmt.Errorf("agent: %s/v1/config answered %s: %s %s", a.broker, resp.Status, e.Error, e.Detail)
	}
	var c api.Config
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return api.Config{}, fmt.Errorf("agent: %s/v1/config: %w", a.broker, err)
	}
	if c.MaxSessionAgeSeconds <= 0 {
		return api.Config{}, fmt.Errorf("agent: %s names no max_session_age, so the session would have no end", a.broker)
	}
	a.mu.Lock()
	a.deadline = a.now().Add(time.Duration(c.MaxSessionAgeSeconds) * time.Second)
	a.ceilingWarning = time.Duration(c.CeilingWarningSeconds) * time.Second
	a.mu.Unlock()
	return c, nil
}

// SessionEndsAt is when this session ends; zero before Connect.
func (a *Agent) SessionEndsAt() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deadline
}

// DeadlineChanged is signalled when a refresh moves SessionEndsAt, so the
// agent process re-arms the timer that ends it (pre-flight I6). It holds one
// signal; a second refresh before the first is read is the same news.
func (a *Agent) DeadlineChanged() <-chan struct{} { return a.deadlineChanged }

// Handshakes is how many connections this session has opened.
func (a *Agent) Handshakes() int64 { return a.handshakes.Load() }

// Done is closed when the broker ends the session — it answered
// session_expired or credential_revoked, or it no longer trusts the
// certificate. The agent process exits on it, so the next `port49 login`
// starts a new session instead of finding this one "already logged in"
// (pre-flight F10).
func (a *Agent) Done() <-chan struct{} { return a.done }

// end records why the broker ended the session and closes Done, once.
func (a *Agent) end(why error) {
	a.endOnce.Do(func() {
		fmt.Fprintf(a.log, "port49 agent: the broker ended the session: %v\n", why)
		close(a.done)
	})
}

// Mint asks the broker for a fresh token for one device. A transport failure
// is retried once, on a new connection, under the same Idempotency-Key, so a
// mint whose response was lost is replayed rather than cut again (design
// §17); a 409 idempotency_in_progress, that first try still minting, is
// waited out under the same key. A 401 session_expired or
// trust_domain_unresolved ends the session, and so does a reconnect whose
// handshake the broker refuses. A 401 credential_revoked ends it too. An
// item the broker could not decide is returned with an *ItemError, never
// alone.
func (a *Agent) Mint(ctx context.Context, device string, enable bool, ttl time.Duration) (api.MintItem, error) {
	select {
	case <-a.done:
		return api.MintItem{}, ErrSessionOver
	default:
	}
	if ends := a.SessionEndsAt(); ends.IsZero() || !a.now().Before(ends) {
		return api.MintItem{}, ErrSessionOver
	}
	body, err := json.Marshal(api.MintRequest{Devices: []string{device}, Enable: enable, TTLSeconds: int(ttl / time.Second)})
	if err != nil {
		return api.MintItem{}, err
	}
	key, err := newKey()
	if err != nil {
		return api.MintItem{}, err
	}
	var resp *http.Response
	for wait := 0; ; wait++ {
		if resp, err = a.post(ctx, body, key); err != nil {
			return api.MintItem{}, err
		}
		if resp.StatusCode != http.StatusConflict {
			break
		}
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		drain(resp.Body)
		if e.Error != "idempotency_in_progress" || wait >= inProgressRetries {
			return api.MintItem{}, fmt.Errorf("agent: the broker answered %s: %s %s", resp.Status, e.Error, e.Detail)
		}
		// The first try under this key is still minting at the broker (a
		// lost response, retried by post): wait for it and be answered
		// from it, under the same key (design §17).
		select {
		case <-ctx.Done():
			return api.MintItem{}, ctx.Err()
		case <-time.After(retryAfter(resp.Header)):
		}
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if over := sessionOver(resp.StatusCode, e); over != nil {
			a.end(over)
			return api.MintItem{}, over
		}
		if busy := unavailable(resp, e); busy != nil {
			return api.MintItem{}, busy
		}
		return api.MintItem{}, fmt.Errorf("agent: the broker answered %s: %s %s", resp.Status, e.Error, e.Detail)
	}
	var mr api.MintResponse
	if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
		return api.MintItem{}, fmt.Errorf("agent: the broker's answer: %w", err)
	}
	if len(mr.Results) != 1 || mr.Results[0].Device != device {
		return api.MintItem{}, fmt.Errorf("agent: asked for %s, the broker answered %d items", device, len(mr.Results))
	}
	item := mr.Results[0]
	switch {
	case item.Error != "":
		return item, &ItemError{Device: item.Device, Code: item.Error, Detail: item.Detail}
	case item.Verdict == "":
		return api.MintItem{}, fmt.Errorf("agent: the broker answered %s with neither a verdict nor an error", device)
	}
	return item, nil
}

// post sends one mint request under key, retrying a transport failure once
// on a new connection, exactly as Mint did before plan 7a; the refusals
// that end the session end it here.
func (a *Agent) post(ctx context.Context, body []byte, key string) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.broker+"/v1/tokens", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := a.do(req)
		if err == nil {
			return resp, nil
		}
		a.client.CloseIdleConnections()
		if over := a.refusedReconnect(err); over != nil {
			return nil, over
		}
		if attempt == 2 {
			// A hang-up right after the handshake with a certificate still
			// in date is a refusal whose alert was lost or a broker that
			// restarted, and says so; it does not end the session, since
			// only an alert or the expiry says for certain.
			var hup *hangUpError
			if errors.As(err, &hup) {
				return nil, hup
			}
			return nil, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
		}
	}
}

// APIError is a broker answer that is neither a 200 nor a refusal that ends
// the session (sessionOver): its status, the API's code (design §17's
// Errors) and the broker's detail. A 503 is one too, revocation_busy among
// them: it ends nothing, and the operator asks again after RetryAfter, the
// broker's Retry-After (zero for none).
type APIError struct {
	Status     int
	Code       string
	Detail     string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	switch {
	case e.Status == http.StatusServiceUnavailable && e.Code == "certificate_status_unavailable" && e.Detail != "":
		// The broker's detail says what it could not establish, as
		// unavailable says it.
		return "agent: " + e.Detail + retryIn(e.RetryAfter)
	case e.Status == http.StatusServiceUnavailable:
		return "agent: the broker is unavailable just now: " + e.Code + ": " + e.Detail + retryIn(e.RetryAfter)
	}
	return "agent: the broker refused: " + e.Code + ": " + e.Detail + retryIn(e.RetryAfter)
}

// call sends one request on the held connection and decodes a 200 into out.
// A refusal that ends the session ends it here, as a mint's does; anything
// else, a 503 included, is an *APIError, so a caller can tell
// revocation_busy from api_right_missing by its code. A transport failure
// is tried once more on a new connection, as post does: every call made
// through it is safe to repeat (identity and explain read; a revocation
// made again reaches what the first did not, and stands as before).
func (a *Agent) call(ctx context.Context, method, path string, in, out any) error {
	select {
	case <-a.done:
		return ErrSessionOver
	default:
	}
	if ends := a.SessionEndsAt(); ends.IsZero() || !a.now().Before(ends) {
		return ErrSessionOver
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	var resp *http.Response
	for attempt := 1; ; attempt++ {
		var rd io.Reader = http.NoBody
		if in != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, a.broker+path, rd)
		if err != nil {
			return err
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if resp, err = a.do(req); err == nil {
			break
		}
		a.client.CloseIdleConnections()
		if over := a.refusedReconnect(err); over != nil {
			return over
		}
		if attempt == 2 {
			var hup *hangUpError
			if errors.As(err, &hup) {
				return hup
			}
			return fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
		}
	}
	defer drain(resp.Body)
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("agent: the broker's answer: %w", err)
		}
		return nil
	}
	var e api.Error
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
	if over := sessionOver(resp.StatusCode, e); over != nil {
		a.end(over)
		return over
	}
	if resp.StatusCode == http.StatusNotFound && e.Error == "" {
		// The broker's mux has no such route: a port49d older than this
		// agent (pre-flight I9).
		return &APIError{Status: http.StatusNotFound, Code: "not_supported", Detail: fmt.Sprintf(
			"the broker at %s does not serve %s: it runs a port49d older than this port49", a.broker, path)}
	}
	if e.Error == "" {
		// Not the broker's API answering: a proxy, or a body cut short.
		return fmt.Errorf("agent: %s%s answered %s with no API error", a.broker, path, resp.Status)
	}
	return &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail, RetryAfter: retryAfterHeader(resp.Header)}
}

// Identity is GET /v1/identity: what the broker resolves this session's
// principal to (design §17).
func (a *Agent) Identity(ctx context.Context) (api.Identity, error) {
	var out api.Identity
	return out, a.call(ctx, http.MethodGet, "/v1/identity", nil, &out)
}

// Explain is POST /v1/explain: a hypothetical decision from the broker's
// policy in force (design §17).
func (a *Agent) Explain(ctx context.Context, req api.ExplainRequest) (api.ExplainResponse, error) {
	var out api.ExplainResponse
	return out, a.call(ctx, http.MethodPost, "/v1/explain", req, &out)
}

// Revoke is POST /v1/tokens/revoke under this session's principal's rights
// (spec §5.1.4). A self-revocation leaves no mark, so the session goes on;
// a revocation of this session's own principal by another is answered
// credential_revoked at the next call, which ends it. A 503
// revocation_busy revoked nothing and ends nothing.
func (a *Agent) Revoke(ctx context.Context, req api.RevokeRequest) (api.RevokeResponse, error) {
	var out api.RevokeResponse
	return out, a.call(ctx, http.MethodPost, "/v1/tokens/revoke", req, &out)
}

// refusedReconnect ends the session on a transport error that means no
// reconnect will be accepted, and returns why; nil for any other error.
func (a *Agent) refusedReconnect(err error) error {
	if refused := a.refusal(err); refused != nil {
		// A reconnect whose handshake failed: the certificate expired
		// or the trust changed under the session, and no retry will
		// mint (Ruling Q1; pre-flight F10).
		over := fmt.Errorf("%w: %s", ErrSessionOver, strings.TrimPrefix(refused.Error(), "agent: "))
		a.end(over)
		return over
	}
	// A hang-up with a certificate past its NotAfter is that refusal
	// with its alert lost, which over a real network the RST can
	// discard: nothing this session holds will mint again, so it ends
	// as the alert would have (pre-flight F10).
	if hup := (*hangUpError)(nil); errors.As(err, &hup) && !hup.expired.IsZero() {
		over := fmt.Errorf("%w: %s", ErrSessionOver, strings.TrimPrefix(hup.Error(), "agent: "))
		a.end(over)
		return over
	}
	return nil
}

// sessionOver is the ErrSessionOver a broker's answer means, or nil: a 401
// that nothing this session holds will get past.
func sessionOver(status int, e api.Error) error {
	if status != http.StatusUnauthorized {
		return nil
	}
	switch e.Error {
	case "session_expired":
		return ErrSessionOver
	case "trust_domain_unresolved":
		// The certificate expired, or stopped verifying, under the held
		// connection: nothing this session can do will mint again (spec
		// §13, decision 12).
		return fmt.Errorf("%w: the broker no longer trusts this certificate (%s)", ErrSessionOver, e.Detail)
	case "credential_revoked":
		// An operator revoked this principal or this certificate (spec
		// §5.1.4): nothing this session holds will mint again, and no new
		// one until the lift.
		return &RevokedError{Detail: e.Detail}
	}
	return nil
}

// unavailable is the error a 503 means, or nil for any other answer. A 503
// is the broker unable to answer just now: it never ends the session, and
// the operator asks again (pre-flight I7). Only the broker's code and its
// fixed detail are said, and its Retry-After when it sends one.
func unavailable(resp *http.Response, e api.Error) error {
	if resp.StatusCode != http.StatusServiceUnavailable {
		return nil
	}
	if e.Error == "certificate_status_unavailable" {
		// The broker's detail says what it could not establish, and to try
		// again: said as it is, not wrapped in the same sentence again.
		if e.Detail != "" {
			return fmt.Errorf("agent: %s%s", e.Detail, retryHint(resp.Header))
		}
		return fmt.Errorf("agent: the broker cannot establish your certificate's revocation status just now; try again%s",
			retryHint(resp.Header))
	}
	return fmt.Errorf("agent: the broker is unavailable just now (%s): %s%s", e.Error, e.Detail, retryHint(resp.Header))
}

// retryHint is "; retry in Ns" for a Retry-After in whole seconds, or "".
func retryHint(h http.Header) string { return retryIn(retryAfterHeader(h)) }

// retryAfterHeader is a Retry-After in whole seconds, uncapped, or zero
// when there is none the agent can read.
func retryAfterHeader(h http.Header) time.Duration {
	if n, err := strconv.Atoi(h.Get("Retry-After")); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// retryIn is "; retry in Ns" for a positive d, or "".
func retryIn(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf("; retry in %ds", int(d/time.Second))
}

// Refresh re-authenticates the session on the held connection (spec §5.6;
// decision 33): it asks the broker for a challenge, signs it with the
// session's key over the connection's TLS exporter value, and sends the
// signature. It is run by `port49 refresh` and `port49 login` alone, never
// on the agent's own initiative: the ceiling measures time since a person
// authenticated. A refusal that names the challenge, a connection dropped
// between the two requests or a hardware touch slower than the challenge's
// minute, is tried once more.
//
// credential_revoked ends the session, as a mint's does. Anything else the
// broker refuses (refresh_too_soon, a 503) is returned and ends nothing, and
// the deadline moves only on a refresh the broker answered 200.
func (a *Agent) Refresh(ctx context.Context) (api.RefreshResponse, error) {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	select {
	case <-a.done:
		return api.RefreshResponse{}, ErrSessionOver
	default:
	}
	if ends := a.SessionEndsAt(); ends.IsZero() || !a.now().Before(ends) {
		return api.RefreshResponse{}, ErrSessionOver
	}
	signer, ok := a.cert.PrivateKey.(crypto.Signer)
	if !ok {
		return api.RefreshResponse{}, errors.New("agent: the session's key cannot sign a refresh")
	}
	for attempt := 1; ; attempt++ {
		out, retry, err := a.refreshOnce(ctx, signer)
		if err == nil || !retry || attempt == 2 {
			return out, err
		}
	}
}

// refreshOnce is one challenge and its answer. retry says the broker found
// no live challenge for the answer: a new challenge may succeed.
func (a *Agent) refreshOnce(ctx context.Context, signer crypto.Signer) (api.RefreshResponse, bool, error) {
	var conn *watchedConn
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { conn, _ = i.Conn.(*watchedConn) }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost,
		a.broker+"/v1/refresh/challenge", http.NoBody)
	if err != nil {
		return api.RefreshResponse{}, false, err
	}
	resp, err := a.do(req)
	if err != nil {
		// A reconnect the broker refuses ends the session, as a mint's
		// does; no new challenge would be answered either.
		if over := a.refusedReconnect(err); over != nil {
			return api.RefreshResponse{}, false, over
		}
		return api.RefreshResponse{}, false, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
	}
	if resp.StatusCode != http.StatusOK {
		defer drain(resp.Body)
		_, _, err := a.refreshRefused(resp, "a refresh challenge")
		return api.RefreshResponse{}, false, err
	}
	var ch api.RefreshChallenge
	derr := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&ch)
	drain(resp.Body)
	if derr != nil {
		return api.RefreshResponse{}, false, errors.New("agent: the broker's refresh challenge is malformed")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(ch.Nonce)
	if err != nil || len(nonce) != api.RefreshNonceLen {
		return api.RefreshResponse{}, false, errors.New("agent: the broker's refresh challenge is malformed")
	}
	// The exporter value of the connection the challenge came on: the
	// answer verifies only there, so a nonce carried to another connection
	// proves nothing (decision 33).
	if conn == nil {
		return api.RefreshResponse{}, false, errors.New("agent: the refresh challenge came on no TLS connection")
	}
	cs, ok := conn.tlsState()
	if !ok {
		return api.RefreshResponse{}, false, errors.New("agent: the refresh challenge came on no TLS connection")
	}
	ekm, err := cs.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
	if err != nil {
		return api.RefreshResponse{}, false, fmt.Errorf("agent: the connection's exporter value: %w", err)
	}
	sig, err := api.SignRefresh(signer, api.RefreshMessage(nonce, ekm))
	if err != nil {
		return api.RefreshResponse{}, false, fmt.Errorf("agent: signing the refresh: %w", err)
	}
	body, err := json.Marshal(api.RefreshRequest{Nonce: ch.Nonce, Signature: base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil {
		return api.RefreshResponse{}, false, err
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, a.broker+"/v1/refresh", bytes.NewReader(body))
	if err != nil {
		return api.RefreshResponse{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = a.do(req)
	if err != nil {
		if over := a.refusedReconnect(err); over != nil {
			return api.RefreshResponse{}, false, over
		}
		return api.RefreshResponse{}, true, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return a.refreshRefused(resp, "the refresh")
	}
	var out api.RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return api.RefreshResponse{}, false, fmt.Errorf("agent: the broker's answer to the refresh: %w", err)
	}
	ends, err := time.Parse(time.RFC3339, out.SessionEndsAt)
	if err != nil {
		return api.RefreshResponse{}, false, fmt.Errorf("agent: the broker's answer to the refresh names no session_ends_at: %w", err)
	}
	a.mu.Lock()
	a.deadline = ends
	a.mu.Unlock()
	select {
	case a.deadlineChanged <- struct{}{}:
	default:
	}
	return out, false, nil
}

// refreshRefused is the error a refused challenge or refresh means. The
// code decides, never the detail text: credential_revoked ends the session,
// refresh_challenge_missing is worth one new challenge, and the rest end
// nothing.
func (a *Agent) refreshRefused(resp *http.Response, what string) (api.RefreshResponse, bool, error) {
	var e api.Error
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&e)
	if over := sessionOver(resp.StatusCode, e); over != nil && e.Error == "credential_revoked" {
		a.end(over)
		return api.RefreshResponse{}, false, over
	}
	if busy := unavailable(resp, e); busy != nil {
		return api.RefreshResponse{}, false, busy
	}
	hint := ""
	if resp.StatusCode == http.StatusTooManyRequests {
		hint = retryHint(resp.Header)
	}
	return api.RefreshResponse{}, e.Error == "refresh_challenge_missing",
		fmt.Errorf("agent: the broker refused %s: %s (%s)%s", what, e.Detail, e.Error, hint)
}

// ItemError is a device the broker could not decide: a fault on its side or
// in its inventory, not a refusal of the operator (design §17). It carries
// the broker's code and detail; the operator's answer is usually to tell
// whoever runs port49d.
type ItemError struct {
	Device, Code, Detail string
}

func (e *ItemError) Error() string {
	what := map[string]string{
		"device_unconfigured":     "the broker's inventory does not configure this device",
		"broker_error":            "the broker failed",
		"idempotency_in_progress": "the broker is still minting an earlier try of this request",
		"attribute_too_long":      "a session attribute for this device is too long once filled in",
		"attribute_unsafe":        "a session attribute for this device would contain a character port49 refuses (= or *, a control character, or invalid UTF-8) once filled in",
		"bad_request":             "the broker refused the request",
		"idempotency_conflict":    "the broker holds a different request under this request's key",
	}[e.Code]
	if what == "" {
		what = "the broker could not answer"
	}
	return fmt.Sprintf("agent: no token for %s: %s (%s): %s", e.Device, what, e.Code, e.Detail)
}

// refusal says what a failed handshake most likely means, or nil for an
// error that is not one: a broker that is down, unreachable, or sending an
// alert that is not about the certificate is left to the caller's own
// message. In TLS 1.3 the broker rejects a client certificate
// after the client's side of the handshake is done, so the agent sees only
// the bare alert on its first read, with no reason; the causes are named
// here instead, and an expired certificate by its own date.
func (a *Agent) refusal(err error) error {
	var verify *tls.CertificateVerificationError
	if errors.As(err, &verify) {
		return fmt.Errorf("agent: the broker's certificate at %s does not verify (%v); check that the trust anchor "+
			"(--broker-ca) is the CA that issued it, and that the broker URL is a name the certificate carries",
			a.broker, verify.Err)
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || !certificateAlerts[op.Err.Error()] {
		return nil
	}
	if leaf := a.leaf(); leaf != nil && !a.now().Before(leaf.NotAfter) {
		return fmt.Errorf("agent: the broker at %s refused this certificate: your certificate expired at %s; "+
			"renew it (%v)", a.broker, leaf.NotAfter.UTC().Format(time.RFC3339), op.Err)
	}
	return fmt.Errorf("agent: the broker at %s refused this certificate (%v); the likely causes: it has expired or "+
		"been revoked, it was issued by a CA other than the broker's client trust anchor (client_ca_file), or it "+
		"does not carry exactly one email address (the broker's log says which)", a.broker, op.Err)
}

// watchedConn is a broker connection that knows whether the broker has ever
// sent it application data.
type watchedConn struct {
	net.Conn
	answered atomic.Bool
}

// tlsState is the TLS connection's state. The transport fills
// http.Response.TLS only for a bare *tls.Conn, which this is not.
func (c *watchedConn) tlsState() (tls.ConnectionState, bool) {
	tc, ok := c.Conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, false
	}
	return tc.ConnectionState(), true
}

func (c *watchedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.answered.Store(true)
	}
	return n, err
}

// do sends req and, when it fails on a connection whose handshake completed
// but which the broker never answered, says so with a *hangUpError.
//
// In TLS 1.3 the client's handshake is done before the broker has checked its
// certificate, so the broker's refusal races the first request: the agent
// may read the alert, or its write may meet the reset of a connection the
// broker already closed, and then the alert is lost and all it has is
// "connection reset by peer" or EOF. A new connection closed before its
// first answer is how a refusal looks when the race is lost. A connection
// that has answered before, a dial failure and a timeout are not.
func (a *Agent) do(req *http.Request) (*http.Response, error) {
	var conn *watchedConn
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		conn, _ = i.Conn.(*watchedConn)
	}}
	resp, err := a.client.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err == nil || conn == nil || conn.answered.Load() {
		return resp, err
	}
	var ne net.Error
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return resp, err
	}
	hup := &hangUpError{broker: a.broker, err: err}
	if leaf := a.leaf(); leaf != nil && !a.now().Before(leaf.NotAfter) {
		hup.expired = leaf.NotAfter
	}
	return resp, hup
}

// hangUpError is a new connection the broker closed after the handshake and
// before any answer: a refused certificate whose alert was lost, or a broker
// that stopped or restarted just then.
// It is a diagnosis, not a verdict, and ends the session only when expired
// is set: the agent's own clock says no broker will take the certificate.
type hangUpError struct {
	broker  string
	err     error
	expired time.Time // the certificate's NotAfter, when it is past
}

func (e *hangUpError) Error() string {
	if !e.expired.IsZero() {
		return fmt.Sprintf("agent: the broker at %s closed a new connection right after the handshake (%v); it "+
			"refused this certificate: your certificate expired at %s; renew it",
			e.broker, e.err, e.expired.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("agent: the broker at %s closed a new connection right after the handshake, before answering "+
		"(%v); either it refused this certificate (it has expired or been revoked, it was issued by a CA other than "+
		"the broker's client trust anchor (client_ca_file), it does not carry exactly one email address, or it is "+
		"not issued for client authentication), or the "+
		"broker stopped or restarted just then; if `port49 token` fails the same way again, it is the certificate",
		e.broker, e.err)
}

func (e *hangUpError) Unwrap() error { return e.err }

// certificateAlerts are the alerts a broker sends about the certificate it
// was shown, by crypto/tls's text for them: its alert type is unexported.
// Any other alert — internal_error, handshake_failure — is a fault on the
// broker's side, handled like an unreachable broker: the session stays up.
var certificateAlerts = map[string]bool{
	"tls: bad certificate":               true,
	"tls: unsupported certificate":       true,
	"tls: revoked certificate":           true,
	"tls: expired certificate":           true,
	"tls: unknown certificate":           true,
	"tls: unknown certificate authority": true,
	"tls: access denied":                 true,
	"tls: certificate required":          true,
}

// leaf is the operator's certificate, parsed; nil when there is none.
func (a *Agent) leaf() *x509.Certificate {
	if a.cert.Leaf != nil {
		return a.cert.Leaf
	}
	if len(a.cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(a.cert.Certificate[0])
	if err != nil {
		return nil
	}
	return leaf
}

// TokenRequest is what `port49 token` sends the agent.
type TokenRequest struct {
	Device     string `json:"device"`
	Enable     bool   `json:"enable"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// Status is GET /status on the agent's socket. CertFingerprint is the
// session's certificate (CertFingerprint). CeilingWarningSeconds is the
// broker's session.ceiling_warning: how near a device's own ceiling
// `port49 token` warns.
type Status struct {
	Broker                string `json:"broker"`
	CertFingerprint       string `json:"cert_fingerprint"`
	SessionEndsAt         string `json:"session_ends_at"`
	Handshakes            int64  `json:"handshakes"`
	CeilingWarningSeconds int    `json:"ceiling_warning_seconds"`
}

// Handler is the agent's socket: POST /token mints one device and answers the
// broker's item; POST /refresh refreshes the session and answers what the
// broker extended; GET /status says whose session this is and when it ends.
// GET /identity, POST /explain and POST /revoke carry the API's
// /v1/identity, /v1/explain and /v1/tokens/revoke over the held connection.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		var req TokenRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.Device == "" {
			writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "name one device"})
			return
		}
		item, err := a.Mint(r.Context(), req.Device, req.Enable, time.Duration(req.TTLSeconds)*time.Second)
		var ie *ItemError
		var revoked *RevokedError
		switch {
		case errors.As(err, &ie):
			// The item as the broker sent it: its error is the client's to
			// report, and Client.Token turns it back into an ItemError.
			writeJSON(w, http.StatusOK, item)
		case errors.As(err, &revoked):
			// Its own code, so the client rebuilds it without the
			// ErrSessionOver text that says to log in.
			writeJSON(w, http.StatusGone, api.Error{Error: "credential_revoked", Detail: revoked.Detail})
		case errors.Is(err, ErrSessionOver):
			writeJSON(w, http.StatusGone, api.Error{Error: "session_over", Detail: err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadGateway, api.Error{Error: "broker_error", Detail: err.Error()})
		default:
			writeJSON(w, http.StatusOK, item)
		}
	})
	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
		out, err := a.Refresh(r.Context())
		var revoked *RevokedError
		switch {
		case errors.As(err, &revoked):
			writeJSON(w, http.StatusGone, api.Error{Error: "credential_revoked", Detail: revoked.Detail})
		case errors.Is(err, ErrSessionOver):
			writeJSON(w, http.StatusGone, api.Error{Error: "session_over", Detail: err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadGateway, api.Error{Error: "refresh_failed", Detail: err.Error()})
		default:
			writeJSON(w, http.StatusOK, out)
		}
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		warn := a.ceilingWarning
		a.mu.Unlock()
		writeJSON(w, http.StatusOK, Status{Broker: a.broker, CertFingerprint: a.fingerprint,
			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes(),
			CeilingWarningSeconds: int(warn / time.Second)})
	})
	mux.HandleFunc("GET /identity", func(w http.ResponseWriter, r *http.Request) {
		out, err := a.Identity(r.Context())
		answer(w, out, err)
	})
	mux.HandleFunc("POST /explain", func(w http.ResponseWriter, r *http.Request) {
		var req api.ExplainRequest
		if err := decodeOne(r.Body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "not an explain request"})
			return
		}
		out, err := a.Explain(r.Context(), req)
		answer(w, out, err)
	})
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		var req api.RevokeRequest
		if err := decodeOne(r.Body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "not a revocation request"})
			return
		}
		out, err := a.Revoke(r.Context(), req)
		answer(w, out, err)
	})
	return mux
}

// decodeOne reads one JSON object, with no unknown fields and nothing after
// it, as the broker reads these bodies: the agent forwards only what it
// decoded, so anything after the object would be dropped in silence.
func decodeOne(body io.Reader, v any) error {
	dec := json.NewDecoder(io.LimitReader(body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// answer writes one API call's result to the socket: out on success; a
// session that is over as POST /token says it (410, the revocation's own
// code kept); a broker refusal, a 503 included, with its own status, body
// and Retry-After, so the client rebuilds the *APIError; anything else 502
// with the agent's error.
//
// 410 is reserved for the agent's own session end, which the client reads
// as ErrSessionOver: a 410 the broker sent is relayed as a 502, so it can
// never say the session is over while the agent's runs on.
func answer(w http.ResponseWriter, out any, err error) {
	var revoked *RevokedError
	var refused *APIError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, out)
	case errors.As(err, &revoked):
		writeJSON(w, http.StatusGone, api.Error{Error: "credential_revoked", Detail: revoked.Detail})
	case errors.Is(err, ErrSessionOver):
		writeJSON(w, http.StatusGone, api.Error{Error: "session_over", Detail: err.Error()})
	case errors.As(err, &refused):
		status := refused.Status
		if status == http.StatusGone {
			status = http.StatusBadGateway
		}
		if refused.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(refused.RetryAfter/time.Second)))
		}
		writeJSON(w, status, api.Error{Error: refused.Code, Detail: refused.Detail})
	default:
		writeJSON(w, http.StatusBadGateway, api.Error{Error: "broker_error", Detail: err.Error()})
	}
}

// drain reads a response to its end before closing it. A body closed unread
// cannot give its connection back, and the next mint would be a new handshake:
// the held connection this package exists to keep.
func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	body.Close()
}

func newKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
