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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/hwkey"
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
	// BundleKept is whether port49 has kept a CA bundle for this broker, so
	// the rotation hint may promise to keep the CA current (RotatedCA).
	BundleKept bool
	// VerifyBroker, when set, is the dialer's tls.Config.VerifyConnection: it
	// runs after the broker's chain verified and before a request is written
	// (brokercrl.Checker.VerifyConnection). Its error ends the connection.
	VerifyBroker func(tls.ConnectionState) error
	// TouchKey is the touch_key slot, nil when none is configured or it did
	// not open. It is the agent's only when it sits on the session key's own
	// token (SameToken); Status says whether it is.
	TouchKey hwkey.Key
	// TouchKeyUnusable is why TouchKey is nil though touch_key is configured
	// (it did not open), for Status.
	TouchKeyUnusable string
	// KeyRef is the session key's reference in canonical form, never a PIN;
	// "" for a file key. `port49 login` compares it before it opens a token.
	KeyRef string
}

// ErrSessionOver is a session that is over: past its ceiling by the agent's
// clock or the broker's, or holding a certificate the broker no longer
// trusts. The answer is `port49 login`.
var ErrSessionOver = errors.New("agent: the session is over; run `port49 login`")

// BrokerRefusedError is a connection Config.VerifyBroker refused, after the
// broker's chain verified and before a request was written: a revoked broker
// certificate, or one whose revocation could not be checked under broker_crl:
// require. It is not a broker that is down, and not a session that is over:
// the next connection checks again.
type BrokerRefusedError struct{ Err error }

func (e *BrokerRefusedError) Error() string { return "agent: " + e.Err.Error() }
func (e *BrokerRefusedError) Unwrap() error { return e.Err }

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

// revokeWait is how long the agent waits on POST /v1/tokens/revoke: the
// broker's wait for its revocation slot (api.RevokeSlotWait), the run it
// bounds at RevokeTimeout, which port49d sets to admin.OpTimeout, the
// revocations_file save (admin.PersistTimeout, headroom as port49d's admin
// socket gives it) and a margin for the answer. Every other call keeps the
// client's thirty seconds, which a revocation behind a slow store outlives:
// the agent would give up on a revocation that went on to finish (final
// review I1).
const revokeWait = api.RevokeSlotWait + admin.OpTimeout + admin.PersistTimeout + revokeAnswerMargin

// revokeAnswerMargin is the time past the broker's bounds a revocation's
// answer is given to arrive.
const revokeAnswerMargin = 10 * time.Second

// revokeTimeout is revokeWait, a var so a test can shorten it.
var revokeTimeout = revokeWait

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
	broker       string
	cert         tls.Certificate
	client       *http.Client
	revokeClient *http.Client // client's transport, no Timeout: Revoke's ctx carries revokeTimeout
	now          func() time.Time
	log          io.Writer
	handshakes   atomic.Int64
	// brokerRoots are the CAs the last handshake verified the broker's
	// certificate to, one per verified chain (BrokerRoots).
	brokerRoots atomic.Pointer[[]*x509.Certificate]
	// fingerprint is the certificate's, as CertFingerprint gives it.
	fingerprint string
	// bundleKept is Config.BundleKept.
	bundleKept bool
	// session is the agent's session: 32 random bytes drawn at New, base64url,
	// sent as api.AgentSessionHeader on every broker request (decision 45
	// ruling 15). It is a credential of sorts: never logged, never in Status.
	session string
	// key is the session key when it is a hardware key, nil for a file key.
	key hwkey.Key
	// touch is the touch key when it is usable (same token as key), else
	// nil; touchUnusable says why not when touch_key is configured.
	touch         hwkey.Key
	touchUnusable string
	keyRef        string

	// wire is the held connection's one slot (plan 7d, Ruling 15): one
	// exchange at a time, which the transport did already, now with the
	// agent knowing what holds it. revoking is when a revocation took it,
	// in Unix nanoseconds; 0 when none holds it.
	wire     chan struct{}
	revoking atomic.Int64

	mu       sync.Mutex
	deadline time.Time
	// ceilingWarning is /v1/config's ceiling_warning_seconds: how near a
	// device's own ceiling `port49 token` warns.
	ceilingWarning time.Duration
	// refreshed is the last refresh's per-context answer, for GET /status.
	// A refresh replaces it whole, never edits it.
	refreshed []api.RefreshedSession

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
	a := &Agent{broker: strings.TrimRight(c.BrokerURL, "/"), now: c.Now, log: c.Log, bundleKept: c.BundleKept,
		done:            make(chan struct{}),
		deadlineChanged: make(chan struct{}, 1), wire: make(chan struct{}, 1)}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = io.Discard
	}
	var session [32]byte
	_, _ = rand.Read(session[:]) // crypto/rand.Read does not return an error (Go 1.24)
	a.session = base64.RawURLEncoding.EncodeToString(session[:])
	a.cert = c.Cert
	a.fingerprint = CertFingerprint(c.Cert)
	a.keyRef = c.KeyRef
	a.key, _ = c.Cert.PrivateKey.(hwkey.Key)
	a.touchUnusable = c.TouchKeyUnusable
	if c.TouchKey != nil {
		if ok, why := SameToken(c.Cert.PrivateKey, c.TouchKey); ok {
			a.touch = c.TouchKey
		} else {
			a.touchUnusable = why
			// A touch key that is not the session's token's is not used and
			// holds nothing open.
			_ = c.TouchKey.Close()
		}
	}
	cert := c.Cert
	var verify func(tls.ConnectionState) error
	if c.VerifyBroker != nil {
		verify = func(cs tls.ConnectionState) error {
			if err := c.VerifyBroker(cs); err != nil {
				return &BrokerRefusedError{Err: err}
			}
			return nil
		}
	}
	dialer := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.BrokerCA,
		VerifyConnection: verify,
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
			if tc, ok := conn.(*tls.Conn); ok {
				if roots := chainRoots(tc.ConnectionState().VerifiedChains); len(roots) > 0 {
					a.brokerRoots.Store(&roots)
				}
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
	a.revokeClient = &http.Client{Transport: tr}
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
	// Connect runs before the socket listens, so nothing contends for the wire yet.
	if err := a.takeWire(ctx, false, "connected", "port49 login"); err != nil {
		return api.Config{}, err
	}
	defer a.giveWire(false)
	resp, err := a.do(req)
	if err != nil {
		if refused := a.refusal(err); refused != nil {
			return api.Config{}, refused
		}
		var hup *hangUpError
		if errors.As(err, &hup) {
			return api.Config{}, hup
		}
		var no *BrokerRefusedError
		if errors.As(err, &no) {
			return api.Config{}, no
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

// chainRoots is the root of every verified chain, each once. A rotation by
// cross-signing verifies the server's certificate to the old root and the new
// one, and which comes first is not the broker's to choose.
func chainRoots(chains [][]*x509.Certificate) []*x509.Certificate {
	var roots []*x509.Certificate
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		if !slices.ContainsFunc(roots, root.Equal) {
			roots = append(roots, root)
		}
	}
	return roots
}

// BrokerRoots are the CAs the last handshake verified the broker's
// certificate to, one per verified chain; nil before one. A CA bundle the
// broker sends must hold any one of them (decision 43 ruling 25).
func (a *Agent) BrokerRoots() []*x509.Certificate {
	if p := a.brokerRoots.Load(); p != nil {
		return slices.Clone(*p)
	}
	return nil
}

// RotatedCAHint is the fix for a broker certificate no CA this host trusts
// issued, said on the same line: a host away through a whole CA rotation
// (decision 43 ruling 25).
//
// It promises that port49 keeps the CA current only where it can: a broker
// that sends no CA bundle leaves nothing to keep, so the promise (RotatedCAHintKept)
// is made only where a bundle was kept for this broker, which is a broker
// known to send one. Anywhere else the fix is the file the host was given.
const RotatedCAHint = rotatedCAFix + "; ask for /etc/port49/broker-ca.pem to be updated"

// RotatedCAHintKept is RotatedCAHint for a broker whose CA bundle port49 has
// kept: the next login keeps the new CA current from the bundle the broker
// sends.
const RotatedCAHintKept = rotatedCAFix + "; port49 keeps it current from then on"

const rotatedCAFix = "if the broker's operator rotated its CA while this host was away, get the broker's CA from " +
	"them and run `port49 login --broker-ca FILE` once"

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
		if err := a.takeWire(ctx, false, "minted", "port49 token"); err != nil {
			return api.MintItem{}, err
		}
		if resp, err = a.post(ctx, body, key); err != nil {
			a.giveWire(false)
			return api.MintItem{}, err
		}
		if resp.StatusCode != http.StatusConflict {
			break // the wire is held through this answer's read, and given back below
		}
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		drain(resp.Body)
		// Given back across the wait: a revocation sent now goes at once,
		// never behind a mint that is only sleeping.
		a.giveWire(false)
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
	defer a.giveWire(false)
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
		// The check refused the broker's certificate: said as that, not
		// retried, and the session stays up (a CRL blip must not end it).
		var no *BrokerRefusedError
		if errors.As(err, &no) {
			return nil, no
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
		if strings.Contains(e.Detail, api.UncoveredStatus) {
			return "agent: " + e.Detail // final until the operator acts: no "retry in"
		}
		return "agent: " + e.Detail + retryIn(e.RetryAfter)
	case e.Status == http.StatusServiceUnavailable:
		return "agent: the broker is unavailable just now: " + e.Code + ": " + e.Detail + retryIn(e.RetryAfter)
	}
	return "agent: the broker refused: " + e.Code + ": " + e.Detail + retryIn(e.RetryAfter)
}

// wireWait bounds how long a call that is not a revocation waits for
// the held connection: the budget it had before plan 7d, when it
// queued in the transport under the client's 30s timeout.
var wireWait = 30 * time.Second

// RevocationRunningError is a call that waited wireWait for the held
// connection while a revocation the operator sent held it: nothing was
// sent, and the revocation is still the broker's to answer. Undone and
// Again name what was not done and the command to run again; Detail is
// the whole line, when it came back through the agent's socket.
type RevocationRunningError struct {
	Since         time.Time
	Undone, Again string
	Detail        string
}

func (e *RevocationRunningError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("your revocation sent at %s is still running on the broker; nothing was %s; run %s "+
		"again once port49 revoke reports", e.Since.Local().Format("15:04:05"), e.Undone, e.Again)
}

// takeWire waits for the held connection. A revocation waits as long as
// its ctx lets it and marks the wire as its own; any other call waits
// wireWait, and if a revocation still holds it then, says so, naming
// what it did not do (undone) and the command to run again (again).
func (a *Agent) takeWire(ctx context.Context, revocation bool, undone, again string) error {
	wait := ctx
	if !revocation {
		var cancel context.CancelFunc
		wait, cancel = context.WithTimeout(ctx, wireWait)
		defer cancel()
	}
	select {
	case a.wire <- struct{}{}:
	case <-wait.Done():
		if since := a.revoking.Load(); since != 0 && ctx.Err() == nil {
			return &RevocationRunningError{Since: time.Unix(0, since), Undone: undone, Again: again}
		}
		if revocation && a.revoking.Load() != 0 {
			// Its own timeout ran out behind another revocation: nothing of
			// it reached the broker, so it is not unanswered.
			return errors.New("agent: an earlier revocation still held the connection; this one was not sent")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("agent: the connection to the broker at %s was busy for %v", a.broker, wireWait)
	}
	if revocation {
		a.revoking.Store(a.now().UnixNano())
	}
	return nil
}

func (a *Agent) giveWire(revocation bool) {
	if revocation {
		a.revoking.Store(0)
	}
	<-a.wire
}

// call sends one request on the held connection and decodes a 200 into out.
// A refusal that ends the session ends it here, as a mint's does; anything
// else, a 503 included, is an *APIError, so a caller can tell
// revocation_busy from api_right_missing by its code. A transport failure
// is tried once more on a new connection, as post does: identity and
// explain read, and are safe to repeat.
func (a *Agent) call(ctx context.Context, method, path string, in, out any) error {
	return a.exchange(ctx, a.client, nil, method, path, in, out)
}

// exchange is call on client c. With unanswered set, a request whose
// writing began is never sent again: a transport failure after it, a
// timeout included, is unanswered's error, since the broker may have acted
// on it. Only a failure before any byte left the agent (a dial, a handshake,
// a connection that dropped before the write) is tried again. The
// transport's own retry of a held connection it finds closed is the same
// rule: it repeats a request only when nothing of it was written.
//
// hangUpError cannot tell the two apart: it means the broker never
// answered, not that nothing was written. WroteHeaders can: the request
// line and headers, a few hundred bytes, are buffered whole in the
// transport's 4 KiB writer and reach the connection only after it fires.
func (a *Agent) exchange(ctx context.Context, c *http.Client, unanswered func(error) error,
	method, path string, in, out any) error {
	select {
	case <-a.done:
		return ErrSessionOver
	default:
	}
	if ends := a.SessionEndsAt(); ends.IsZero() || !a.now().Before(ends) {
		return ErrSessionOver
	}
	revocation := unanswered != nil // only Revoke passes one, and it never gets the error
	if err := a.takeWire(ctx, revocation, "asked", "port49 "+strings.TrimPrefix(path, "/v1/")); err != nil {
		return err
	}
	defer a.giveWire(revocation)
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
		var sent atomic.Bool
		traced := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }})
		req, err := http.NewRequestWithContext(traced, method, a.broker+path, rd)
		if err != nil {
			return err
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if resp, err = a.doOn(c, req); err == nil {
			break
		}
		a.client.CloseIdleConnections()
		if over := a.refusedReconnect(err); over != nil {
			return over
		}
		var no *BrokerRefusedError
		if errors.As(err, &no) {
			return no
		}
		if unanswered != nil && sent.Load() {
			return unanswered(err)
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
			if unanswered != nil {
				// A 200 with no answer in it, from an intermediary: the
				// broker may still have acted.
				return unanswered(fmt.Errorf("its 200 did not decode: %w", err))
			}
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
//
// It waits revokeTimeout, past the broker's worst case, and is never sent
// twice once written: a revocation the broker did not answer may be in
// force, and is said so (UnansweredRevokeError), never retried into a
// revocation_busy that would say nothing was revoked (final review I1).
func (a *Agent) Revoke(ctx context.Context, req api.RevokeRequest) (api.RevokeResponse, error) {
	var out api.RevokeResponse
	ctx, cancel := context.WithTimeout(ctx, revokeTimeout)
	defer cancel()
	unanswered := func(err error) error {
		return &UnansweredRevokeError{Who: "the broker at " + a.broker, Principal: req.Principal != "", Err: err}
	}
	if err := a.exchange(ctx, a.revokeClient, unanswered, http.MethodPost, "/v1/tokens/revoke", req, &out); err != nil {
		return out, err
	}
	if out.By == "" {
		// The broker always says what it revoked: a 200 that names
		// nothing ({}, null) is an intermediary's, and the broker may
		// still have acted.
		return api.RevokeResponse{}, unanswered(errors.New("its 200 named no revocation"))
	}
	return out, nil
}

// UnansweredRevokeError is a revocation sent and never answered, by the
// broker or by the agent: it may have run, and the operator looks before
// asking again. Its text is port49 revoke's on the admin socket for the same
// case. A self or key revocation leaves no mark for --list to show; the
// decision log names it.
type UnansweredRevokeError struct {
	Who       string // who did not answer: "the broker at …", "your agent at …"
	Principal bool   // a revocation of a principal, which leaves a standing mark
	Err       error
}

func (e *UnansweredRevokeError) Error() string {
	if e.Principal {
		return fmt.Sprintf("agent: %s did not answer the revocation (%v); it may be in force — check `port49 "+
			"revoke --list` (on port49d's host) and port49d's log before retrying", e.Who, e.Err)
	}
	return fmt.Sprintf("agent: %s did not answer the revocation (%v); it may have run — check port49d's "+
		"decision log (event revoke) before retrying", e.Who, e.Err)
}

func (e *UnansweredRevokeError) Unwrap() error { return e.Err }

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
		if strings.Contains(e.Detail, api.UncoveredStatus) {
			return fmt.Errorf("agent: %s", e.Detail) // final until the operator acts: no "retry in"
		}
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
// minute, is tried once more, and so is a challenge that met a transport
// failure.
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
	if err := a.takeWire(ctx, false, "refreshed", "port49 refresh"); err != nil {
		return api.RefreshResponse{}, false, err
	}
	defer a.giveWire(false)
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
		var no *BrokerRefusedError
		if errors.As(err, &no) {
			return api.RefreshResponse{}, false, no
		}
		// Anything else is tried once more on a new connection, as a mint
		// is: a held connection the broker closed as the challenge went out
		// on it is the network or a restarting broker, not an answer.
		a.client.CloseIdleConnections()
		return api.RefreshResponse{}, true, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
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
		var no *BrokerRefusedError
		if errors.As(err, &no) {
			return api.RefreshResponse{}, false, no
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
	a.refreshed = out.Sessions
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
			"(--broker-ca) is the CA that issued it, and that the broker URL is a name the certificate carries%s",
			a.broker, verify.Err, RotatedCA(verify.Err, a.bundleKept))
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
func (a *Agent) do(req *http.Request) (*http.Response, error) { return a.doOn(a.client, req) }

// doOn is do on client c, which shares a.client's transport.
func (a *Agent) doOn(c *http.Client, req *http.Request) (*http.Response, error) {
	req.Header.Set(api.AgentSessionHeader, a.session)
	var conn *watchedConn
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		conn, _ = i.Conn.(*watchedConn)
	}}
	resp, err := c.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
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

// RotatedCA is RotatedCAHint after "; " for a certificate no CA this host
// trusts issued, and "" for any other failure. kept is whether port49 has
// kept a CA bundle for this broker, which makes it RotatedCAHintKept.
func RotatedCA(err error, kept bool) string {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		if kept {
			return "; " + RotatedCAHintKept
		}
		return "; " + RotatedCAHint
	}
	return ""
}

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

// CertificateEnd is the session certificate's notAfter, zero for none (plan
// 9b; spec §13 decision 43 ruling 21). Past it the broker refuses every
// request on the connection (Identity), so the agent process exits there
// (agentMain); a device session a refresh extended runs to its own ceiling
// (spec §5.1.4).
func (a *Agent) CertificateEnd() time.Time {
	if leaf := a.leaf(); leaf != nil {
		return leaf.NotAfter
	}
	return time.Time{}
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
	// Sessions is the last refresh's answer per live context, absent before
	// one: what `port49 ssh` reads when its in-session warning is due, so a
	// `port49 refresh` in another terminal moves it (decision 42 ruling 11).
	Sessions []api.RefreshedSession `json:"sessions,omitempty"`
	// KeyState is whether the session key can sign now: present, absent or
	// locked; "present" for a file key.
	KeyState string `json:"key_state"`
	// TouchKey is true only when the touch key opened and sits on the same
	// token (module and token serial) as a pkcs11 session key (ruling 12);
	// TouchKeyUnusable says why not when touch_key is configured.
	TouchKey         bool   `json:"touch_key"`
	TouchKeyUnusable string `json:"touch_key_unusable,omitempty"`
	// KeyRef is the session key's reference in canonical form (never a PIN),
	// "" for a file key: what login compares before it opens a token.
	KeyRef string `json:"key_ref,omitempty"`
}

// TokenKey is a key on a PKCS#11 token: the module it was opened through and
// the token's serial name the token (pkcs11.Signer's methods).
type TokenKey interface {
	ModulePath() string
	TokenSerial() string
}

// SameToken reports whether touch sits on the same token as session, the
// session key, by module and token serial (decision 45 ruling 12). When it
// does not, why says so. The PIN is only ever sent to a key for which this is
// true: another token's PIN tries are not the agent's to spend.
func SameToken(session any, touch hwkey.Key) (ok bool, why string) {
	s, sok := session.(TokenKey)
	t, tok := touch.(TokenKey)
	switch {
	case !sok:
		return false, "touch_key needs a pkcs11 session key: this session's key is not on a PKCS#11 token"
	case !tok:
		return false, "touch_key is not a PKCS#11 key"
	case s.ModulePath() != t.ModulePath() || s.TokenSerial() != t.TokenSerial():
		return false, "touch_key is on another token than the session key; it must be on the same token"
	}
	return true, ""
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
		case errors.As(err, new(*RevocationRunningError)):
			// Not the broker failing: the operator's own revocation is still
			// running, and nothing was minted.
			writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "revocation_running", Detail: err.Error()})
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
		case errors.As(err, new(*RevocationRunningError)):
			writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "revocation_running", Detail: err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadGateway, api.Error{Error: "refresh_failed", Detail: err.Error()})
		default:
			writeJSON(w, http.StatusOK, out)
		}
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		warn, sessions := a.ceilingWarning, a.refreshed
		a.mu.Unlock()
		writeJSON(w, http.StatusOK, Status{Broker: a.broker, CertFingerprint: a.fingerprint,
			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes(),
			CeilingWarningSeconds: int(warn / time.Second), Sessions: sessions,
			KeyState: a.keyState(), TouchKey: a.touch != nil, TouchKeyUnusable: a.touchUnusable, KeyRef: a.keyRef})
	})
	mux.HandleFunc("POST /unlock", a.unlock)
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

// keyState is the session key's State, "present" for a file key.
func (a *Agent) keyState() string {
	if a.key == nil {
		return hwkey.Present.String()
	}
	return a.key.State().String()
}

// Unlock's limits: a PIN is at most maxPIN bytes inside a body of at most
// maxUnlockBody.
const (
	maxPIN        = 64
	maxUnlockBody = 256
)

// UnlockRefusal is POST /unlock's 401 pin_refused body: the token's own
// tries-left flags, which the client rebuilds as a *hwkey.PINError.
type UnlockRefusal struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
	Low    bool   `json:"low,omitempty"`
	Final  bool   `json:"final,omitempty"`
}

// unlock is POST /unlock {"pin": "…"}: the PIN goes to the session key and,
// when it is on the same token, the touch key. The body and the PIN are read
// as bytes and zeroed: a Go string cannot be, and the PIN is in nothing the
// agent logs or returns.
func (a *Agent) unlock(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxUnlockBody+1))
	defer clear(body)
	pin, ok := unlockPIN(body, err)
	defer clear(pin)
	if !ok {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "send {\"pin\": \"…\"}, a PIN of 1 to 64 bytes"})
		return
	}
	if a.key == nil {
		writeJSON(w, http.StatusOK, struct{}{}) // a file key has nothing to unlock
		return
	}
	// Each Unlock zeroes the PIN it is given, so each gets its own copy.
	err = a.key.Unlock(slices.Clone(pin))
	if err == nil && a.touch != nil {
		if terr := a.touch.Unlock(slices.Clone(pin)); terr != nil {
			fmt.Fprintf(a.log, "port49 agent: the touch key stayed locked: %v\n", terr)
		}
	}
	var pe *hwkey.PINError
	switch {
	case err == nil:
		fmt.Fprintf(a.log, "port49 agent: the key was unlocked\n")
		writeJSON(w, http.StatusOK, struct{}{})
	case errors.As(err, &pe):
		detail := "the token refused the PIN"
		switch {
		case pe.Final:
			detail += "; one try is left before the key locks"
		case pe.Low:
			detail += "; fewer tries are left"
		}
		writeJSON(w, http.StatusUnauthorized, UnlockRefusal{Error: "pin_refused", Detail: detail, Low: pe.Low, Final: pe.Final})
	case errors.Is(err, hwkey.ErrKeyAbsent):
		writeJSON(w, http.StatusConflict, api.Error{Error: "key_absent", Detail: "the key is not present: insert it"})
	default:
		writeJSON(w, http.StatusBadGateway, api.Error{Error: "unlock_failed", Detail: err.Error()})
	}
}

// unlockPIN reads the pin field of {"pin": "…"} out of body as bytes: the
// JSON string is cut from a json.RawMessage and unescaped by hand, since
// decoding into a Go string would leave a copy that cannot be zeroed. Only
// the escapes \" and \\ are understood, which are the two Client.Unlock
// writes. The caller zeroes the returned PIN.
func unlockPIN(body []byte, readErr error) (pin []byte, ok bool) {
	if readErr != nil || len(body) > maxUnlockBody {
		return nil, false
	}
	var f struct {
		PIN json.RawMessage `json:"pin"`
	}
	err := json.Unmarshal(body, &f)
	raw := f.PIN
	defer clear(raw)
	if err != nil || len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	for i := 1; i < len(raw)-1; i++ {
		c := raw[i]
		if c == '\\' {
			i++
			if i >= len(raw)-1 || (raw[i] != '"' && raw[i] != '\\') {
				clear(pin)
				return nil, false
			}
			c = raw[i]
		}
		if len(pin) == maxPIN {
			clear(pin)
			return nil, false
		}
		pin = append(pin, c)
	}
	return pin, len(pin) > 0
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
	case errors.As(err, new(*RevocationRunningError)):
		writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "revocation_running", Detail: err.Error()})
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
