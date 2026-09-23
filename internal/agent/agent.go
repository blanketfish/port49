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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// connectTimeout bounds Connect: the dial and the handshake that is the
// session's one use of the key. It is inside `port49 login`'s 15-second wait,
// so a broker that never answers is reported through the agent's own log
// rather than by login giving up on a silent agent (pre-flight F9). A var so
// a test can shorten it.
var connectTimeout = 10 * time.Second

// Agent is one operator session.
type Agent struct {
	broker     string
	cert       tls.Certificate
	client     *http.Client
	now        func() time.Time
	log        io.Writer
	handshakes atomic.Int64

	mu       sync.Mutex
	deadline time.Time

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
	a := &Agent{broker: strings.TrimRight(c.BrokerURL, "/"), now: c.Now, log: c.Log, done: make(chan struct{})}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = io.Discard
	}
	a.cert = c.Cert
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
			return conn, nil
		},
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	a.client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return a
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
	resp, err := a.client.Do(req)
	if err != nil {
		if refused := a.refusal(err); refused != nil {
			return api.Config{}, refused
		}
		return api.Config{}, fmt.Errorf("agent: connecting to the broker at %s: %w", a.broker, err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return api.Config{}, fmt.Errorf("agent: %s/v1/config answered %s", a.broker, resp.Status)
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
	a.mu.Unlock()
	return c, nil
}

// SessionEndsAt is when this session ends; zero before Connect.
func (a *Agent) SessionEndsAt() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deadline
}

// Handshakes is how many connections this session has opened.
func (a *Agent) Handshakes() int64 { return a.handshakes.Load() }

// Done is closed when the broker ends the session — it answered
// session_expired, or it no longer trusts the certificate. The agent process
// exits on it, so the next `port49 login` starts a new session instead of
// finding this one "already logged in" (pre-flight F10).
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
// §17). A 401 session_expired or trust_domain_unresolved ends the session,
// and so does a reconnect whose handshake the broker refuses. An item the
// broker could not decide is returned with an *ItemError, never alone.
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
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.broker+"/v1/tokens", bytes.NewReader(body))
		if err != nil {
			return api.MintItem{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err = a.client.Do(req)
		if err == nil {
			break
		}
		a.client.CloseIdleConnections()
		if refused := a.refusal(err); refused != nil {
			// A reconnect whose handshake failed: the certificate expired
			// or the trust changed under the session, and no retry will
			// mint (Ruling Q1; pre-flight F10).
			over := fmt.Errorf("%w: %s", ErrSessionOver, strings.TrimPrefix(refused.Error(), "agent: "))
			a.end(over)
			return api.MintItem{}, over
		}
		if attempt == 2 {
			return api.MintItem{}, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
		}
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if resp.StatusCode == http.StatusUnauthorized {
			var over error
			switch e.Error {
			case "session_expired":
				over = ErrSessionOver
			case "trust_domain_unresolved":
				// The certificate expired, or stopped verifying, under the
				// held connection: nothing this session can do will mint
				// again (spec §13, decision 12).
				over = fmt.Errorf("%w: the broker no longer trusts this certificate (%s)", ErrSessionOver, e.Detail)
			}
			if over != nil {
				a.end(over)
				return api.MintItem{}, over
			}
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

// ItemError is a device the broker could not decide: a fault on its side or
// in its inventory, not a refusal of the operator (design §17). It carries
// the broker's code and detail; the operator's answer is usually to tell
// whoever runs port49d.
type ItemError struct {
	Device, Code, Detail string
}

func (e *ItemError) Error() string {
	what := map[string]string{
		"device_unconfigured":  "the broker's inventory does not configure this device",
		"broker_error":         "the broker failed",
		"bad_request":          "the broker refused the request",
		"idempotency_conflict": "the broker holds a different request under this request's key",
	}[e.Code]
	if what == "" {
		what = "the broker could not answer"
	}
	return fmt.Sprintf("agent: no token for %s: %s (%s): %s", e.Device, what, e.Code, e.Detail)
}

// refusal says what a failed handshake most likely means, or nil for an
// error that is not one: a broker that is down or unreachable is left to the
// caller's own message. In TLS 1.3 the broker rejects a client certificate
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
	if !errors.As(err, &op) || op.Op != "remote error" {
		return nil
	}
	if leaf := a.leaf(); leaf != nil && !a.now().Before(leaf.NotAfter) {
		return fmt.Errorf("agent: the broker at %s refused this certificate: your certificate expired at %s; "+
			"renew it (%v)", a.broker, leaf.NotAfter.UTC().Format(time.RFC3339), op.Err)
	}
	return fmt.Errorf("agent: the broker at %s refused this certificate (%v); the likely causes: it has expired or "+
		"been revoked, or it was issued by a CA other than the broker's client trust anchor (client_ca_file)",
		a.broker, op.Err)
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

// Status is GET /status on the agent's socket.
type Status struct {
	Broker        string `json:"broker"`
	SessionEndsAt string `json:"session_ends_at"`
	Handshakes    int64  `json:"handshakes"`
}

// Handler is the agent's socket: POST /token mints one device and answers the
// broker's item; GET /status says whose session this is and when it ends.
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
		switch {
		case errors.As(err, &ie):
			// The item as the broker sent it: its error is the client's to
			// report, and Client.Token turns it back into an ItemError.
			writeJSON(w, http.StatusOK, item)
		case errors.Is(err, ErrSessionOver):
			writeJSON(w, http.StatusGone, api.Error{Error: "session_over", Detail: err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadGateway, api.Error{Error: "broker_error", Detail: err.Error()})
		default:
			writeJSON(w, http.StatusOK, item)
		}
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Status{Broker: a.broker,
			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes()})
	})
	return mux
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
