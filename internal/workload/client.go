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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/keyfile"
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

// Config is a workload's broker and its certificate files.
type Config struct {
	Broker            string // https://host:port
	BrokerCA          *x509.CertPool
	CertFile, KeyFile string
	Deadline          time.Duration // 0 is DefaultDeadline
	Now               func() time.Time
	// Warn says a late renewal; nil says nothing.
	Warn func(format string, args ...any)
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
func LoadCertificate(certFile, keyFile string, now time.Time, warn func(string, ...any)) (tls.Certificate, error) {
	var cert tls.Certificate
	var err error
	for i := range 3 {
		if cert, err = keyfile.LoadX509KeyPair(certFile, keyFile); err == nil ||
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
			strings.TrimSuffix(leaf.NotAfter.Sub(now).Round(time.Minute).String(), "0s"))
	}
	cert.Leaf = leaf
	return cert, nil
}

// Client is one run's connection to the broker.
type Client struct {
	cfg   Config
	http  *http.Client
	sleep func(ctx context.Context, d time.Duration) error
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
	cert, err := LoadCertificate(cfg.CertFile, cfg.KeyFile, cfg.Now(), cfg.Warn)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cfg.BrokerCA,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}}
	return &Client{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}, sleep: sleepCtx}, nil
}

// MintOptions is one run's mint.
type MintOptions struct {
	Devices []string
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
	var conf api.Config
	if err := c.do(ctx, deadline, http.MethodGet, "/v1/config", nil, "", &conf); err != nil {
		return api.MintResponse{}, unminted(err, o.Devices)
	}
	page := max(conf.BatchMax, 1)
	var out api.MintResponse
	for i := 0; i < len(o.Devices); i += page {
		devs := o.Devices[i:min(i+page, len(o.Devices))]
		body, err := json.Marshal(api.MintRequest{Devices: devs, Enable: o.Enable,
			TTLSeconds: int(o.TTL / time.Second), Purpose: o.Purpose})
		if err != nil {
			return out, err
		}
		key, err := newKey()
		if err != nil {
			return out, err
		}
		var resp api.MintResponse
		if err := c.do(ctx, deadline, http.MethodPost, "/v1/tokens", body, key, &resp); err != nil {
			return out, unminted(err, o.Devices[i:])
		}
		if out.Principal == "" {
			out.Principal, out.Subject, out.Subjects = resp.Principal, resp.Subject, resp.Subjects
		}
		out.Results = append(out.Results, resp.Results...)
	}
	return out, nil
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
// cannot answer now: a 503 (but an uncovered certificate status), a 429, a
// 409 idempotency_in_progress after its Retry-After (5s when absent, 60s at
// most), a failed connection after 1s doubling to 30s; until deadline. Any
// other answer is final.
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
		var last error
		var pause time.Duration
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			last, pause = fmt.Errorf("no answer: %w", err), wait
			wait = min(wait*2, 30*time.Second)
		} else {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// The decoder's error names a position or a type, never the body.
				if err := json.Unmarshal(raw, out); err != nil {
					return fmt.Errorf("the broker's answer to %s is not JSON: %w", path, err)
				}
				return nil
			}
			var e api.Error
			_ = json.Unmarshal(raw, &e)
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
	return status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests ||
		(status == http.StatusConflict && e.Error == "idempotency_in_progress")
}

func retryAfter(h http.Header) time.Duration {
	if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 {
		return min(time.Duration(s)*time.Second, time.Minute)
	}
	return 5 * time.Second
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
