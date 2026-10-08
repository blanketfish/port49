// Package certstatus answers whether a client certificate, or any
// certificate above it in its verified chain but the anchor, is revoked,
// from the CRLs and OCSP responder port49d's broker.certificate_status names
// (spec §5.1.4; decision 33). A CRL is verified against its source's
// issuer certificate before anything uses it; an OCSP answer is held to RFC
// 6960's responder and freshness rules. It decides nothing about policy:
// the broker reads its Result.
package certstatus

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Verdict is a certificate's status.
type Verdict int

const (
	Good Verdict = iota
	Revoked
	Unknown
)

func (v Verdict) String() string { return [...]string{"good", "revoked", "unknown"}[v] }

// Result is one Check: the chain's verdict, the source that gave it and
// its name, the depth and subject of the certificate that decided (0, the
// leaf), when it was revoked, whether that is a hold, and for Unknown why.
type Result struct {
	Verdict   Verdict
	Source    string // "crl", "ocsp", or "none"
	Name      string
	Depth     int
	Subject   string
	RevokedAt time.Time
	Hold      bool
	Detail    string
}

type CRLSource struct {
	Name, File, URL string
	Issuer          *x509.Certificate // the CA that signs the list (issuer_file)
}

type OCSPConfig struct {
	Responder string
	UseAIA    bool
	Timeout   time.Duration
	Hash      crypto.Hash // crypto.SHA256, or crypto.SHA1 (ocsp.hash)
}

type Config struct {
	CRLs            []CRLSource
	OCSP            *OCSPConfig
	RefreshInterval time.Duration
	StateDir        string // where each verified list is kept, crl-<name>.der
}

// The configuration's defaults, for a Config built without them.
const (
	defaultRefresh     = 10 * time.Minute
	defaultOCSPTimeout = 2 * time.Second
	sayEvery           = 10 * time.Minute
)

// Checker holds each source's last good list and the OCSP answers still
// fresh. It is safe for concurrent use.
type Checker struct {
	cfg   Config
	now   func() time.Time
	m     *metrics.Metrics
	logf  func(string, ...any)
	http  *http.Client
	after func(time.Duration) <-chan time.Time

	mu    sync.Mutex
	crls  map[string]*loadedCRL
	onNew func(issuer, serial, source string, bulk bool)
	// failing is, by source, whether its last load failed: the next good
	// one is said (loaded).
	failing      map[string]bool
	ocsp         map[string]ocspEntry
	ocspInflight map[string]*ocspCall
	said         map[string]time.Time
}

// New builds a Checker with nothing loaded: LoadPersisted, then Run, put
// lists in force. logf says its lines, each begun "broker: certificate
// status: ", for the caller to begin with its process's name.
func New(cfg Config, now func() time.Time, m *metrics.Metrics, logf func(string, ...any)) *Checker {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = defaultRefresh
	}
	if cfg.OCSP != nil {
		o := *cfg.OCSP
		if o.Timeout <= 0 {
			o.Timeout = defaultOCSPTimeout
		}
		if o.Hash == 0 {
			o.Hash = crypto.SHA256 // ocsp.CreateRequest's own default is SHA-1
		}
		cfg.OCSP = &o
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Checker{cfg: cfg, now: now, m: m, logf: logf, after: time.After,
		http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("a status source does not redirect")
		}},
		crls: map[string]*loadedCRL{}, failing: map[string]bool{}, ocsp: map[string]ocspEntry{}, ocspInflight: map[string]*ocspCall{},
		said: map[string]time.Time{}}
}

// OnNewEntry sets f to be told of each serial a verified list newly names
// over its source's last good list, a certificateHold entry excepted.
// bulk is true when the entries are a whole list rather than news: a kept
// list put in force again at start (LoadPersisted), whose entries were each
// told before, or a source's first list, every entry of which is new only to
// this process (final review M-6).
func (c *Checker) OnNewEntry(f func(issuer, serial, source string, bulk bool)) {
	c.mu.Lock()
	c.onNew = f
	c.mu.Unlock()
}

// Check is the chain's status (pre-flight I2). chain is a verified chain,
// leaf first and the anchor last. Each certificate but the anchor is
// checked against the one above it: the first Revoked decides, with its
// depth; otherwise the first Unknown decides; otherwise Good.
func (c *Checker) Check(ctx context.Context, chain []*x509.Certificate) Result {
	if len(chain) == 0 {
		res := Result{Verdict: Unknown, Source: "none", Detail: "no certificate to check"}
		c.m.CertStatusChecks.WithLabelValues(res.Source, res.Verdict.String()).Inc()
		c.m.CertStatusUnavailable.Inc()
		return res
	}
	var res Result
	unknown := -1
	var unknownRes Result
	last := len(chain) - 1
	if last == 0 {
		last = 1 // a lone self-issued leaf is checked against itself
	}
	for i := 0; i < last; i++ {
		cert, issuer := chain[i], chain[min(i+1, len(chain)-1)]
		r := c.checkOne(ctx, cert, issuer, i)
		r.Depth = i
		if i > 0 {
			r.Subject = printsafe.Line(cert.Subject.String(), 200)
		}
		if r.Verdict == Revoked {
			res = r
			break
		}
		if r.Verdict == Unknown && unknown < 0 {
			unknown, unknownRes = i, r
		}
		if i == 0 {
			res = r
		}
	}
	if res.Verdict != Revoked && unknown >= 0 {
		res = unknownRes
	}
	c.m.CertStatusChecks.WithLabelValues(res.Source, res.Verdict.String()).Inc()
	if res.Verdict == Unknown {
		c.m.CertStatusUnavailable.Inc()
	}
	return res
}

// checkOne is one certificate's status against its issuer: a verified list
// that names it is final; a fresh one that does not is Good; then OCSP. A
// responder that applies to cert but failed is an outage, said first and
// never in the API's uncovered words, so the broker says try again and port49
// workload retries; one that does not apply leaves an uncovered issuer
// uncovered (decision 40, ruling 10).
func (c *Checker) checkOne(ctx context.Context, cert, issuer *x509.Certificate, depth int) Result {
	res := c.checkCRLs(cert, issuer, depth)
	if res.Verdict == Unknown && c.cfg.OCSP != nil {
		o := c.checkOCSP(ctx, cert, issuer)
		if o.Verdict != Unknown {
			return o
		}
		if strings.HasSuffix(o.Detail, ": "+ocspNoResponder) {
			res.Detail = res.Detail + "; " + o.Detail
		} else {
			res.Detail = o.Detail + "; " + strings.Replace(res.Detail, api.UncoveredStatus, "no fresh CRL covers", 1)
		}
	}
	return res
}

// Describe names each source, with its list's next update, and the
// responder, for port49d's start line.
func (c *Checker) Describe() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var parts []string
	for _, src := range c.cfg.CRLs {
		state := "not loaded yet"
		if l := c.crls[src.Name]; l != nil {
			state = "next update " + c.nextUpdate(l).UTC().Format(time.RFC3339)
		}
		parts = append(parts, fmt.Sprintf("CRL %s (%s)", src.Name, state))
	}
	if o := c.cfg.OCSP; o != nil {
		if o.Responder != "" {
			parts = append(parts, "OCSP "+printsafe.Line(redactURL(o.Responder), 120))
		} else {
			parts = append(parts, "OCSP at each certificate's own responder (use_aia)")
		}
	}
	if len(parts) == 0 {
		return "no source"
	}
	return strings.Join(parts, ", ")
}

// say logs a line once per key per ten minutes, so a source down says so
// without a line at every retry.
func (c *Checker) say(key, format string, args ...any) {
	now := c.now()
	c.mu.Lock()
	if last, ok := c.said[key]; ok && now.Sub(last) < sayEvery {
		c.mu.Unlock()
		return
	}
	c.said[key] = now
	c.mu.Unlock()
	c.logf(format, args...)
}
