// Package brokercrl checks the certificate a broker presents against the CRLs
// that certificate and its issuers name, before the client writes a request
// to it: a revoked broker never sees a bearer ID token or a signature (plan
// 9c, ruling 9). It is the client side of certstatus, which port49d's broker
// runs for client certificates.
package brokercrl

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Mode is broker_crl.
type Mode string

const (
	ModeCheck   Mode = "check"   // revoked refuses; unavailable is said and goes on
	ModeRequire Mode = "require" // revoked and unavailable both refuse
	ModeOff     Mode = "off"
)

// ParseMode reads broker_crl: empty is the default, check.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "":
		return ModeCheck, nil
	case ModeCheck, ModeRequire, ModeOff:
		return Mode(s), nil
	}
	return "", fmt.Errorf("broker_crl %q: it is check, require or off", printsafe.Line(s, 40))
}

const (
	// fetchWait bounds the wait on a CRL server, once per Checker minute.
	fetchWait = 5 * time.Second
	// retryAfter is how long a failed fetch is remembered, so a CRL server
	// that is down costs one wait, not one per connection.
	retryAfter = time.Minute
)

// RevokedError is a broker certificate a list names.
type RevokedError struct{ Subject, Serial, List string }

func (e *RevokedError) Error() string {
	return fmt.Sprintf("the broker's certificate %s (serial %s) is revoked by %s; nothing was sent to it; "+
		"tell the broker's operator", e.Subject, e.Serial, e.List)
}

// UncheckedError is a broker certificate whose revocation could not be
// checked under broker_crl: require.
type UncheckedError struct{ Detail string }

func (e *UncheckedError) Error() string {
	return "the broker certificate's revocation could not be checked (" + e.Detail + "); broker_crl: require " +
		"refuses it, so nothing was sent to the broker; get the CRL server back, or set broker_crl: check"
}

// Checker checks the broker's verified chain against the CRLs its
// certificates name, keeping the last good list of each in dir. It is safe
// for concurrent use; connections wait on one another, so a CRL server that
// is down is waited on once.
type Checker struct {
	dir  string
	mode Mode
	now  func() time.Time
	warn func(string)

	mu     sync.Mutex
	sets   map[string]*set
	warned bool
}

// set is one distinct group of lists: a certstatus.Checker over them and when
// they last failed to load.
type set struct {
	chk       *certstatus.Checker
	persisted bool
	failedAt  time.Time
	failure   string            // the last failed load, said with any unknown
	keptErr   string            // why a kept list was not put in force at start
	urls      map[string]string // source name -> its url, as said
}

// link is one certificate of the chain and the one that issued it.
type link struct{ cert, issuer *x509.Certificate }

// New builds a Checker. dir keeps each list ("" keeps none); warn says, once,
// that a list could not be had under check.
func New(dir string, mode Mode, now func() time.Time, warn func(string)) *Checker {
	if now == nil {
		now = time.Now
	}
	if warn == nil {
		warn = func(string) {}
	}
	return &Checker{dir: dir, mode: mode, now: now, warn: warn, sets: map[string]*set{}}
}

// VerifyConnection is a tls.Config.VerifyConnection: it runs after the
// chain verified and before any request is written.
func (c *Checker) VerifyConnection(cs tls.ConnectionState) error {
	if c.mode == ModeOff {
		return nil
	}
	if len(cs.VerifiedChains) == 0 {
		// Not reachable while every tls.Config sets RootCAs; if it ever
		// were, there is nothing to check, and require reads that as
		// unchecked.
		if c.mode == ModeRequire {
			return &UncheckedError{Detail: "the connection has no verified certificate chain"}
		}
		return nil
	}
	chain := cs.VerifiedChains[0]
	var links []link
	var srcs []certstatus.CRLSource
	urls := map[string]string{}
	// Link by link (pre-flight I10): an intermediate that names no
	// distribution point is passed over, and the certificate it issued is
	// still checked. Check(ctx, chain) would read that intermediate as
	// unknown and refuse every login under require.
	for i := 0; i+1 < len(chain); i++ {
		named := false
		for _, raw := range chain[i].CRLDistributionPoints {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			named = true
			sum := sha256.Sum256([]byte(raw))
			name := strings.ToLower(u.Host) + "-" + hex.EncodeToString(sum[:4])
			srcs = append(srcs, certstatus.CRLSource{Name: name, URL: raw, Issuer: chain[i+1], IssuerWord: "the issuing CA's"})
			urls[name] = say(u)
		}
		if named {
			links = append(links, link{chain[i], chain[i+1]})
		}
	}
	if len(links) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.setFor(srcs, urls)
	if !s.persisted {
		s.persisted = true
		// A kept list that does not load is replaced by the fetch below; if
		// that fails too, the operator is told why the kept one was no use.
		if errs := s.chk.LoadPersisted(); len(errs) > 0 {
			s.keptErr = errs[0].Error()
		}
	}
	rev, unknown := s.check(links)
	if rev == nil && unknown != "" && (s.failedAt.IsZero() || c.now().Sub(s.failedAt) >= retryAfter) {
		ctx, cancel := context.WithTimeout(context.Background(), fetchWait)
		errs := s.chk.LoadAll(ctx)
		cancel()
		rev, unknown = s.check(links)
		s.failedAt, s.failure = time.Time{}, ""
		if len(errs) > 0 {
			s.failure = errs[0].Error()
		}
		// A list that loaded but cannot answer (past its next update, or
		// scoped away) is remembered like a failed fetch: a stuck publisher
		// must not cost a download per connection.
		if len(errs) > 0 || rev == nil && unknown != "" {
			s.failedAt = c.now()
		}
	}
	if rev != nil {
		return rev
	}
	if unknown == "" {
		return nil
	}
	if s.failure != "" {
		unknown = s.failure + "; " + unknown
	}
	if s.keptErr != "" {
		unknown += "; the list kept from before was not used: " + s.keptErr
	}
	if c.mode == ModeRequire {
		return &UncheckedError{Detail: unknown}
	}
	if !c.warned {
		c.warned = true
		c.warn("could not check the broker certificate's revocation (" + unknown + "); going on, because broker_crl " +
			"is check; set broker_crl: require to refuse a broker whose lists cannot be had")
	}
	return nil
}

// setFor is the kept group of lists for srcs, made on first use.
func (c *Checker) setFor(srcs []certstatus.CRLSource, urls map[string]string) *set {
	keys := make([]string, 0, len(srcs))
	for _, s := range srcs {
		h := sha256.Sum256(s.Issuer.Raw)
		keys = append(keys, s.Name+"/"+hex.EncodeToString(h[:4]))
	}
	sort.Strings(keys)
	key := strings.Join(keys, " ")
	if s, ok := c.sets[key]; ok {
		return s
	}
	chk := certstatus.New(certstatus.Config{CRLs: srcs, StateDir: c.dir}, c.now,
		metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	s := &set{chk: chk, urls: urls}
	c.sets[key] = s
	return s
}

// check is the first revoked link, else the first unknown one's reason.
func (s *set) check(links []link) (*RevokedError, string) {
	var unknown string
	for _, l := range links {
		r := s.chk.Check(context.Background(), []*x509.Certificate{l.cert, l.issuer})
		switch r.Verdict {
		case certstatus.Revoked:
			list := "a CRL"
			if u, ok := s.urls[r.Name]; ok {
				list = "the CRL at " + u
			}
			return &RevokedError{Subject: printsafe.Line(l.cert.Subject.String(), 200),
				Serial: l.cert.SerialNumber.Text(16), List: list}, ""
		case certstatus.Unknown:
			if unknown == "" {
				unknown = r.Detail
			}
		}
	}
	return nil, unknown
}

// say is a distribution point as a message may carry it: no credentials, no
// query.
func say(u *url.URL) string {
	v := *u
	v.User, v.RawQuery, v.Fragment, v.RawFragment = nil, "", "", ""
	return printsafe.Line(v.String(), 200)
}
