package certstatus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/printsafe"
)

// loadedCRL is one source's last good list: verified, and in scope.
type loadedCRL struct {
	name     string
	issuer   *x509.Certificate
	list     *x509.RevocationList
	revoked  map[string]revokedEntry // serial as big.Int.Text(16)
	userOnly bool                    // IDP onlyContainsUserCerts: covers leaves alone
}

type revokedEntry struct {
	at   time.Time
	hold bool
}

const (
	crlMax       = 16 << 20
	crlFetchTime = 30 * time.Second
	retryFirst   = 30 * time.Second
	// crlFutureSkew is how far ahead a list's ThisUpdate may be, as an OCSP
	// answer's may.
	crlFutureSkew = 5 * time.Minute
)

var (
	oidAuthorityKeyID     = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidCRLNumber          = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidDeltaCRL           = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistPt      = asn1.ObjectIdentifier{2, 5, 29, 28}
	reasonCertificateHold = 6
)

// accept verifies raw as src's list and checks its scope, returning the
// list ready to use or why it is refused (pre-flight C1, I3). Nothing about
// a list is read for any purpose before this returns it.
func (c *Checker) accept(src CRLSource, raw []byte) (*loadedCRL, error) {
	if blk, _ := pem.Decode(raw); blk != nil && blk.Type == "X509 CRL" {
		raw = blk.Bytes
	}
	list, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, fmt.Errorf("does not parse as a CRL: %w", err)
	}
	if weakSignature(list.SignatureAlgorithm) {
		return nil, fmt.Errorf("is signed with %s, which port49 does not trust", list.SignatureAlgorithm)
	}
	if err := list.CheckSignatureFrom(src.Issuer); err != nil {
		return nil, fmt.Errorf("is not signed by issuer_file's certificate (%v)", err)
	}
	// The key alone is not the issuer: a CA's key under another CA's name
	// would put its list on that name's certificates (RFC 5280 §6.3.3(b)).
	if !bytes.Equal(list.RawIssuer, src.Issuer.RawSubject) {
		listName, fileName := list.Issuer.String(), src.Issuer.Subject.String()
		if listName == fileName {
			return nil, fmt.Errorf("names its issuer %q as issuer_file's subject does, but encoded differently "+
				"(the same name, other bytes, such as a UTF8String against a PrintableString); the CA must "+
				"encode its CRL's issuer exactly as its certificate's subject", printsafe.Line(listName, 200))
		}
		return nil, fmt.Errorf("names its issuer %q, not issuer_file's %q",
			printsafe.Line(listName, 200), printsafe.Line(fileName, 200))
	}
	if len(list.AuthorityKeyId) > 0 && len(src.Issuer.SubjectKeyId) > 0 &&
		!bytes.Equal(list.AuthorityKeyId, src.Issuer.SubjectKeyId) {
		return nil, errors.New("names an authority key identifier other than issuer_file's subject key identifier")
	}
	// A list from the future, served early, would refuse the current one
	// as a rollback until its own dates pass.
	if list.ThisUpdate.After(c.now().Add(crlFutureSkew)) {
		return nil, fmt.Errorf("is dated %s, in the future", list.ThisUpdate.UTC().Format(time.RFC3339))
	}
	l := &loadedCRL{name: src.Name, issuer: src.Issuer, list: list, revoked: map[string]revokedEntry{}}
	for _, ext := range list.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRL):
			return nil, errors.New("is a delta CRL; name the full CRL")
		case ext.Id.Equal(oidIssuingDistPt):
			userOnly, err := userCertsOnly(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("is scoped by its issuing distribution point (%v); name a CRL covering "+
					"every serial, or one scoped to user certificates alone", err)
			}
			l.userOnly = userOnly
		case ext.Critical && !ext.Id.Equal(oidAuthorityKeyID) && !ext.Id.Equal(oidCRLNumber):
			return nil, fmt.Errorf("carries a critical extension port49 does not understand (%s)", ext.Id)
		}
	}
	for _, e := range list.RevokedCertificateEntries {
		for _, ext := range e.Extensions {
			if ext.Critical {
				return nil, fmt.Errorf("has an entry with a critical extension (%s), such as an indirect CRL's issuer", ext.Id)
			}
		}
		l.revoked[e.SerialNumber.Text(16)] = revokedEntry{at: e.RevocationTime, hold: e.ReasonCode == reasonCertificateHold}
	}
	return l, nil
}

// userCertsOnly reads an Issuing Distribution Point and accepts it only
// when it says nothing but onlyContainsUserCerts (true) or nothing at all:
// a distribution point, a reason subset, an indirect CRL or an attribute or
// CA scope partitions the issuer's serials (pre-flight I3).
func userCertsOnly(der []byte) (bool, error) {
	var idp struct {
		DistributionPoint          asn1.RawValue  `asn1:"optional,tag:0"`
		OnlyContainsUserCerts      bool           `asn1:"optional,tag:1"`
		OnlyContainsCACerts        bool           `asn1:"optional,tag:2"`
		OnlySomeReasons            asn1.BitString `asn1:"optional,tag:3"`
		IndirectCRL                bool           `asn1:"optional,tag:4"`
		OnlyContainsAttributeCerts bool           `asn1:"optional,tag:5"`
	}
	if rest, err := asn1.Unmarshal(der, &idp); err != nil || len(rest) != 0 {
		return false, errors.New("an issuing distribution point that does not parse")
	}
	switch {
	case len(idp.DistributionPoint.FullBytes) > 0:
		return false, errors.New("it names a distribution point")
	case idp.OnlyContainsCACerts:
		return false, errors.New("it covers CA certificates only")
	case idp.OnlySomeReasons.BitLength > 0:
		return false, errors.New("it covers some reasons only")
	case idp.IndirectCRL:
		return false, errors.New("it is an indirect CRL")
	case idp.OnlyContainsAttributeCerts:
		return false, errors.New("it covers attribute certificates only")
	}
	return idp.OnlyContainsUserCerts, nil
}

// install puts a verified list in force for its source when it is not
// older than the last good one, persists it, and reports its new entries.
// It is the one place a list is put in force.
func (c *Checker) install(src CRLSource, l *loadedCRL, persist bool) error {
	c.mu.Lock()
	prev := c.crls[src.Name]
	if prev != nil {
		older := l.list.ThisUpdate.Before(prev.list.ThisUpdate)
		if prev.list.Number != nil && l.list.Number != nil {
			older = l.list.Number.Cmp(prev.list.Number) < 0 ||
				(l.list.Number.Cmp(prev.list.Number) == 0 && older)
		}
		if older {
			c.mu.Unlock()
			return fmt.Errorf("is older than the list in force (number %v, this update %s); an older list is not taken",
				l.list.Number, l.list.ThisUpdate.UTC().Format(time.RFC3339))
		}
	}
	c.crls[src.Name] = l
	onNew := c.onNew
	c.mu.Unlock()
	c.gaugeOne(l)
	if persist && c.cfg.StateDir != "" {
		if err := inventory.WriteAtomic(c.cfg.StateDir, stateFile(src.Name), l.list.Raw, 0o600); err != nil {
			c.say("persist "+src.Name, "port49d: broker: certificate status: CRL %s could not be kept in %s (%v); "+
				"a restart will fetch it again", src.Name, c.cfg.StateDir, err)
		}
	}
	if onNew != nil {
		for serial, e := range l.revoked {
			if e.hold {
				continue // a hold is lifted by the CA: refused while listed, never marked (M13)
			}
			if prev != nil {
				if _, had := prev.revoked[serial]; had {
					continue
				}
			}
			onNew(l.list.Issuer.String(), serial, src.Name)
		}
	}
	return nil
}

// load fetches, verifies and installs one source.
func (c *Checker) load(ctx context.Context, src CRLSource) error {
	raw, err := c.fetch(ctx, src)
	if err != nil {
		c.m.CRLLoads.WithLabelValues(src.Name, "failed").Inc()
		return err
	}
	l, err := c.accept(src, raw)
	if err == nil {
		c.mu.Lock()
		prev := c.crls[src.Name]
		c.mu.Unlock()
		if prev != nil && bytes.Equal(prev.list.Raw, l.list.Raw) {
			c.gaugeOne(prev)
			c.m.CRLLoads.WithLabelValues(src.Name, "unchanged").Inc()
			return nil
		}
		err = c.install(src, l, true)
	}
	if err != nil {
		c.m.CRLLoads.WithLabelValues(src.Name, "refused").Inc()
		return err
	}
	c.m.CRLLoads.WithLabelValues(src.Name, "loaded").Inc()
	return nil
}

// LoadPersisted puts each source's kept list in force at start, read
// behind the fence and verified again, so a restart during a publisher
// outage keeps a list still fresh (pre-flight I8).
func (c *Checker) LoadPersisted() []error {
	var errs []error
	if c.cfg.StateDir == "" {
		return nil
	}
	for _, src := range c.cfg.CRLs {
		path := filepath.Join(c.cfg.StateDir, stateFile(src.Name))
		raw, err := fence.ReadNoLink(path, crlMax, "kept CRL")
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil {
			var l *loadedCRL
			if l, err = c.accept(src, raw); err == nil {
				err = c.install(src, l, false)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("kept CRL %s: %w", src.Name, err))
		}
	}
	return errs
}

// LoadAll fetches every source once, now, and says which did not load.
func (c *Checker) LoadAll(ctx context.Context) []error {
	var errs []error
	for _, src := range c.cfg.CRLs {
		if err := c.load(ctx, src); err != nil {
			errs = append(errs, fmt.Errorf("CRL %s: %w", src.Name, err))
		}
	}
	return errs
}

// Run fetches every source now, then each on its own schedule: every
// RefreshInterval after a success, and from 30s doubling to
// RefreshInterval after a failure (pre-flight I8). It returns when ctx ends.
func (c *Checker) Run(ctx context.Context) {
	type next struct {
		at    time.Time
		delay time.Duration
	}
	due := map[string]*next{}
	for _, src := range c.cfg.CRLs {
		due[src.Name] = &next{at: c.now()}
	}
	for {
		soonest := c.now().Add(c.cfg.RefreshInterval)
		for _, src := range c.cfg.CRLs {
			n := due[src.Name]
			if c.now().Before(n.at) {
				soonest = minTime(soonest, n.at)
				continue
			}
			if err := c.load(ctx, src); err != nil {
				c.say("load "+src.Name, "port49d: broker: certificate status: CRL %s: %s; the list in force stays "+
					"until its next update", src.Name, printsafe.Line(err.Error(), 300))
				n.delay = min(max(2*n.delay, retryFirst), c.cfg.RefreshInterval)
				n.at = c.now().Add(n.delay)
			} else {
				n.delay = 0 // the next failure is retried from 30s again
				n.at = c.now().Add(c.cfg.RefreshInterval)
			}
			soonest = minTime(soonest, n.at)
		}
		select {
		case <-ctx.Done():
			return
		case <-c.after(soonest.Sub(c.now())):
		}
	}
}

// fetch reads a source's bytes: a regular file, or an HTTP(S) URL that
// does not redirect, each within crlMax, the URL within crlFetchTime.
func (c *Checker) fetch(ctx context.Context, src CRLSource) ([]byte, error) {
	if src.File != "" {
		return readCRLFile(src.File)
	}
	if !httpURL(src.URL) {
		return nil, errors.New("its url is not http or https")
	}
	fctx, cancel := context.WithTimeout(ctx, crlFetchTime)
	defer cancel()
	req, err := http.NewRequestWithContext(fctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // its message repeats the url as written, credentials and all
		}
		return nil, fmt.Errorf("could not be fetched from %s (%v)", printsafe.Line(redactURL(src.URL), 120), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("its server answered %s", printsafe.Line(resp.Status, 120))
	}
	return readMax(resp.Body)
}

// readCRLFile reads a regular file. It is opened non-blocking, so a named
// pipe in its place is refused rather than hanging the poll. The list's
// signature, not the file's owner, is what it is trusted for.
func readCRLFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("could not be read (%v)", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("could not be read (%v)", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return readMax(f)
}

// readMax reads r to at most crlMax bytes, refusing more.
func readMax(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, crlMax+1))
	if err != nil {
		return nil, fmt.Errorf("could not be read (%v)", err)
	}
	if len(raw) > crlMax {
		return nil, fmt.Errorf("is larger than %d MiB", crlMax>>20)
	}
	return raw, nil
}

// gaugeOne sets the time the list stops applying (pre-flight M7).
func (c *Checker) gaugeOne(l *loadedCRL) {
	c.m.CRLNextUpdate.WithLabelValues(l.name).Set(float64(c.nextUpdate(l).Unix()))
}

// nextUpdate is when l stops applying: its NextUpdate, or when it names
// none, refresh_interval from its ThisUpdate (spec §5.1.4). Measured from
// ThisUpdate, not from the load, an old list fetched again is not made
// fresh by the fetch.
func (c *Checker) nextUpdate(l *loadedCRL) time.Time {
	if next := l.list.NextUpdate; !next.IsZero() {
		return next
	}
	return l.list.ThisUpdate.Add(c.cfg.RefreshInterval)
}

// httpURL is whether s is an http or https URL, the only schemes a status
// source is fetched over.
func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// redactURL is s for a log line or a Result: its userinfo and query, which
// may carry a credential, are replaced.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "a url that does not parse"
	}
	if u.User != nil {
		u.User = url.User("redacted")
	}
	if u.RawQuery != "" || u.ForceQuery {
		u.RawQuery, u.ForceQuery = "redacted", false
	}
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

var safeName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// stateFile is the name a source's list is kept under in StateDir:
// crl-<name>.der, or for a name outside [a-z0-9_-] its SHA-256, so no name
// reaches outside the directory or another source's file.
func stateFile(name string) string {
	if !safeName.MatchString(name) {
		sum := sha256.Sum256([]byte(name))
		name = "sha256-" + hex.EncodeToString(sum[:])
	}
	return "crl-" + name + ".der"
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// checkCRLs reads every list in force whose issuer certificate is,
// byte for byte, the certificate that verified cert (pre-flight C1); a
// list scoped to user certificates covers a leaf that is not itself a CA.
func (c *Checker) checkCRLs(cert, issuer *x509.Certificate, depth int) Result {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	serial := cert.SerialNumber.Text(16)
	var fresh *loadedCRL
	var stale []string
	for _, l := range c.crls {
		if !bytes.Equal(l.issuer.Raw, issuer.Raw) || (l.userOnly && (depth > 0 || cert.IsCA)) {
			continue
		}
		if e, revoked := l.revoked[serial]; revoked {
			return Result{Verdict: Revoked, Source: "crl", Name: l.name, RevokedAt: e.at, Hold: e.hold}
		}
		next := c.nextUpdate(l)
		if now.Before(next) {
			fresh = l
		} else {
			stale = append(stale, fmt.Sprintf("CRL %s is past its next update, %s", l.name, next.UTC().Format(time.RFC3339)))
		}
	}
	if fresh != nil {
		return Result{Verdict: Good, Source: "crl", Name: fresh.name}
	}
	detail := fmt.Sprintf("no fresh CRL or OCSP answer covers %q", printsafe.Line(issuer.Subject.String(), 200))
	if len(stale) > 0 {
		detail = strings.Join(stale, "; ")
	}
	return Result{Verdict: Unknown, Source: "none", Detail: detail}
}
