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
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/printsafe"
)

// loadedCRL is one source's last good list: verified, and in scope.
type loadedCRL struct {
	name     string
	issuer   *x509.Certificate
	list     *x509.RevocationList
	revoked  map[string]revokedEntry // serial as big.Int.Text(16)
	userOnly bool                    // IDP onlyContainsUserCerts: covers leaves alone
	// dpNames are the IDP's distributionPoint fullName GeneralNames, each
	// in its DER encoding: when set, the list covers only a certificate
	// whose CRL distribution points carry one of them, byte for byte
	// (RFC 5280 §5.2.5; spec §13, decision 40, ruling 17).
	dpNames [][]byte
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
	oidCRLDistPoints      = asn1.ObjectIdentifier{2, 5, 29, 31}
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
		return nil, fmt.Errorf("is not signed by %s certificate (%v)", src.issuerWord(), err)
	}
	// The key alone is not the issuer: a CA's key under another CA's name
	// would put its list on that name's certificates (RFC 5280 §6.3.3(b)).
	if !bytes.Equal(list.RawIssuer, src.Issuer.RawSubject) {
		listName, fileName := list.Issuer.String(), src.Issuer.Subject.String()
		if listName == fileName {
			return nil, fmt.Errorf("names its issuer %q as %s subject does, but encoded differently "+
				"(the same name, other bytes, such as a UTF8String against a PrintableString); the CA must "+
				"encode its CRL's issuer exactly as its certificate's subject",
				printsafe.Line(listName, 200), src.issuerWord())
		}
		return nil, fmt.Errorf("names its issuer %q, not %s %q",
			printsafe.Line(listName, 200), src.issuerWord(), printsafe.Line(fileName, 200))
	}
	if len(list.AuthorityKeyId) > 0 && len(src.Issuer.SubjectKeyId) > 0 &&
		!bytes.Equal(list.AuthorityKeyId, src.Issuer.SubjectKeyId) {
		return nil, fmt.Errorf("names an authority key identifier other than %s subject key identifier", src.issuerWord())
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
			userOnly, names, err := idpScope(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("is scoped by its issuing distribution point (%v); name a CRL covering "+
					"every serial, one scoped to user certificates alone, or one scoped to a distribution point "+
					"its certificates name by fullName", err)
			}
			l.userOnly, l.dpNames = userOnly, names
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

// idpScope reads an Issuing Distribution Point and accepts it only when it
// says nothing but a distributionPoint named by fullName, onlyContainsUserCerts
// (true), both, or nothing at all: a name relative to the issuer, a reason
// subset (even an empty one), an indirect CRL, an attribute or CA scope, or a
// field port49 does not know partitions the issuer's serials in a way port49
// does not follow (pre-flight I3; decision 40, ruling 17). It walks the
// fields itself, so one out of DER (out of order, a default spelled out,
// bytes left over) is refused rather than hiding another. names are the
// fullName GeneralNames, each in its DER encoding.
func idpScope(der []byte) (userOnly bool, names [][]byte, err error) {
	unparsed := errors.New("an issuing distribution point that does not parse")
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	switch {
	case err != nil || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound:
		return false, nil, unparsed
	case len(rest) != 0:
		return false, nil, errors.New("an issuing distribution point with bytes left over")
	}
	last := -1
	for rest := seq.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return false, nil, unparsed
		}
		switch {
		case f.Class != asn1.ClassContextSpecific || f.Tag > 5:
			return false, nil, errors.New("an issuing distribution point with a field port49 does not know")
		case f.Tag <= last:
			return false, nil, errors.New("an issuing distribution point with its fields out of order")
		}
		last = f.Tag
		switch f.Tag {
		case 0:
			if !f.IsCompound {
				return false, nil, unparsed
			}
			if names, err = fullNames(f); err != nil {
				return false, nil, err
			}
			continue
		case 3:
			return false, nil, errors.New("it covers some reasons only")
		}
		// The rest are BOOLEAN DEFAULT FALSE, which DER writes only as TRUE.
		if f.IsCompound || len(f.Bytes) != 1 || (f.Bytes[0] != 0 && f.Bytes[0] != 0xff) {
			return false, nil, unparsed
		}
		if f.Bytes[0] == 0 {
			return false, nil, errors.New("an issuing distribution point with a default spelled out")
		}
		switch f.Tag {
		case 1:
			userOnly = true
		case 2:
			return false, nil, errors.New("it covers CA certificates only")
		case 4:
			return false, nil, errors.New("it is an indirect CRL")
		case 5:
			return false, nil, errors.New("it covers attribute certificates only")
		}
	}
	return userOnly, names, nil
}

// fullNames reads a distributionPoint ([0] EXPLICIT DistributionPointName)
// and returns its fullName GeneralNames, each in its DER encoding. A name
// relative to the CRL issuer, or an empty or malformed fullName, is an error.
func fullNames(dp asn1.RawValue) ([][]byte, error) {
	var dpn asn1.RawValue
	if rest, err := asn1.Unmarshal(dp.Bytes, &dpn); err != nil || len(rest) != 0 {
		return nil, errors.New("a distribution point name that does not parse")
	}
	if dpn.Class != asn1.ClassContextSpecific || dpn.Tag != 0 || !dpn.IsCompound {
		return nil, errors.New("it names a distribution point relative to the CRL issuer, not by fullName")
	}
	var names [][]byte
	for rest := dpn.Bytes; len(rest) > 0; {
		var gn asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
			return nil, errors.New("a distribution point fullName that does not parse")
		}
		names = append(names, gn.FullBytes)
	}
	if len(names) == 0 {
		return nil, errors.New("a distribution point fullName with no name")
	}
	return names, nil
}

// certDPNames are the fullName GeneralNames of cert's CRL distribution
// points, each in its DER encoding. A point carrying reasons or a cRLIssuer
// names nothing: port49 follows no reason partition and no indirect issuer
// (ruling 17). An extension that does not parse, or a point out of DER,
// gives none, so no scoped list covers the certificate (fail closed).
func certDPNames(cert *x509.Certificate) [][]byte {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidCRLDistPoints) {
			continue
		}
		var points []asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &points); err != nil || len(rest) != 0 {
			return nil
		}
		var names [][]byte
		for _, p := range points {
			n, ok := pointNames(p)
			if !ok {
				return nil
			}
			names = append(names, n...)
		}
		return names
	}
	return nil
}

// pointNames are one DistributionPoint's fullName names: none when it
// carries reasons or a cRLIssuer, has no distributionPoint, or names one
// relative to the CRL issuer. ok is false for a point out of DER.
func pointNames(p asn1.RawValue) (names [][]byte, ok bool) {
	if p.Class != asn1.ClassUniversal || p.Tag != asn1.TagSequence || !p.IsCompound {
		return nil, false
	}
	var dp *asn1.RawValue
	restricted, last := false, -1
	for rest := p.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil || f.Class != asn1.ClassContextSpecific ||
			f.Tag > 2 || f.Tag <= last || (f.Tag == 0 && !f.IsCompound) {
			return nil, false
		}
		last = f.Tag
		if f.Tag == 0 {
			dp = &f
		} else {
			restricted = true
		}
	}
	if restricted || dp == nil {
		return nil, true
	}
	if names, err := fullNames(*dp); err == nil {
		return names, true
	}
	return nil, true
}

// nameWords is a list's distribution point names for a line: the first two,
// each URI as printable text and any other kind of name said as such, and
// how many more.
func nameWords(names [][]byte) string {
	const shown = 2
	var out []string
	for _, n := range names[:min(len(names), shown)] {
		var gn asn1.RawValue
		if _, err := asn1.Unmarshal(n, &gn); err == nil && gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 {
			out = append(out, printsafe.Line(string(gn.Bytes), 200))
		} else {
			out = append(out, "(a name that is not a URI)")
		}
	}
	words := strings.Join(out, ", ")
	if len(names) > shown {
		words += fmt.Sprintf(" and %d more", len(names)-shown)
	}
	return words
}

// namesOne says whether have holds one of want, byte for byte.
func namesOne(have, want [][]byte) bool {
	for _, h := range have {
		for _, w := range want {
			if bytes.Equal(h, w) {
				return true
			}
		}
	}
	return false
}

// errSourceReplaced is install's refusal of a list fetched for a source that
// SetCRLSources has since replaced; load does not count it a failure.
var errSourceReplaced = errors.New("its source was replaced while it was fetched")

// install puts a verified list in force for its source when it is not
// older than the last good one, persists it, and reports its new entries.
// It is the one place a list is put in force.
func (c *Checker) install(src CRLSource, l *loadedCRL, persist bool) error {
	c.mu.Lock()
	// A load that began before SetCRLSources replaced its source finishes
	// against the issuer it started with; its list must not come back.
	if i := slices.IndexFunc(c.cfg.CRLs, func(s CRLSource) bool { return s.Name == src.Name }); i >= 0 &&
		!bytes.Equal(c.cfg.CRLs[i].Issuer.Raw, src.Issuer.Raw) {
		c.mu.Unlock()
		return errSourceReplaced
	}
	prev := c.crls[src.Name]
	// A rollback is a list older than another of the same issuer; a new
	// CA's numbers and dates start where they like.
	if prev != nil && bytes.Equal(prev.issuer.Raw, l.issuer.Raw) {
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
			c.say("persist "+src.Name, c.prefix()+"CRL %s could not be kept in %s (%v); "+
				"a restart will fetch it again", src.Name, c.cfg.StateDir, err)
		}
	}
	if onNew != nil {
		bulk := !persist || prev == nil
		for serial, e := range l.revoked {
			if e.hold {
				continue // a hold is lifted by the CA: refused while listed, never marked (M13)
			}
			if prev != nil {
				if _, had := prev.revoked[serial]; had {
					continue
				}
			}
			onNew(l.list.Issuer.String(), serial, src.Name, bulk)
		}
	}
	return nil
}

// load fetches, verifies and installs one source.
func (c *Checker) load(ctx context.Context, src CRLSource) error {
	raw, err := c.fetch(ctx, src)
	if err != nil {
		c.m.CRLLoads.WithLabelValues(c.component(), src.Name, "failed").Inc()
		c.setFailing(src.Name)
		return err
	}
	l, err := c.accept(src, raw)
	if err == nil {
		c.mu.Lock()
		prev := c.crls[src.Name]
		c.mu.Unlock()
		if prev != nil && bytes.Equal(prev.list.Raw, l.list.Raw) {
			c.gaugeOne(prev)
			c.m.CRLLoads.WithLabelValues(c.component(), src.Name, "unchanged").Inc()
			c.loaded(src, prev, false)
			return nil
		}
		if err = c.install(src, l, true); err == nil {
			c.loaded(src, l, prev == nil || !c.now().Before(c.nextUpdate(prev)))
		}
	}
	if errors.Is(err, errSourceReplaced) {
		return nil // the replacement source is fetched on its own
	}
	if err != nil {
		c.m.CRLLoads.WithLabelValues(c.component(), src.Name, "refused").Inc()
		c.setFailing(src.Name)
		return err
	}
	c.m.CRLLoads.WithLabelValues(c.component(), src.Name, "loaded").Inc()
	return nil
}

func (c *Checker) setFailing(name string) {
	c.mu.Lock()
	c.failing[name] = true
	c.mu.Unlock()
}

// loaded says a source's list is in force when it comes into force from
// none or from a stale one (fresh), or after a failed load, so the silence
// after "not loaded yet" or a failure line is never all an operator has. A
// steady reload says nothing. The failure line's limit is reset, so the
// next failure is said at once.
func (c *Checker) loaded(src CRLSource, l *loadedCRL, fresh bool) {
	c.mu.Lock()
	say := fresh || c.failing[src.Name]
	delete(c.failing, src.Name)
	if say {
		delete(c.said, "load "+src.Name)
	}
	c.mu.Unlock()
	if !say {
		return
	}
	next := c.nextUpdate(l)
	if !c.now().Before(next) {
		c.logf(c.prefix()+"CRL %s loaded, but its next update, %s, has passed: "+
			"it establishes nothing until the CA publishes a newer list", src.Name, next.UTC().Format(time.RFC3339))
		return
	}
	c.logf(c.prefix()+"CRL %s loaded (next update %s)", src.Name,
		next.UTC().Format(time.RFC3339))
}

// LoadPersisted puts each source's kept list in force at start, read
// behind the fence and verified again, so a restart during a publisher
// outage keeps a list still fresh (pre-flight I8).
func (c *Checker) LoadPersisted() []error {
	var errs []error
	if c.cfg.StateDir == "" {
		return nil
	}
	for _, src := range c.sources() {
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
	for _, src := range c.sources() {
		if err := c.load(ctx, src); err != nil {
			errs = append(errs, fmt.Errorf("CRL %s: %w", src.Name, err))
		}
	}
	return errs
}

// Run fetches every source now, then each on its own schedule: every
// RefreshInterval after a success, and from 30s doubling to
// RefreshInterval after a failure (pre-flight I8). It also asks the OCSP
// responder again about answers in use as they reach their refresh point
// (refreshOCSP). It returns when ctx ends.
func (c *Checker) Run(ctx context.Context) {
	type next struct {
		at     time.Time
		delay  time.Duration
		issuer []byte // the issuer certificate the schedule is for
	}
	due := map[string]*next{}
	for {
		srcs := c.sources()
		soonest := c.now().Add(c.cfg.RefreshInterval)
		for _, src := range srcs {
			n := due[src.Name]
			if n == nil || !bytes.Equal(n.issuer, src.Issuer.Raw) {
				// New, or its issuer was replaced (SetCRLSources): fetch now.
				n = &next{at: c.now(), issuer: src.Issuer.Raw}
				due[src.Name] = n
			}
			if c.now().Before(n.at) {
				soonest = minTime(soonest, n.at)
				continue
			}
			if err := c.load(ctx, src); err != nil {
				c.say("load "+src.Name, c.prefix()+"CRL %s: %s; the list in force stays "+
					"until its next update", src.Name, printsafe.Line(err.Error(), 300))
				n.delay = min(max(2*n.delay, retryFirst), c.cfg.RefreshInterval)
				n.at = c.now().Add(n.delay)
			} else {
				n.delay = 0 // the next failure is retried from 30s again
				n.at = c.now().Add(c.cfg.RefreshInterval)
			}
			soonest = minTime(soonest, n.at)
		}
		if c.cfg.OCSP != nil {
			if at := c.refreshOCSP(ctx); !at.IsZero() {
				soonest = minTime(soonest, at)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-c.after(soonest.Sub(c.now())):
		}
	}
}

// sources are the CRL sources now.
func (c *Checker) sources() []CRLSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.cfg.CRLs)
}

// SetCRLSources replaces the CRL sources, as the trust set they were
// verified against changed (a CA rotation, spec §13 decision 50 ruling 15).
// A list in force whose source is gone is dropped, and so is one that does
// not verify against the source's issuer certificate now (a renewed CA
// certificate with the same key still verifies it, and keeps it). Run fetches the changed sources at once.
func (c *Checker) SetCRLSources(srcs []CRLSource) {
	c.mu.Lock()
	c.cfg.CRLs = slices.Clone(srcs)
	for name, l := range c.crls {
		i := slices.IndexFunc(srcs, func(s CRLSource) bool { return s.Name == name })
		switch {
		case i < 0:
			delete(c.crls, name)
		case !bytes.Equal(srcs[i].Issuer.Raw, l.issuer.Raw):
			// A CA renewed with its key and name still signs the list in
			// force: keep it if it verifies against the new certificate.
			if nl, err := c.accept(srcs[i], l.list.Raw); err == nil {
				c.crls[name] = nl
			} else {
				delete(c.crls, name)
			}
		}
	}
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
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
	c.m.CRLNextUpdate.WithLabelValues(c.component(), l.name).Set(float64(c.nextUpdate(l).Unix()))
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
// byte for byte, the certificate that verified cert (pre-flight C1). One
// that names cert's serial is final whatever its scope: serials are unique
// per issuer, and an indirect list or an entry naming another issuer is
// refused. Otherwise a list scoped to user certificates covers a leaf that
// is not itself a CA, and one scoped to a distribution point covers a
// certificate whose CRL distribution points name it (decision 40, ruling
// 17); a list that does not cover cert never says "not revoked" for it.
func (c *Checker) checkCRLs(cert, issuer *x509.Certificate, depth int) Result {
	now := c.now()
	dps := certDPNames(cert)
	c.mu.Lock()
	defer c.mu.Unlock()
	serial := cert.SerialNumber.Text(16)
	var fresh *loadedCRL
	var stale, scoped []string
	for _, l := range c.crls {
		if !bytes.Equal(l.issuer.Raw, issuer.Raw) {
			continue
		}
		if e, revoked := l.revoked[serial]; revoked {
			return Result{Verdict: Revoked, Source: "crl", Name: l.name, RevokedAt: e.at, Hold: e.hold}
		}
		if l.userOnly && (depth > 0 || cert.IsCA) {
			continue
		}
		if len(l.dpNames) > 0 && !namesOne(dps, l.dpNames) {
			scoped = append(scoped, fmt.Sprintf("CRL %s is scoped to the distribution point %s, which this "+
				"certificate's CRL distribution points do not name outside a reasons or cRLIssuer restriction; "+
				"issue it with that name", l.name, nameWords(l.dpNames)))
			continue
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
	if len(scoped) > 0 {
		detail += " (" + strings.Join(scoped, "; ") + ")"
	}
	if len(stale) > 0 {
		// Opening "CRL ", so the broker classes it a stale list.
		detail = strings.Join(append(stale, scoped...), "; ")
	}
	return Result{Verdict: Unknown, Source: "none", Detail: detail}
}
