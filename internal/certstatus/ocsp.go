package certstatus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/rhwendt/port49/internal/printsafe"
)

type ocspEntry struct {
	res     Result
	expires time.Time
}

const (
	ocspMaxCache   = time.Hour        // a revocation reaches the broker within it
	ocspFailCache  = 30 * time.Second // a responder down is asked once per 30s (M15)
	ocspFutureSkew = 5 * time.Minute
	ocspMaxBody    = 1 << 20
	ocspSweepAt    = 1024 // cached answers past which expired ones are swept at each insert
)

// checkOCSP asks the responder about cert, held to RFC 6960 (pre-flight
// C2): the answer verifies for issuer, and its signer is issuer itself or
// a delegate issuer signed that carries id-kp-OCSPSigning and is inside its
// validity; its serial is cert's; its ThisUpdate is at most five minutes
// ahead; its NextUpdate, when set, is still to come, and when unset its
// ThisUpdate is within RefreshInterval. A good or revoked answer is cached
// to the earlier of its NextUpdate and an hour, never once expired; a
// failure for 30s. Concurrent questions about one certificate share one
// request (M15).
func (c *Checker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate) Result {
	key := ocspKey(cert, issuer)
	for {
		c.mu.Lock()
		if e, ok := c.ocsp[key]; ok && c.now().Before(e.expires) {
			c.mu.Unlock()
			return e.res
		}
		if wait, busy := c.ocspInflight[key]; busy {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return Result{Verdict: Unknown, Source: "none", Detail: "OCSP: the question was abandoned"}
			}
		}
		done := make(chan struct{})
		c.ocspInflight[key] = done
		c.mu.Unlock()
		res, ttl := c.askOCSP(ctx, cert, issuer)
		c.mu.Lock()
		if ttl > 0 {
			now := c.now()
			if len(c.ocsp) >= ocspSweepAt {
				for k, e := range c.ocsp {
					if !now.Before(e.expires) {
						delete(c.ocsp, k)
					}
				}
			}
			c.ocsp[key] = ocspEntry{res: res, expires: now.Add(ttl)}
		}
		delete(c.ocspInflight, key)
		close(done)
		c.mu.Unlock()
		return res
	}
}

// askOCSP is one question, and how long its answer may be reused.
func (c *Checker) askOCSP(ctx context.Context, cert, issuer *x509.Certificate) (Result, time.Duration) {
	url := c.cfg.OCSP.Responder
	if url == "" && c.cfg.OCSP.UseAIA && len(cert.OCSPServer) > 0 {
		url = cert.OCSPServer[0]
	}
	unknown := func(why string) (Result, time.Duration) {
		return Result{Verdict: Unknown, Source: "none",
			Detail: "OCSP " + printsafe.Line(url, 120) + ": " + printsafe.Line(why, 200)}, ocspFailCache
	}
	if url == "" {
		return unknown("no responder for this certificate")
	}
	if !httpURL(url) {
		return unknown("its url is not http or https")
	}
	reqBody, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: c.cfg.OCSP.Hash})
	if err != nil {
		return unknown(err.Error())
	}
	qctx, cancel := context.WithTimeout(ctx, c.cfg.OCSP.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return unknown("its url does not parse")
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	resp, err := c.http.Do(req)
	if err != nil {
		return unknown("did not answer")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, ocspMaxBody))
	if resp.StatusCode != http.StatusOK {
		return unknown("answered " + resp.Status)
	}
	if err != nil {
		return unknown("its answer could not be read")
	}
	// The signature is checked here, not by ParseResponseForCert: given the
	// issuer, it would refuse an intermediate that embeds its own
	// certificate, which its parent signed, not itself (re-check R8).
	r, err := ocsp.ParseResponseForCert(raw, cert, nil)
	if err != nil {
		return unknown("its answer does not parse, or is for another certificate")
	}
	// Read after the signature: everything below is the signer's word.
	now := c.now()
	signer := issuer
	if r.Certificate != nil && !bytes.Equal(r.Certificate.Raw, issuer.Raw) {
		if r.Certificate.CheckSignatureFrom(issuer) != nil {
			return unknown("its answer is signed by a certificate this issuer did not sign")
		}
		if !delegateOK(r.Certificate, now) {
			return unknown("its answer is signed by a delegate without the OCSP-signing usage, or out of validity")
		}
		signer = r.Certificate
	}
	if r.CheckSignatureFrom(signer) != nil {
		return unknown("its answer does not verify for this issuer")
	}
	switch {
	case r.SerialNumber == nil || r.SerialNumber.Cmp(cert.SerialNumber) != 0:
		return unknown("its answer is for another serial")
	case r.ThisUpdate.After(now.Add(ocspFutureSkew)):
		return unknown("its answer is dated in the future")
	case !r.NextUpdate.IsZero() && !now.Before(r.NextUpdate):
		return unknown("its answer is past its next update")
	case r.NextUpdate.IsZero() && r.ThisUpdate.Before(now.Add(-c.cfg.RefreshInterval)):
		return unknown("its answer is older than refresh_interval and names no next update")
	}
	res := Result{Source: "ocsp", Name: printsafe.Line(url, 120)}
	switch r.Status {
	case ocsp.Good:
		res.Verdict = Good
	case ocsp.Revoked:
		res.Verdict, res.RevokedAt = Revoked, r.RevokedAt
		res.Hold = r.RevocationReason == ocsp.CertificateHold
	default:
		return unknown("answered unknown")
	}
	ttl := ocspMaxCache
	if !r.NextUpdate.IsZero() {
		ttl = min(ttl, r.NextUpdate.Sub(now))
	}
	return res, ttl
}

// delegateOK is RFC 6960 §4.2.2.2's delegated responder: issued by the
// issuer (checked by the caller), carrying id-kp-OCSPSigning, and inside
// its validity.
func delegateOK(d *x509.Certificate, now time.Time) bool {
	if now.Before(d.NotBefore) || now.After(d.NotAfter) {
		return false
	}
	for _, u := range d.ExtKeyUsage {
		if u == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}

func ocspKey(cert, issuer *x509.Certificate) string {
	sum := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]) + "|" + cert.SerialNumber.Text(16)
}
