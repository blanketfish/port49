package certstatus

import (
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha1" // the CertID hashes matchCertID computes
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/rhwendt/port49/internal/printsafe"
)

type ocspEntry struct {
	res     Result
	expires time.Time
}

// ocspCall is one question in flight, shared by every caller asking it.
type ocspCall struct {
	done chan struct{}
	res  Result
}

// ocspNoResponder is the one OCSP failure that is not an outage: no
// responder applies to the certificate (use_aia, and it names none).
const ocspNoResponder = "no responder for this certificate"

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
// validity; its CertID is cert's, issuer and serial; its ThisUpdate is at
// most five minutes ahead; its NextUpdate, when set, is still to come, and
// when unset its ThisUpdate is within RefreshInterval. A good or revoked
// answer is cached while it is fresh and at most an hour; a failure for
// 30s. Concurrent questions about one certificate share one request (M15),
// and that request belongs to none of them: a caller that hangs up stops
// waiting, never the question, so it cannot leave its failure to the rest.
func (c *Checker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate) Result {
	key := ocspKey(cert, issuer)
	c.mu.Lock()
	if e, ok := c.ocsp[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.res
	}
	call, busy := c.ocspInflight[key]
	if !busy {
		call = &ocspCall{done: make(chan struct{})}
		c.ocspInflight[key] = call
		go c.ask(context.WithoutCancel(ctx), key, call, cert, issuer)
	}
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.res
	case <-ctx.Done():
		return Result{Verdict: Unknown, Source: "none", Detail: "OCSP: the question was abandoned"}
	}
}

// ask runs one shared question to its end, bounded by OCSP.Timeout alone,
// caches its outcome and hands it to every caller waiting on call.
func (c *Checker) ask(ctx context.Context, key string, call *ocspCall, cert, issuer *x509.Certificate) {
	res, ttl := c.askOCSP(ctx, cert, issuer)
	c.mu.Lock()
	defer c.mu.Unlock()
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
	call.res = res
	delete(c.ocspInflight, key)
	close(call.done)
}

// askOCSP is one question, and how long its answer may be reused.
func (c *Checker) askOCSP(ctx context.Context, cert, issuer *x509.Certificate) (Result, time.Duration) {
	url := c.cfg.OCSP.Responder
	if url == "" && c.cfg.OCSP.UseAIA && len(cert.OCSPServer) > 0 {
		url = cert.OCSPServer[0]
	}
	shown := printsafe.Line(redactURL(url), 120)
	unknown := func(why string) (Result, time.Duration) {
		return Result{Verdict: Unknown, Source: "none",
			Detail: "OCSP " + shown + ": " + printsafe.Line(why, 200)}, ocspFailCache
	}
	if url == "" {
		return unknown(ocspNoResponder)
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
	if weakSignature(r.SignatureAlgorithm) {
		return unknown("its answer is signed with " + r.SignatureAlgorithm.String() + ", which port49 does not trust")
	}
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
	// Everything below is read from the signed bytes, and only from the
	// answers whose whole CertID is cert's (RFC 6960 §3.2(1)): a serial
	// alone is another CA's certificate too.
	single, why := matchCertID(r.TBSResponseData, cert, issuer)
	if why != "" {
		return unknown(why)
	}
	switch {
	case single.ThisUpdate.After(now.Add(ocspFutureSkew)):
		return unknown("its answer is dated in the future")
	case !single.NextUpdate.IsZero() && !now.Before(single.NextUpdate):
		return unknown("its answer is past its next update")
	case single.NextUpdate.IsZero() && single.ThisUpdate.Before(now.Add(-c.cfg.RefreshInterval)):
		return unknown("its answer is older than refresh_interval and names no next update")
	}
	res := Result{Source: "ocsp", Name: shown}
	switch single.status() {
	case ocsp.Good:
		res.Verdict = Good
	case ocsp.Revoked:
		res.Verdict, res.RevokedAt = Revoked, single.Revoked.RevocationTime
		res.Hold = int(single.Revoked.Reason) == ocsp.CertificateHold
	default:
		return unknown("answered unknown")
	}
	// Reused only while it is fresh: to its NextUpdate, or with none to
	// refresh_interval past its ThisUpdate, and never past an hour.
	fresh := single.NextUpdate
	if fresh.IsZero() {
		fresh = single.ThisUpdate.Add(c.cfg.RefreshInterval)
	}
	return res, min(ocspMaxCache, fresh.Sub(now))
}

// The parts of RFC 6960's ResponseData that decide a status, parsed from
// the signed bytes: x/crypto/ocsp keeps the CertID's issuer hashes to
// itself.
type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
}

type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type certID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

// status is the answer's certStatus; a revoked one without a time is not
// one, and reads as unknown.
func (s singleResponse) status() int {
	switch {
	case bool(s.Good):
		return ocsp.Good
	case bool(s.Unknown) || s.Revoked.RevocationTime.IsZero():
		return ocsp.Unknown
	}
	return ocsp.Revoked
}

var certIDHashes = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

// matchCertID is the one answer in tbs whose CertID names cert under
// issuer, by issuer name hash, issuer key hash and serial, each answer
// under its own hash algorithm; or why there is none to take. Answers that
// match and disagree are none.
func matchCertID(tbs []byte, cert, issuer *x509.Certificate) (singleResponse, string) {
	var data responseData
	if rest, err := asn1.Unmarshal(tbs, &data); err != nil || len(rest) != 0 {
		return singleResponse{}, "its answer does not parse"
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return singleResponse{}, "the issuer's public key does not parse"
	}
	var match []singleResponse
	for _, s := range data.Responses {
		h, ok := certIDHashes[s.CertID.HashAlgorithm.Algorithm.String()]
		if !ok || !h.Available() || s.CertID.SerialNumber == nil || s.CertID.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			continue
		}
		name, key := h.New(), h.New()
		name.Write(issuer.RawSubject)
		key.Write(spki.PublicKey.RightAlign())
		if bytes.Equal(s.CertID.IssuerNameHash, name.Sum(nil)) && bytes.Equal(s.CertID.IssuerKeyHash, key.Sum(nil)) {
			match = append(match, s)
		}
	}
	if len(match) == 0 {
		return singleResponse{}, "its answer is for another certificate"
	}
	for _, s := range match[1:] {
		if s.status() != match[0].status() {
			return singleResponse{}, "its answer says two things about this certificate"
		}
	}
	for _, ext := range match[0].SingleExtensions {
		if ext.Critical {
			return singleResponse{}, "its answer carries a critical extension port49 does not understand"
		}
	}
	return match[0], ""
}

// weakSignature is a signature algorithm port49 takes from no status
// source: SHA-1 or MD5, open to a collision over content the requester
// chooses. SHA-1 stays allowed as the CertID hash (ocsp.hash), which
// signs nothing.
func weakSignature(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
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
