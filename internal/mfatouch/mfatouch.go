// Package mfatouch is what a hardware_key_touch proof is made of, shared by the
// agent and the agentless workload client (plan 9c, decision 45 rulings 12–14):
// the attestation chain read off the token, the signature over the challenge
// and the connection's exporter value, and the one POST /v1/mfa that is sent
// on the connection that value came from or not at all.
package mfatouch

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"

	"github.com/rhwendt/port49/internal/broker/api"
)

// ErrConnectionChanged is a touch made over a connection that was replaced
// before the post.
var ErrConnectionChanged = errors.New("the connection changed during the touch; run it again")

// Certificates is a key whose token lists its certificate objects
// (pkcs11.Signer): the attestations among them.
type Certificates interface {
	Certificates() ([]*x509.Certificate, error)
}

// ErrNoAttestation is a token that does not show the attestations the proof
// carries. Provisional on L60: what a YubiKey lists through libykcs11 is
// measured there.
var ErrNoAttestation = errors.New("your token does not show its attestation certificates")

// Chain is the proof's attestation chain, base64url DER, in the order the
// broker reads: the slot attestation whose key is the touch key's, the device
// (f9) certificate that signed it, and the slot attestation whose key is the
// session key's. Any missing is ErrNoAttestation. A slot attestation is a
// certificate with the slot's key that a device certificate on the token
// signed, never just the first with that key: a slot can hold its own
// certificate beside its attestation, with the same key (final review I1).
// The certificates are the token's own statement; the broker verifies them
// against the operator's roots, and nothing here trusts them.
func Chain(certs []*x509.Certificate, touch, session crypto.PublicKey) ([]string, error) {
	for _, device := range certs {
		touchAtt := issuedBy(certs, device, touch)
		sessionAtt := issuedBy(certs, device, session)
		if touchAtt == nil || sessionAtt == nil {
			continue
		}
		enc := base64.RawURLEncoding
		return []string{enc.EncodeToString(touchAtt.Raw), enc.EncodeToString(device.Raw), enc.EncodeToString(sessionAtt.Raw)}, nil
	}
	return nil, ErrNoAttestation
}

// issuedBy is the certificate in certs, other than device, whose key is key and
// whose signature device made. The signature is checked directly, as
// pivattest.Verify does: some f9 certificates carry no basic constraints.
func issuedBy(certs []*x509.Certificate, device *x509.Certificate, key crypto.PublicKey) *x509.Certificate {
	for _, c := range certs {
		if c == device || !sameKey(c.PublicKey, key) || !bytes.Equal(c.RawIssuer, device.RawSubject) {
			continue
		}
		if device.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			return c
		}
	}
	return nil
}

func sameKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// Challenge decodes a challenge as the broker issues it: base64url, 32 bytes.
func Challenge(s string) ([]byte, error) {
	ch, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(ch) != api.MFAChallengeLen {
		return nil, errors.New("the challenge is not one this broker issues")
	}
	return ch, nil
}

// Exporter is the connection's exporter value for a touch proof.
func Exporter(cs tls.ConnectionState) ([]byte, error) {
	ekm, err := cs.ExportKeyingMaterial(api.MFAExporterLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("the connection's exporter value: %w", err)
	}
	return ekm, nil
}

// Sign is the touch key's signature over api.MFAMessage(challenge, ekm), as
// the broker verifies it: the key's touch, up to the token's timeout, happens
// inside. The caller holds no connection across it.
func Sign(touch crypto.Signer, challenge, ekm []byte) ([]byte, error) {
	return api.SignRefresh(touch, api.MFAMessage(challenge, ekm))
}

// Request is POST /v1/mfa's body for a touch proof.
func Request(challenge string, sig []byte, chain []string) ([]byte, error) {
	return json.Marshal(api.MFAProofRequest{Challenge: challenge, Method: "hardware_key_touch",
		Signature: base64.RawURLEncoding.EncodeToString(sig), Attestation: chain})
}

// Post sends body to url on client's connection, and only if that connection's
// exporter value is ekm, the one the signature covers: the exporter value is
// read as the connection is taken, and a request whose connection is not the
// one signed over is cut before its body is written and answered with
// ErrConnectionChanged, so the broker records no refused proof for a
// signature that could never verify (re-review R6). do sends the request: the
// agent's own (which adds its session header) or a workload's client.Do. It
// must refuse redirects (NoRedirect): a proof is posted to the broker named
// and nowhere else. state reads a TLS state off a connection the client
// dialed.
func Post(ctx context.Context, do func(*http.Request) (*http.Response, error), url string, body, ekm []byte,
	state func(net.Conn) (tls.ConnectionState, bool)) (*http.Response, error) {
	var changed, ok atomic.Bool
	// The last connection the transport took is the one the body goes on.
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		match := false
		if cs, has := state(i.Conn); has {
			now, err := Exporter(cs)
			match = err == nil && bytes.Equal(now, ekm)
		}
		ok.Store(match)
		changed.Store(!match)
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, url,
		&gatedBody{r: bytes.NewReader(body), ok: &ok})
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := do(req)
	if changed.Load() {
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return nil, ErrConnectionChanged
	}
	return resp, err
}

// NoRedirect is an http.Client's CheckRedirect that refuses to follow one: the
// 3xx is the answer, and it is not a 200.
func NoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// gatedBody gives no byte of the proof until the connection it will travel on
// is known to be the one signed over.
type gatedBody struct {
	r  io.Reader
	ok *atomic.Bool
}

func (g *gatedBody) Read(p []byte) (int, error) {
	if !g.ok.Load() {
		return 0, ErrConnectionChanged
	}
	return g.r.Read(p)
}
