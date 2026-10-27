package broker

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/printsafe"
)

// An admin-level call needs its right and a proof that a person is at the
// security key, made for that one request (spec §5.1.6; §13 decision 54
// ruling 15): a call with no proof is answered with a challenge, and the
// retry carries a proof of it over its own method, path and body, on the
// connection that was asked.

const (
	// adminChallengeTTL is how long a challenge is kept, in memory.
	adminChallengeTTL = 2 * time.Minute
	// maxAdminProofHeader bounds the proof header: three certificates, a
	// signature and a challenge, base64url twice.
	maxAdminProofHeader = 16 << 10
)

// adminEntry is a challenge kept: the connection it was issued on and its end.
type adminEntry struct {
	conn string
	exp  time.Time
}

// adminChallenges is the broker's memory of the challenges it issued, one
// mutex over both maps. byKey holds each challenge under the key §5.1.6
// names, so another caller, connection or request misses it; byConn holds
// the key a connection's challenge is under, so a connection holds one and a
// new one replaces the last. A challenge leaves by being taken (once), by its
// end, by its connection's close and by being replaced. The zero value is
// ready.
type adminChallenges struct {
	mu     sync.Mutex
	byKey  map[string]adminEntry
	byConn map[string]string
	// judging, when set, is called between taking a challenge and judging its
	// proof. Tests only.
	judging atomic.Pointer[func()]
}

// put keeps key for conn until exp, dropping what conn held and what has
// ended.
func (g *adminChallenges) put(conn, key string, exp, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.byKey == nil {
		g.byKey, g.byConn = map[string]adminEntry{}, map[string]string{}
	}
	for k, e := range g.byKey {
		if !now.Before(e.exp) {
			g.drop(k, e)
		}
	}
	if old, ok := g.byConn[conn]; ok {
		g.drop(old, g.byKey[old])
	}
	g.byKey[key], g.byConn[conn] = adminEntry{conn: conn, exp: exp}, key
}

// take spends key: true for the one caller that finds it, before its end.
func (g *adminChallenges) take(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.byKey[key]
	if !ok {
		return false
	}
	g.drop(key, e)
	return now.Before(e.exp)
}

// closed drops what conn held.
func (g *adminChallenges) closed(conn string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if key, ok := g.byConn[conn]; ok {
		g.drop(key, g.byKey[key])
	}
}

// drop removes key; the caller holds mu.
func (g *adminChallenges) drop(key string, e adminEntry) {
	delete(g.byKey, key)
	if g.byConn[e.conn] == key {
		delete(g.byConn, e.conn)
	}
}

// len is how many challenges are held.
func (g *adminChallenges) len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.byKey)
}

// adminKey is a challenge's key: hex SHA-256(challenge ‖ 0 ‖ exporter ‖ 0 ‖
// principal ‖ 0 ‖ fingerprint ‖ 0 ‖ request_sha256).
func adminKey(ch, ekm []byte, principal, fingerprint string, request [32]byte) string {
	h := sha256.New()
	for i, part := range [][]byte{ch, ekm, []byte(principal), []byte(fingerprint), request[:]} {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// connClosed is a ConnState: a closed connection's challenge is dropped. The
// connection's exporter value names it, as it does in the challenge's key.
// It chains after closeIdleWithoutCertificate and never replaces it.
func (b *Broker) connClosed(c net.Conn, s http.ConnState) {
	if s != http.StateClosed && s != http.StateHijacked {
		return
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	cs := tc.ConnectionState()
	if ekm, err := cs.ExportKeyingMaterial(api.AdminExporterLabel, nil, 32); err == nil {
		b.admin.closed(hex.EncodeToString(ekm))
	}
}

// AdminTouchUnavailable is the line port49-broker and port49d say, at start
// and at every reload, where a subject holds an admin-level right (spec §12):
// "" when roots are loaded.
func (b *Broker) AdminTouchUnavailable() string {
	if b.mfaTouch() {
		return ""
	}
	return "no attestation roots are configured " +
		"(broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file): every admin operation " +
		"will be refused until they are"
}

// adminGate is the proof an admin-level call needs, after its right. It
// returns true only when a proof made for this exact request verified and
// was taken; otherwise it has written the 401 or 503 and the admin_touch
// record. c is the caller authenticate found, and op and target are what the
// challenge shows the person. It runs before the request takes the revocation
// slot or touches the store, so a touch never holds the slot and a refused
// proof changes nothing. It logs and counts the proof's outcome and never a
// challenge, signature or attestation.
func (b *Broker) adminGate(w http.ResponseWriter, r *http.Request, c caller, body []byte, op, target string) bool {
	if b.skipAdminProof {
		return true
	}
	now := b.Now()
	emit := func(verdict string, reason decision.Reason, chSHA, why string) {
		b.emit(decision.Record{TS: now, Event: decision.EventAdminTouch, Verdict: verdict, Reason: reason,
			Principal: c.principal, Auth: c.auth(),
			Admin: &decision.Admin{Operation: op, Target: target, ChallengeSHA256: chSHA, Why: why}})
	}
	refuse := func(chSHA, cause string) bool {
		b.Metrics.AdminTouch.WithLabelValues("refused").Inc()
		emit(decision.VerdictDeny, decision.AdminTouchRefused, chSHA, cause)
		writeError(w, http.StatusUnauthorized, string(decision.AdminTouchRefused), cause)
		return false
	}
	if !b.mfaTouch() {
		b.Metrics.AdminTouch.WithLabelValues("unavailable").Inc()
		emit(decision.VerdictDeny, decision.AdminTouchUnavailable, "", "no attestation roots")
		writeError(w, http.StatusServiceUnavailable, string(decision.AdminTouchUnavailable),
			"no attestation roots are configured "+
				"(broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file); admin operations need them")
		return false
	}
	if c.oidc != nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return refuse("", "an admin call is proved by a touch on a connection that presented your client "+
			"certificate: a bearer token cannot prove, so log in and call through your agent")
	}
	ekm, err := r.TLS.ExportKeyingMaterial(api.AdminExporterLabel, nil, 32)
	if err != nil {
		return refuse("", "this connection cannot export keying material")
	}
	request := api.AdminRequestSHA256(r.Method, r.URL.RequestURI(), body)
	header := r.Header.Get(api.AdminProofHeader)
	if header == "" {
		ch := make([]byte, api.MFAChallengeLen)
		_, _ = rand.Read(ch)
		exp := now.Add(adminChallengeTTL)
		b.admin.put(hex.EncodeToString(ekm), adminKey(ch, ekm, c.principal, c.cred.Fingerprint, request), exp, now)
		sum := sha256.Sum256(ch)
		b.Metrics.AdminTouch.WithLabelValues("required").Inc()
		emit(decision.VerdictDeny, decision.AdminTouchRequired, hex.EncodeToString(sum[:]), "")
		writeJSON(w, http.StatusUnauthorized, api.Error{Error: string(decision.AdminTouchRequired),
			Detail: fmt.Sprintf("this call needs a touch of your security key: %s %s", op, printsafe.Line(target, 200)),
			Admin: &api.AdminChallenge{Operation: op, Target: target, Challenge: base64.RawURLEncoding.EncodeToString(ch),
				ExpiresAt: exp.UTC()}})
		return false
	}

	var proof api.AdminProof
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err == nil && len(header) <= maxAdminProofHeader {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		err = dec.Decode(&proof)
	} else if err == nil {
		err = fmt.Errorf("over %d bytes", maxAdminProofHeader)
	}
	ch, chErr := base64.RawURLEncoding.DecodeString(proof.Challenge)
	chSum := sha256.Sum256([]byte(proof.Challenge))
	if chErr == nil {
		chSum = sha256.Sum256(ch)
	}
	chSHA := hex.EncodeToString(chSum[:])
	if err != nil || chErr != nil || len(ch) != api.MFAChallengeLen {
		return refuse(chSHA, "the "+api.AdminProofHeader+" header is not a proof: base64url JSON with the "+
			"challenge, the signature and three attestation certificates")
	}
	touch, cause := parseTouch(api.MFAProofRequest{Challenge: proof.Challenge, Signature: proof.Signature,
		Attestation: proof.Attestation})
	if cause != "" {
		return refuse(chSHA, cause)
	}
	// The challenge is taken under this caller's, connection's and request's
	// own key, so another's finds nothing and spends nothing.
	if !b.admin.take(adminKey(ch, ekm, c.principal, c.cred.Fingerprint, request), now) {
		return refuse(chSHA, "the challenge is unknown, spent or expired, or was made for another request, "+
			"connection or caller; ask again")
	}
	if h := b.admin.judging.Load(); h != nil {
		(*h)()
	}
	if cause := b.verifyTouchMessage(r, touch, api.AdminExporterLabel, func(ekm []byte) []byte {
		return api.AdminMessage(ch, request, ekm)
	}, now); cause != "" {
		return refuse(chSHA, cause)
	}
	b.Metrics.AdminTouch.WithLabelValues("proved").Inc()
	emit(decision.VerdictPermit, decision.AdminTouchProved, chSHA, "")
	return true
}
