package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// Per-login MFA at the broker (spec §5.1.5; §13 decision 45 rulings 12–19):
// a mint under a requirement is answered with a challenge, the person
// proves it at POST /v1/mfa, and the mint is made again naming it.

const (
	// mfaChallengeTTL is how long a challenge, and the proved record that
	// follows it, are kept.
	mfaChallengeTTL = 5 * time.Minute
	// mfaProofTTL is how long a proof is kept for reuse: the longest
	// reuse_for a policy may say (policy.maxMFAReuse).
	mfaProofTTL = 8 * time.Hour
	// maxMFABody bounds POST /v1/mfa's body: a touch proof carries three
	// certificates and a signature.
	maxMFABody = 64 << 10
)

// MFAVerifiers is broker.identity.per_login_mfa resolved: nil Anchors means
// hardware_key_touch is unavailable here; idp_mfa is available while a
// human OIDC verifier is configured. Anchors is the operator's roots file
// alone: no certificate a request carries is ever added to it.
type MFAVerifiers struct {
	Anchors   *pivattest.Anchors
	AMR       []string // default ["mfa"]
	ACRValues string
}

// perLoginMFA is the verifiers in force now. The roots are swapped whole at a SIGHUP, so
// a reader takes the pointer once and uses it; nothing it points to is ever written.
func (b *Broker) perLoginMFA() *MFAVerifiers {
	b.mfaMu.RLock()
	defer b.mfaMu.RUnlock()
	return b.PerLoginMFA
}

// AttestationRoots is the roots in force now, nil for none.
func (b *Broker) AttestationRoots() *pivattest.Anchors {
	if m := b.perLoginMFA(); m != nil {
		return m.Anchors
	}
	return nil
}

// SetAttestationRoots puts a (nil for none) in force as the roots a touch is verified
// against, keeping AMR and ACRValues, while the broker serves: port49d and port49-broker
// call it at SIGHUP with the file re-read (spec §5.1.6: "add the root or intermediate to
// attestation_roots_file, then reload").
func (b *Broker) SetAttestationRoots(a *pivattest.Anchors) {
	b.mfaMu.Lock()
	defer b.mfaMu.Unlock()
	next := MFAVerifiers{}
	if b.PerLoginMFA != nil {
		next = *b.PerLoginMFA
	}
	next.Anchors = a
	b.PerLoginMFA = &next
}

// mfaTouch reports whether this broker verifies a hardware_key_touch.
func (b *Broker) mfaTouch() bool {
	v := b.perLoginMFA()
	return v != nil && v.Anchors != nil && v.Anchors.Roots != nil
}

// mfaIdP reports whether this broker verifies an idp_mfa.
func (b *Broker) mfaIdP() bool {
	return b.Identity != nil && len(b.Identity.Humans()) > 0
}

// mfaAMR is the amr values an idp_mfa proof may carry (RFC 8176).
func (b *Broker) mfaAMR() []string {
	if v := b.perLoginMFA(); v != nil && len(v.AMR) > 0 {
		return v.AMR
	}
	return []string{"mfa"}
}

// mfaVerified is the methods this broker verifies now, in the vocabulary's
// order.
func (b *Broker) mfaVerified() []policy.MFAMethod {
	var out []policy.MFAMethod
	if b.mfaTouch() {
		out = append(out, policy.HardwareKeyTouch)
	}
	if b.mfaIdP() {
		out = append(out, policy.IdPMFA)
	}
	return out
}

// MFAUnavailable is decision 45 ruling 18's statement for pol at now: one
// line naming the devices where a requirement accepts no method this broker
// verifies, so every login it applies to there is denied
// per_login_mfa_unavailable, or "" when every requirement has one. port49d
// says it at its start and at each swap, once per policy; it never refuses
// either.
func (b *Broker) MFAUnavailable(pol *policy.Policy, now time.Time) string {
	const named = 10
	var devices, accepts []string
	var touchRemedy, idpRemedy bool // which method an unmet accept could be cured by
	for _, d := range pol.MFARequirements(now) {
		unmet := false
		for _, r := range d.Requirements {
			if len(b.mfaUsable(r)) > 0 {
				continue
			}
			unmet = true
			touchRemedy = touchRemedy || r.Accepts(policy.HardwareKeyTouch)
			// A machine proves only hardware_key_touch: an OIDC verifier
			// cures nothing for it.
			idpRemedy = idpRemedy || (r.Accepts(policy.IdPMFA) && !r.Machine)
			a := "[" + strings.Join(methodNames(r.Accept), ", ") + "]"
			if r.Machine {
				a += " for machines"
			}
			if !slices.Contains(accepts, a) {
				accepts = append(accepts, a)
			}
		}
		if unmet {
			devices = append(devices, d.Device)
		}
	}
	if len(devices) == 0 {
		return ""
	}
	list := strings.Join(devices[:min(len(devices), named)], ", ")
	if len(devices) > named {
		list += fmt.Sprintf(" and %d more", len(devices)-named)
	}
	verified := "none"
	if v := b.mfaVerified(); len(v) > 0 {
		verified = strings.Join(methodNames(v), ", ")
	}
	var remedies []string
	if touchRemedy {
		remedies = append(remedies, "broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file loads "+
			"(hardware_key_touch, the only method a machine proves)")
	}
	if idpRemedy {
		remedies = append(remedies, "a human OIDC verifier is configured (idp_mfa)")
	}
	return fmt.Sprintf("per_login_mfa: %d device(s) require accept %s, and this broker verifies %s: %s; "+
		"every login the requirement applies to there is denied per_login_mfa_unavailable until %s",
		len(devices), strings.Join(accepts, ", "), verified, list, strings.Join(remedies, " or "))
}

// mfaConfig is GET /v1/config's per_login_mfa, nil when none is verified.
func (b *Broker) mfaConfig() *api.MFAConfig {
	methods := b.mfaVerified()
	if len(methods) == 0 {
		return nil
	}
	c := &api.MFAConfig{Methods: methodNames(methods)}
	if v := b.perLoginMFA(); v != nil {
		c.ACRValues = v.ACRValues
	}
	return c
}

func methodNames(ms []policy.MFAMethod) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = string(m)
	}
	return out
}

// mfaSum is the hex SHA-256 of parts, a zero byte between each.
func mfaSum(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// challengeKey and provedKey are the store keys of a challenge and its
// proved record, each over its binding, so a caller computing another's
// key finds nothing and spends nothing (re-review R1):
// "plm-challenge/" + hex SHA-256(ch ‖ 0 ‖ principal) and
// "plm-proved/" + hex SHA-256(ch ‖ 0 ‖ principal ‖ 0 ‖ fingerprint ‖ 0 ‖ agentSHA256).
func challengeKey(ch []byte, principal string) string {
	return "plm-challenge/" + mfaSum(string(ch), principal)
}

func provedKey(ch []byte, principal, fingerprint, agentSHA256 string) string {
	return "plm-proved/" + mfaSum(string(ch), principal, fingerprint, agentSHA256)
}

// proofKey is the reuse key, over agent_sha256, never the raw session
// (re-review R2).
func proofKey(principal, fingerprint, agentSHA256 string, m policy.MFAMethod) string {
	return mfaSum(principal, fingerprint, agentSHA256) + "/" + string(m)
}

// mfaTokenKey is an idp_mfa sign-in's once-only key: its ID token's SHA-256,
// so the store never holds a token.
func mfaTokenKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "mfa_token " + hex.EncodeToString(sum[:])
}

// agentKey is the hex SHA-256 of the request's agent session (the 32 bytes
// of Port49-Agent-Session), "" for a caller with none: a workload, a 7h
// bearer. Such a caller keeps no reusable proof; each request proves. The
// raw session is never kept or compared.
func agentKey(r *http.Request) string {
	v := r.Header.Get(api.AgentSessionHeader)
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) != 32 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// callerAgentKey is agentKey for c's request, and "" for a bearer whatever
// header it sends: a bearer keeps no reusable proof (ruling 15).
func callerAgentKey(c caller, r *http.Request) string {
	if c.oidc != nil {
		return ""
	}
	return agentKey(r)
}

// challengeRecord is what a challenge's once-only record holds: its
// binding. agent_sha256 is the hash of the agent session, never the value
// (PutOnce is not sealed).
type challengeRecord struct {
	Principal   string `json:"principal"`
	Fingerprint string `json:"fingerprint"`
	AgentSHA256 string `json:"agent_sha256"`
}

// provedRecord is what a proved challenge's once-only record holds.
type provedRecord struct {
	Method string    `json:"method"`
	At     time.Time `json:"at"`
}

// provedChallenge is the proof made for the challenge a mint names, taken
// once for the request.
type provedChallenge struct {
	Method policy.MFAMethod
	At     time.Time
	// AgentSHA256 is the agent hash of the binding that proved. It is set
	// only on the proof a context records (the held proof of a refresh).
	AgentSHA256 string
}

// mfaRequest is one mint request's per-login state: the caller's agent
// session hash, the proof its named challenge took, and the one challenge
// the request issues, lazily, for the first item that needs it.
type mfaRequest struct {
	agentSHA256 string
	proved      *provedChallenge
	// takeErr is the named challenge's proved record failing to be read: an
	// item under a requirement is then store_unavailable, never asked again.
	takeErr error

	ch      []byte
	exp     time.Time
	chErr   error
	chTried bool
}

// issueChallenge stores a new challenge bound to c and the agent session.
func (b *Broker) issueChallenge(ctx context.Context, c caller, agentSHA256 string) ([]byte, time.Time, error) {
	ch := make([]byte, api.MFAChallengeLen)
	if _, err := rand.Read(ch); err != nil {
		return nil, time.Time{}, err
	}
	rec, err := json.Marshal(challengeRecord{Principal: c.principal, Fingerprint: c.cred.Fingerprint, AgentSHA256: agentSHA256})
	if err != nil {
		return nil, time.Time{}, err
	}
	ok, err := b.Store.PutOnce(ctx, challengeKey(ch, c.principal), rec, mfaChallengeTTL)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !ok {
		return nil, time.Time{}, errors.New("broker: a new challenge collided with a live one")
	}
	return ch, b.Now().Add(mfaChallengeTTL), nil
}

// requestChallenge is the request's challenge, issued on first use.
func (b *Broker) requestChallenge(ctx context.Context, c caller, mf *mfaRequest) ([]byte, time.Time, error) {
	if !mf.chTried {
		mf.chTried = true
		mf.ch, mf.exp, mf.chErr = b.issueChallenge(ctx, c, mf.agentSHA256)
	}
	return mf.ch, mf.exp, mf.chErr
}

// takeProved takes the proved record of the challenge a mint names, under
// the key its own caller computes: another caller's challenge, or this
// one's under another certificate or agent, finds nothing and spends
// nothing (re-review R1). Nil with no error is no proof.
func (b *Broker) takeProved(ctx context.Context, c caller, agentSHA256, challenge string) (*provedChallenge, error) {
	ch, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(ch) != api.MFAChallengeLen {
		return nil, nil
	}
	raw, err := b.Store.TakeOnce(ctx, provedKey(ch, c.principal, c.cred.Fingerprint, agentSHA256))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	var rec provedRecord
	if json.Unmarshal(raw, &rec) != nil {
		return nil, nil
	}
	return &provedChallenge{Method: policy.MFAMethod(rec.Method), At: rec.At}, nil
}

// proofMeets reports whether a per-login proof by method, made at provedAt,
// meets req for a mint at at: req accepts the method, a machine's is a touch
// (ruling 21), and the proof is the mint's own fresh challenge, which covers
// it once whatever reuse_for is, or a reused one made within req.ReuseFor
// before at. It is the one reading of a proof the mint (mfaCovers, judgeMFA)
// and a refresh's judgment of an unspent token (minted.mints) share; at and
// provedAt are on one minter's clock, so no clock across replicas enters it.
func proofMeets(req policy.MFARequirement, method policy.MFAMethod, fresh bool, provedAt, at time.Time) bool {
	return req.Accepts(method) && (!req.Machine || method == policy.HardwareKeyTouch) &&
		(fresh || (req.ReuseFor > 0 && at.Sub(provedAt) < req.ReuseFor))
}

// mfaCovers says whether a proof covers req for this caller now: the
// challenge's own proof named by the mint (once, whatever reuse_for), else
// a kept proof whose method req accepts, made within req.ReuseFor.
// agentSHA256 is the hex SHA-256 of the caller's agent session, "" for none.
// A store error is returned, never read as "not covered".
func (b *Broker) mfaCovers(ctx context.Context, c caller, agentSHA256 string, req policy.MFARequirement,
	proved *provedChallenge, now time.Time) (method string, at time.Time, reused bool, err error) {
	if proved != nil && proofMeets(req, proved.Method, true, proved.At, now) {
		return string(proved.Method), proved.At, false, nil
	}
	if agentSHA256 == "" || req.ReuseFor <= 0 {
		return "", time.Time{}, false, nil
	}
	for _, m := range req.Accept {
		p, err := b.Store.GetMFAProof(ctx, proofKey(c.principal, c.cred.Fingerprint, agentSHA256, m))
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			return "", time.Time{}, false, err
		}
		if proofMeets(req, m, false, p.At, now) && (method == "" || p.At.After(at)) {
			method, at, reused = string(m), p.At, true
		}
	}
	return method, at, reused, nil
}

// mfaVerdict is what judging a requirement came to for one item.
type mfaVerdict struct {
	// rec is the record's per_login_mfa part, nil when there is none to say.
	rec *decision.PerLoginMFA
	// reason is why the item is denied, "" when a proof covers it.
	reason decision.Reason
	detail string
	item   *api.PerLoginMFA
	// method and at are the proof that covered it; agent is the request's
	// agent hash, the binding that proved ("" for a bearer). fresh is a proof
	// made for the mint's own challenge, not one reused (Credential.MFAFresh).
	method string
	at     time.Time
	agent  string
	fresh  bool
}

// mfaUsable is req.Accept narrowed to what this broker verifies now, and a
// machine's to a touch alone (ruling 21).
func (b *Broker) mfaUsable(req policy.MFARequirement) []policy.MFAMethod {
	var out []policy.MFAMethod
	for _, m := range b.mfaVerified() {
		if req.Accepts(m) && (!req.Machine || m == policy.HardwareKeyTouch) {
			out = append(out, m)
		}
	}
	return out
}

// judgeMFA judges the requirement req on device name for c: covered by a
// proof, answered with a challenge, unavailable, or store_unavailable (a
// store error is never "not covered", pre-flight minor 1). held is the proof
// a live context records (a session refresh reads it, spec §5.1.5; nil for a
// mint): it covers when it was made by a usable method req accepts, reuse_for
// has not passed since, and the request's agent session is the one that
// proved (a bearer, or a context recording none, is never covered: ruling 15),
// and only when no named or kept proof does.
func (b *Broker) judgeMFA(ctx context.Context, c caller, mf *mfaRequest, name string, req policy.MFARequirement,
	now time.Time, held *provedChallenge) mfaVerdict {
	secs := int(req.ReuseFor / time.Second)
	rec := &decision.PerLoginMFA{Accept: methodNames(req.Accept), ReuseForSeconds: &secs, Levels: levelNames(req)}
	count := func(method, outcome string) { b.Metrics.PerLoginMFA.WithLabelValues(method, outcome).Inc() }
	usable := b.mfaUsable(req)
	if len(usable) == 0 {
		count("none", "unavailable")
		return mfaVerdict{rec: rec, reason: decision.PerLoginMFAUnavailable, detail: fmt.Sprintf(
			"%s asks for a second factor at each login, and this broker verifies none of the methods it accepts (%s); "+
				"tell the operator", name, strings.Join(methodNames(req.Accept), ", "))}
	}
	// A store error is store_unavailable under the requirement, so its
	// record names the requirement too (decision 45 ruling 19).
	if mf.takeErr != nil {
		return mfaVerdict{rec: rec, reason: decision.StoreUnavailable}
	}
	// Only what is usable now covers: a proof for a method this broker no
	// longer verifies is no proof.
	narrowed := req
	narrowed.Accept = usable
	method, at, reused, err := b.mfaCovers(ctx, c, mf.agentSHA256, narrowed, mf.proved, now)
	if err != nil {
		return mfaVerdict{rec: rec, reason: decision.StoreUnavailable}
	}
	if method == "" && held != nil && proofMeets(narrowed, held.Method, false, held.At, now) &&
		mf.agentSHA256 != "" && mf.agentSHA256 == held.AgentSHA256 {
		method, at, reused = string(held.Method), held.At, true
	}
	if method != "" {
		rec.Method, rec.ProvedAt, rec.Reused = method, decision.FormatTime(at), reused
		if reused {
			count(method, "reused")
		}
		return mfaVerdict{rec: rec, method: method, at: at, agent: mf.agentSHA256, fresh: !reused}
	}
	ch, exp, err := b.requestChallenge(ctx, c, mf)
	if err != nil {
		return mfaVerdict{rec: rec, reason: decision.StoreUnavailable}
	}
	count("none", "required")
	item := &api.PerLoginMFA{Device: name, Challenge: base64.RawURLEncoding.EncodeToString(ch),
		ExpiresAt: exp.UTC().Format(time.RFC3339), Accept: methodNames(req.Accept), Methods: methodNames(usable),
		ReuseForSeconds: secs, ReuseFrom: req.ReuseFrom}
	for _, l := range req.Levels {
		item.Levels = append(item.Levels, api.MFALevel{Level: l.Level, Accept: methodNames(l.Accept),
			ReuseForSeconds: int(l.ReuseFor / time.Second)})
	}
	return mfaVerdict{rec: rec, reason: decision.PerLoginMFARequired, item: item, detail: askText(name, req, usable)}
}

func levelNames(req policy.MFARequirement) []string {
	out := make([]string, len(req.Levels))
	for i, l := range req.Levels {
		out[i] = l.Level
	}
	return out
}

// askText is decision 45 ruling 17's sentence: who asks, which level accepts
// what, and how long a proof covers.
func askText(name string, req policy.MFARequirement, usable []policy.MFAMethod) string {
	levels := make([]string, len(req.Levels))
	for i, l := range req.Levels {
		levels[i] = fmt.Sprintf("%s accepts %s", l.Level, strings.Join(methodNames(l.Accept), ", "))
	}
	return fmt.Sprintf("%s asks for a second factor at each login: %s (reuse %s, from %s); prove one of %s at "+
		"POST /v1/mfa, then mint again naming the challenge", name, strings.Join(levels, "; "),
		reuseText(req.ReuseFor), req.ReuseFrom, strings.Join(methodNames(usable), ", "))
}

// reuseText is d as a policy writes it: 15m, 1h, 0m.
func reuseText(d time.Duration) string {
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	if strings.HasSuffix(s, "m") && strings.Contains(s, "h") {
		s = strings.TrimSuffix(s, "0m")
	}
	if s == "" {
		return "0m"
	}
	return s
}

// mfaProve is POST /v1/mfa (decision 45 rulings 12–15): a touch on the held
// connection, or an ID token as the bearer over a fresh one. The proof is
// judged against the challenge's own record, found under the caller's own
// binding; the binding it is kept under is that record's, never the
// request's (an idp_mfa post carries no certificate and no agent session).
func (b *Broker) mfaProve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMFABody+1))
	if err != nil || len(body) > maxMFABody {
		writeError(w, http.StatusBadRequest, "bad_request", "the request body could not be read or is over 64 KiB")
		return
	}
	var req api.MFAProofRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a proof: "+printsafe.Line(err.Error(), 200))
		return
	}
	method := policy.MFAMethod(req.Method)
	switch {
	case method != policy.HardwareKeyTouch && method != policy.IdPMFA:
		writeError(w, http.StatusBadRequest, "bad_request", "method is hardware_key_touch or idp_mfa")
		return
	case !slices.Contains(b.mfaVerified(), method):
		b.Metrics.PerLoginMFA.WithLabelValues(string(method), "unavailable").Inc()
		writeError(w, http.StatusBadRequest, "bad_request", "this broker verifies no "+string(method)+
			" proof (see per_login_mfa in GET /v1/config)")
		return
	}
	count := func(outcome string) { b.Metrics.PerLoginMFA.WithLabelValues(string(method), outcome).Inc() }

	var c caller
	var raw string // the ID token, for idp_mfa
	if method == policy.HardwareKeyTouch {
		var ok bool
		if c, ok = b.authenticate(w, r, decision.EventPerLoginMFA, "recorded no proof"); !ok {
			return
		}
	} else {
		hasCert := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		tok, has, berr := bearerOf(r)
		if hasCert {
			writeError(w, http.StatusBadRequest, "bad_request", "an idp_mfa proof is posted with no client certificate: "+
				"its ID token is the one credential")
			return
		}
		if !has || berr != nil {
			b.emit(decision.Record{TS: b.Now(), Event: decision.EventPerLoginMFA, Verdict: decision.VerdictDeny,
				Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "oidc"}})
			writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved),
				"an idp_mfa proof is a sign-in: send its ID token as the bearer (Authorization: Bearer)")
			return
		}
		raw = tok
		var ok bool
		if c, ok = b.bearerCaller(w, r, decision.EventPerLoginMFA, "recorded no proof", raw); !ok {
			return
		}
	}

	now := b.Now()
	ch, decodeErr := base64.RawURLEncoding.DecodeString(req.Challenge)
	chHash := sha256.Sum256([]byte(req.Challenge))
	if decodeErr == nil {
		chHash = sha256.Sum256(ch)
	}
	part := &decision.PerLoginMFA{Method: string(method), ChallengeSHA256: hex.EncodeToString(chHash[:])}
	refuse := func(cause string) {
		count("refused")
		b.emit(decision.Record{TS: now, Event: decision.EventPerLoginMFA, Verdict: decision.VerdictDeny,
			Reason: decision.PerLoginMFARefused, Principal: c.principal, Auth: c.auth(), PerLoginMFA: part})
		writeError(w, http.StatusUnauthorized, string(decision.PerLoginMFARefused), cause)
	}
	storeDownSaying := func(detail string) {
		b.emit(decision.Record{TS: now, Event: decision.EventPerLoginMFA, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: c.principal, Auth: c.auth(), PerLoginMFA: part})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), detail)
	}
	storeDown := func() {
		storeDownSaying("the broker could not judge your proof, so it recorded none; ask again and prove again")
	}
	if decodeErr != nil || len(ch) != api.MFAChallengeLen {
		refuse("the challenge is not one this broker issued")
		return
	}
	const unknown = "the challenge is unknown, spent or expired, or was issued to another caller; mint again for a new one"

	var touch *touchProof
	if method == policy.HardwareKeyTouch {
		if c.oidc != nil {
			refuse("a touch proves on the held connection of the certificate that holds the session key, not as a bearer")
			return
		}
		var cause string
		if touch, cause = parseTouch(req); cause != "" {
			refuse(cause)
			return
		}
	} else {
		a := c.oidc
		skew := b.Identity.Timing.ClockSkew
		switch {
		case a.Domain != oidc.Humans:
			refuse("a machine proves by hardware_key_touch alone")
			return
		case a.Nonce != api.MFANonce(ch):
			refuse("the sign-in's nonce does not name this challenge: sign in again from the challenge " +
				"(`port49 login` does)")
			return
		case a.AuthTime.After(a.IssuedAt.Add(skew)):
			refuse("your identity provider's token says you authenticated after it issued the token; such a " +
				"token is no sign-in")
			return
		case a.IssuedAt.Sub(a.AuthTime) > issueFresh+skew || now.Sub(a.AuthTime) > issueFresh+skew:
			refuse(fmt.Sprintf("your identity provider last authenticated you at %s, over %s ago: it did not ask you "+
				"to sign in again; sign in again", a.AuthTime.UTC().Format(time.RFC3339), issueFresh))
			return
		case !slices.ContainsFunc(a.AMR, func(v string) bool { return slices.Contains(b.mfaAMR(), v) }):
			refuse(fmt.Sprintf("your sign-in's amr shows no second factor: this broker accepts %s",
				strings.Join(b.mfaAMR(), ", ")))
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	// The challenge is taken under this caller's own binding: another
	// caller's challenge is not found, so a wrong caller's post spends
	// nothing (re-review R1).
	recRaw, err := b.Store.TakeOnce(ctx, challengeKey(ch, c.principal))
	switch {
	case errors.Is(err, store.ErrNotFound):
		refuse(unknown)
		return
	case err != nil:
		storeDown()
		return
	}
	var bind challengeRecord
	if json.Unmarshal(recRaw, &bind) != nil || bind.Principal != c.principal {
		refuse(unknown)
		return
	}
	if method == policy.HardwareKeyTouch {
		// The post must come from the connection's own certificate and the
		// agent the challenge was issued to.
		if bind.Fingerprint != c.cred.Fingerprint || bind.AgentSHA256 != callerAgentKey(c, r) {
			refuse("the proof is not from the certificate and agent session the challenge was issued to")
			return
		}
		if cause := b.verifyTouch(r, touch, ch, now); cause != "" {
			refuse(cause)
			return
		}
	} else {
		switch first, err := b.Store.PutOnce(ctx, mfaTokenKey(raw), nil, b.Identity.Timing.MaxTokenAge); {
		case err != nil:
			storeDown()
			return
		case !first:
			refuse("this sign-in was used as a proof already; sign in again")
			return
		}
	}

	prov, _ := json.Marshal(provedRecord{Method: string(method), At: now})
	if _, err := b.Store.PutOnce(ctx, provedKey(ch, c.principal, bind.Fingerprint, bind.AgentSHA256), prov,
		mfaChallengeTTL); err != nil {
		storeDown()
		return
	}
	// Kept for reuse under the challenge record's binding for both methods:
	// an idp_mfa post has no certificate and no agent session of its own
	// (re-review R2). A caller with no agent session keeps none.
	if bind.AgentSHA256 != "" {
		if err := b.Store.PutMFAProof(ctx, store.MFAProof{
			Key: proofKey(c.principal, bind.Fingerprint, bind.AgentSHA256, method), Method: string(method), At: now},
			mfaProofTTL); err != nil {
			// The proved record is written: it covers the mint that names
			// this challenge, once, and nothing after it (final review
			// broker minor 4).
			storeDownSaying("the broker recorded your proof for this challenge but could not keep it for reuse; " +
				"mint again naming the challenge, and a later login proves again")
			return
		}
	}
	count("proved")
	b.emit(decision.Record{TS: now, Event: decision.EventPerLoginMFA, Verdict: decision.VerdictPermit,
		Reason: decision.PerLoginMFAProved, Principal: c.principal, Auth: c.auth(), PerLoginMFA: part})
	writeJSON(w, http.StatusOK, api.MFAProofResponse{Method: string(method), ProvedAt: now.UTC().Format(time.RFC3339)})
}

// touchProof is a hardware_key_touch proof parsed.
type touchProof struct {
	sig                   []byte
	touch, device, sessnl *x509.Certificate
}

// parseTouch reads a touch proof's signature and its three attestation
// certificates, [touch slot, f9 device, session slot]: exactly three, so
// nothing else a request carries can be read as a link in a chain.
func parseTouch(req api.MFAProofRequest) (*touchProof, string) {
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil || len(sig) == 0 {
		return nil, "a touch proof carries the signature, base64url"
	}
	if len(req.Attestation) != 3 {
		return nil, "a touch proof carries three attestation certificates: the touch slot's, the device's (f9) and the session slot's"
	}
	certs := make([]*x509.Certificate, 3)
	for i, s := range req.Attestation {
		der, err := base64.RawURLEncoding.DecodeString(s)
		if err == nil {
			certs[i], err = x509.ParseCertificate(der)
		}
		if err != nil {
			return nil, fmt.Sprintf("attestation certificate %d is not base64url DER", i+1)
		}
	}
	return &touchProof{sig: sig, touch: certs[0], device: certs[1], sessnl: certs[2]}, ""
}

var touchPolicyNames = map[byte]string{pivattest.TouchNever: "never", pivattest.TouchCached: "cached", pivattest.TouchAlways: "always"}

// verifyTouch judges a per-login touch proof against the held connection
// (decision 45 ruling 12), "" when it holds: the touch key signed this
// challenge over this connection's exporter value (verifyTouchMessage).
func (b *Broker) verifyTouch(r *http.Request, p *touchProof, ch []byte, now time.Time) string {
	cause, _ := b.verifyTouchMessage(r, p, api.MFAExporterLabel, func(ekm []byte) []byte {
		return api.MFAMessage(ch, ekm)
	}, now)
	return cause
}

// verifyTouchMessage judges a touch proof over msg(ekm), ekm being the held
// connection's exporter value under label, "" when it holds: both slot
// attestations chain, through the one device certificate, to the operator's
// roots; the touch key's policy is always-touch; the session slot's key is
// this connection's client key; and the touch key signed msg(ekm). The roots
// are the operator's alone: no request certificate is added to them. A
// per-login proof and an admin proof differ in label and message, and in
// nothing else. A refusal returns its cause, which may quote what the caller
// sent and belongs in the API answer alone, and why, one fixed word (§5.7's
// admin_touch set) that is safe in a record.
func (b *Broker) verifyTouchMessage(r *http.Request, p *touchProof, label string, msg func(ekm []byte) []byte,
	now time.Time) (cause, why string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "a touch proves on a held connection that presented the session key's certificate", "no_client_certificate"
	}
	ekm, err := r.TLS.ExportKeyingMaterial(label, nil, 32)
	if err != nil {
		return "this connection cannot export keying material", "no_exporter"
	}
	v := b.perLoginMFA()
	if v == nil || v.Anchors == nil {
		// swapped away between the gate and here
		return "no attestation roots are configured", "touch_slot_chain"
	}
	anchors := *v.Anchors
	ta, err := pivattest.Verify(anchors, p.device, p.touch, now)
	if err != nil {
		return "the touch slot's attestation does not verify: " + printsafe.Line(err.Error(), 300), "touch_slot_chain"
	}
	sa, err := pivattest.Verify(anchors, p.device, p.sessnl, now)
	if err != nil {
		return "the session slot's attestation does not verify: " + printsafe.Line(err.Error(), 300), "session_slot_chain"
	}
	// Both slots verified against the one device certificate in the proof,
	// so what can differ is the serial each slot certificate names.
	if ta.Serial != sa.Serial {
		return "the touch key and the session key are not attested by the same device", "device_mismatch"
	}
	if ta.TouchPolicy != pivattest.TouchAlways {
		return fmt.Sprintf("the touch key's attestation must carry touch policy always (it says %s)",
			touchPolicyNames[ta.TouchPolicy]), "touch_policy"
	}
	eq, ok := sa.Key.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !eq.Equal(r.TLS.PeerCertificates[0].PublicKey) {
		return "the session slot's key is not this connection's client key: a touch proves from the token that " +
			"holds it", "session_key"
	}
	alg, ok := api.RefreshAlgorithm(ta.Key)
	if !ok || p.touch.CheckSignature(alg, msg(ekm), p.sig) != nil {
		return "the signature is not the touch key's over this challenge and this connection's exporter value",
			"bad_signature"
	}
	return "", ""
}
