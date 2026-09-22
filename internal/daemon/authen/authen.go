// Package authen runs the RFC 8907 authentication exchange against the token
// set in the store (design §8; spec §5.6, §5.7). It never sees a broker.
package authen

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/token"
)

// Authentication methods, as recorded in a redeem record's auth.method.
const (
	methodPAP   = "pap"
	methodASCII = "ascii"
	methodCHAP  = "chap"
)

type Peer struct {
	NAS      string
	NASAddr  string
	Platform string
}

type Handler struct {
	store    store.Store
	log      decision.Emitter
	limits   *limits.Limiter
	metrics  *metrics.Metrics
	now      func() time.Time
	newCtxID func() string
	// receiptIdleTTL slides a receipt forward on every presentation it
	// answers; receiptMaxAge caps it from the first redemption and never
	// moves. Past either, the presentation is FAIL and `token_spent`
	// (spec §5.7; §13, decision 15).
	receiptIdleTTL time.Duration
	receiptMaxAge  time.Duration
	contextTTL     time.Duration
	// indexTTL is how long a context stays findable by principal, sid, and
	// certificate. It is the reach of revocation (spec §5.1.4), not the life
	// of the context itself.
	indexTTL time.Duration
	// tagKey derives the device tag every minted token carries (internal/token).
	// The daemon computes the tag for the peer and compares it before any
	// store access, so a token cut for another device is recognized rather
	// than merely absent (design §8).
	tagKey []byte
}

// New builds the authentication handler. tagKey is the key the token tag is
// derived under (token.TagKey); it must be the same one the minter uses, or
// every token presented is a device_mismatch.
func New(s store.Store, e decision.Emitter, l *limits.Limiter, m *metrics.Metrics, now func() time.Time,
	newCtxID func() string, receiptIdleTTL, receiptMaxAge, contextTTL, indexTTL time.Duration,
	tagKey []byte) *Handler {
	return &Handler{store: s, log: e, limits: l, metrics: m, now: now, newCtxID: newCtxID,
		receiptIdleTTL: receiptIdleTTL, receiptMaxAge: receiptMaxAge, contextTTL: contextTTL,
		indexTTL: indexTTL, tagKey: tagKey}
}

// phase is a Session's place in a multi-round ASCII exchange. phaseDone is
// terminal: once a session has replied with done == true, any further Start
// or Continue on it takes the unsupported path (ERROR, service_unsupported)
// rather than resuming a finished exchange.
type phase int

const (
	phaseStart phase = iota
	phaseGetUser
	phaseGetPass
	phaseDone
)

type Session struct {
	h     *Handler
	peer  Peer
	start wire.AuthenStart
	user  string // as typed
	phase phase
}

func (h *Handler) NewSession(peer Peer) *Session { return &Session{h: h, peer: peer} }

// Start begins an authentication session. A zero Status in the reply together
// with done == true means: send nothing to the NAS and close out the session
// (the connection layer, Task 14, honors that).
func (s *Session) Start(ctx context.Context, p wire.AuthenStart) (wire.AuthenReply, bool) {
	if s.phase == phaseDone {
		return s.unsupported("port49: session already finished")
	}
	s.start = p
	s.user = string(p.User)
	if p.Action != wire.AuthenActionLogin {
		return s.unsupported("port49: only the login action is supported")
	}
	switch p.AuthenType {
	case wire.AuthenTypePAP:
		return s.verify(ctx, methodPAP, p.Data, p.Data)
	case wire.AuthenTypeCHAP:
		return s.verifyCHAP(ctx, p.Data)
	case wire.AuthenTypeASCII:
		if s.user == "" {
			s.phase = phaseGetUser
			return wire.AuthenReply{Status: wire.AuthenStatusGetUser, ServerMsg: []byte("Username: ")}, false
		}
		s.phase = phaseGetPass
		return wire.AuthenReply{Status: wire.AuthenStatusGetPass, Flags: wire.AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}, false
	default:
		return s.unsupported("port49: authentication type not supported")
	}
}

// Continue advances a multi-round ASCII exchange. A zero Status in the reply
// together with done == true means: send nothing to the NAS (the ABORT case
// below); the connection layer (Task 14) honors that.
func (s *Session) Continue(ctx context.Context, p wire.AuthenContinue) (wire.AuthenReply, bool) {
	if p.Flags&wire.AuthenContinueFlagAbort != 0 {
		s.phase = phaseDone
		return wire.AuthenReply{}, true
	}
	switch s.phase {
	case phaseGetUser:
		s.user = string(p.UserMsg)
		s.phase = phaseGetPass
		return wire.AuthenReply{Status: wire.AuthenStatusGetPass, Flags: wire.AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}, false
	case phaseGetPass:
		return s.verify(ctx, methodASCII, p.UserMsg, p.UserMsg)
	}
	return s.unsupported("port49: unexpected CONTINUE")
}

// verify handles PAP and ASCII, where the presented credential is the token itself.
func (s *Session) verify(ctx context.Context, method string, presented, secret []byte) (wire.AuthenReply, bool) {
	return s.redeem(ctx, method, presented, func(t store.Token) bool {
		return subtle.ConstantTimeCompare(t.Secret, secret) == 1
	})
}

func (s *Session) verifyCHAP(ctx context.Context, data []byte) (wire.AuthenReply, bool) {
	if len(data) < 1+1+md5.Size {
		// Too short to carry ppp_id, a challenge, and a 16-byte response: it cannot
		// match anything, so it fails the same way an unmatched credential does.
		credHash := sha256.Sum256(data)
		return s.fail(ctx, s.newRecord(methodCHAP, credHash), decision.TokenNotFound)
	}
	id, challenge, response := data[0], data[1:len(data)-md5.Size], data[len(data)-md5.Size:]
	return s.redeem(ctx, methodCHAP, data, func(t store.Token) bool {
		m := md5.New()
		m.Write([]byte{id})
		m.Write(t.Secret)
		m.Write(challenge)
		return subtle.ConstantTimeCompare(m.Sum(nil), response) == 1
	})
}

// newRecord builds the redeem record shared by every outcome for the current
// session. method is empty for outcomes that never inspected a credential (an
// unsupported action/type, or a packet in the wrong phase), in which case
// credHash is ignored.
func (s *Session) newRecord(method string, credHash [32]byte) decision.Record {
	rec := decision.Record{TS: s.h.now(), Event: decision.EventRedeem,
		Device: &decision.Device{NAS: s.peer.NASAddr, Name: s.peer.NAS, Platform: s.peer.Platform},
		Session: &decision.Session{Port: string(s.start.Port), RemAddr: string(s.start.RemAddr),
			Privilege: s.start.PrivLvl, Username: Canonical(s.user)}}
	if method != "" {
		rec.Auth = &decision.Auth{Method: method, CredentialSHA256: hex.EncodeToString(credHash[:])}
	}
	return rec
}

func (s *Session) redeem(ctx context.Context, method string, presented []byte, match func(store.Token) bool) (wire.AuthenReply, bool) {
	credHash := sha256.Sum256(presented)
	rec := s.newRecord(method, credHash)

	username := Canonical(s.user)
	if username == "" {
		// Nothing under an empty username could ever be minted: fail without
		// touching the store.
		return s.fail(ctx, rec, decision.TokenNotFound)
	}

	// The device tag is compared before any store access (design §8): a token
	// cut for another device is recognized rather than merely absent, and the
	// event is high-signal because it does not fire during normal operation.
	// A credential that is not token-shaped — a mistyped password — skips this
	// and reaches token_not_found through the store.
	//
	// CHAP is excluded by method rather than by shape. `presented` there is
	// ppp_id ‖ challenge ‖ response, and nothing stops that being Len bytes of
	// base62 by accident; the daemon never sees the token under CHAP, so there
	// is no tag to be wrong and the outcome must stay token_not_found.
	if method != methodCHAP {
		if tag, ok := token.Parse(presented); ok &&
			subtle.ConstantTimeCompare([]byte(tag), []byte(token.Tag(s.h.tagKey, s.peer.NAS))) != 1 {
			return s.fail(ctx, rec, decision.DeviceMismatch)
		}
	}

	port := string(s.start.Port)
	remAddr := string(s.start.RemAddr)

	// An enable START is not a login, so its record is an `escalate`. The kind
	// is settled here, before the receipt is looked up, not after: it is part
	// of the receipt key, so a login receipt cannot answer an enable START
	// (store.ReceiptKey). A login token for a login START, an enable token for
	// an enable START.
	enable := s.start.Service == wire.AuthenServiceEnable
	kind := store.KindLogin
	if enable {
		kind = store.KindEnable
		rec.Event = decision.EventEscalate
	}
	ck := store.ContextKey{NAS: s.peer.NAS, Username: username}

	// An enable START is a second authentication under the same username on the
	// same device (measured: tests/lab/results/L3-arista_eos.md,
	// L3-cisco_iosxe.md). It therefore lands on this operator's own login
	// context, and it must update privilege IN PLACE: plan 1 wrote a fresh
	// ctx_id over it, which spec §5.6 row 1 and §7 both forbid.
	//
	// The gate is read before the receipt, so `auto` never consults a token and
	// a context that has since lost its ceiling cannot be escalated out of a
	// receipt written while it still had one.
	var incumbent store.Context
	if enable {
		c, err := s.h.store.GetContext(ctx, ck)
		s.h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(err)).Inc()
		switch {
		case errors.Is(err, store.ErrNotFound):
			// There is nothing to escalate. An enable is never a way in.
			return s.fail(ctx, rec, decision.ContextMissing)
		case err != nil:
			return s.storeError(rec)
		}
		incumbent = c
		rec.Principal = c.Principal
		rec.Session.CtxID = c.CtxID
		// An empty Enable is a token minted before any enable mode was set, and
		// it is read as `none`: the closed default denies rather than guesses.
		if c.Enable == "none" || c.Enable == "" {
			return s.fail(ctx, rec, decision.EnableRefused)
		}
		if s.start.PrivLvl > c.MaxPrivilege {
			return s.fail(ctx, rec, decision.CeilingExceeded)
		}
		// Defense in depth, and a high-signal event worth alerting on
		// (spec §5.6). rem_addr is a bare address on both platforms measured.
		if c.RemAddr != "" && remAddr != "" && c.RemAddr != remAddr {
			return s.fail(ctx, rec, decision.RemAddrMismatch)
		}
		// `auto` PASSes on the context alone, any password accepted (spec §7).
		// That is only safe because `enable_username: enab` cannot load
		// (config.Load), so this context is always the operator's own and never
		// a shared `$enab15$` pseudo-user's.
		if c.Enable == "auto" {
			return s.escalate(ctx, rec, ck, incumbent)
		}
	}

	rk := store.ReceiptKey{NAS: s.peer.NAS, Username: username, Kind: kind, CredentialSHA256: credHash}

	// 1. Receipt: a byte-identical retransmission replays. The credential hash
	// is in the key, so a different credential misses here and goes on to
	// redeem a token of its own rather than colliding with this receipt.
	r, err := s.h.store.GetReceipt(ctx, rk)
	s.h.metrics.StoreOps.WithLabelValues("get_receipt", storeOutcome(err)).Inc()
	switch {
	case err == nil:
		// The key already selected on the hash; this re-checks what came back.
		// subtle, not ==, for the same reason every other credential
		// comparison in this package uses it: these are attacker-influenced
		// values, and one rule is easier to audit than an exception. A store
		// that answers with a record it was not asked for is a store fault,
		// and replaying it would hand out a decision made for another
		// credential, so it fails rather than passes (spec §5.7).
		if subtle.ConstantTimeCompare(r.CredentialSHA256[:], credHash[:]) != 1 {
			return s.fail(ctx, rec, decision.CredentialMismatch)
		}
		now := s.h.now()
		capAt := r.FirstRedeemedAt.Add(s.h.receiptMaxAge)
		// Two bounds, one outcome. A job that keeps presenting the same
		// credential slides the idle bound; nothing slides the cap.
		//
		// The explicit cap check and the clamp below are deliberately
		// redundant: the clamp alone suffices given config.Load refusing
		// receipt_idle_ttl > receipt_max_age, but New is exported and takes
		// raw durations, so a caller that never went through Load gets the
		// bound from the check rather than from an invariant that did not run.
		if !now.Before(capAt) || !now.Before(r.IdleExpiresAt) {
			return s.fail(ctx, rec, decision.TokenSpent)
		}
		next := now.Add(s.h.receiptIdleTTL)
		if next.After(capAt) {
			next = capAt
		}
		err = s.h.store.ExtendReceipt(ctx, rk, next)
		s.h.metrics.StoreOps.WithLabelValues("extend_receipt", storeOutcome(err)).Inc()
		switch {
		case errors.Is(err, store.ErrNotFound):
			// Not "it was swept": it cannot have been. RetainUntil is
			// receipt_max_age + receipt_idle_ttl from the first redemption and
			// both bounds passed two statements ago, so this receipt was inside
			// its retention when it was read and is inside it now. The only
			// other thing that deletes a receipt is DeleteReceiptsByPrincipal,
			// which is revocation (spec §5.1.4; Task 13). So ErrNotFound here
			// means exactly one thing — this principal was revoked between the
			// read and the extend — and the answer to that is not a PASS.
			return s.fail(ctx, rec, decision.TokenSpent)
		case err != nil:
			// Any other store error is ERROR, not a PASS: the receipt did not
			// slide, so the next presentation would silently get a fresh window.
			return s.storeError(rec)
		}
		rec.Session.CtxID = r.CtxID
		return s.finish(rec, r.Status, decision.ReceiptReplayed)
	case !errors.Is(err, store.ErrNotFound):
		return s.storeError(rec)
	}

	// 2. Candidates under (nas, username), filtered by the kind settled above.
	// A credential that matches a token of the other kind is a kind mismatch,
	// not a missing token.
	cands, err := s.h.store.Candidates(ctx, store.TokenKey{NAS: s.peer.NAS, Username: username})
	s.h.metrics.StoreOps.WithLabelValues("candidates", storeOutcome(err)).Inc()
	if err != nil {
		return s.storeError(rec)
	}
	var winner *store.Token
	for i := range cands {
		if cands[i].Kind == kind && match(cands[i]) {
			winner = &cands[i]
			break
		}
	}
	if winner == nil {
		for i := range cands {
			if cands[i].Kind != kind && match(cands[i]) {
				return s.fail(ctx, rec, decision.TokenKindMismatch)
			}
		}
		return s.fail(ctx, rec, decision.TokenNotFound)
	}

	// 3. Atomic redemption; the loser of a race adopts the winner's receipt.
	//
	// An escalation keeps the context's id (spec §5.6 row 1, §7), and the
	// receipt has to carry that id rather than a fresh one: the receipt is what
	// answers a retransmitted enable, and a ctx_id minted here and stored
	// nowhere would be replayed into the log naming a context that does not
	// exist. `enable` is false on every login path, where this is plan 1's
	// behaviour unchanged.
	ctxID := incumbent.CtxID
	if !enable {
		ctxID = s.h.newCtxID()
	}
	// The retention is deliberately longer than both bounds: a presentation
	// past a bound has to find the receipt in order to be answered
	// `token_spent` rather than `token_not_found` (store.Receipt; spec §5.7).
	now := s.h.now()
	receipt := store.Receipt{CredentialSHA256: credHash, Status: wire.AuthenStatusPass, CtxID: ctxID,
		FirstRedeemedAt: now, IdleExpiresAt: now.Add(s.h.receiptIdleTTL),
		RetainUntil: now.Add(s.h.receiptMaxAge + s.h.receiptIdleTTL)}
	w := store.ReceiptWrite{Key: rk, Receipt: receipt, Principal: winner.Principal,
		IndexTTL: s.h.receiptMaxAge + s.h.receiptIdleTTL}
	err = s.h.store.RedeemAndReceipt(ctx, store.TokenKey{NAS: s.peer.NAS, Username: username}, winner.ID, w)
	s.h.metrics.StoreOps.WithLabelValues("redeem", storeOutcome(err)).Inc()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			r, rerr := s.h.store.GetReceipt(ctx, rk)
			s.h.metrics.StoreOps.WithLabelValues("get_receipt", storeOutcome(rerr)).Inc()
			if rerr == nil && subtle.ConstantTimeCompare(r.CredentialSHA256[:], credHash[:]) == 1 {
				rec.Session.CtxID = r.CtxID
				return s.finish(rec, r.Status, decision.ReceiptReplayed)
			}
			return s.fail(ctx, rec, decision.TokenNotFound)
		}
		return s.storeError(rec)
	}

	// The enable token is spent and the receipt is written under this
	// context's own ctx_id: all that is left is the new privilege. This
	// returns above the `prev` read deliberately — an escalation displaces no
	// context, so `replaced_ctx_id` must stay absent on its record.
	if enable {
		return s.escalate(ctx, rec, ck, incumbent)
	}

	// A context already under this key is this operator's own earlier login on
	// this device: the key cannot tell two of their shells apart, and no wire
	// field can either (spec §15, L1). The overwrite is benign — same
	// principal, same privilege, same blob — but it must not be silent, so the
	// record names the ctx_id it displaces (spec §5.6).
	//
	// This read and the write below are not atomic. Two simultaneous
	// redemptions by one user on one device can both read the same `prev` and
	// both report it, and then one of the two new contexts is overwritten with
	// nothing naming it — the silence `replaced_ctx_id` exists to prevent, in
	// the one case it cannot cover. Closing it needs a compare-and-set on
	// PutContext, which the store interface does not have; plan 2 owns whether
	// to add one.
	prev, perr := s.h.store.GetContext(ctx, ck)
	s.h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(perr)).Inc()
	if perr == nil {
		rec.Session.ReplacedCtxID = prev.CtxID
	}

	// The context carries what the token was minted with, in its §5.1.1 shape:
	// everything a later authorization has to answer from without reaching the
	// broker again.
	newCtx := store.Context{CtxID: ctxID, Principal: winner.Principal, Username: username,
		Port: port, RemAddr: remAddr, PrivLvl: s.start.PrivLvl, BlobHash: winner.BlobHash,
		Credential: winner.Credential, AuthTime: winner.AuthTime, RefreshedAt: s.h.now(),
		LastTouchedAt: s.h.now(),
		Enable:        winner.Enable, MaxPrivilege: winner.MaxPrivilege, CreatedAt: s.h.now()}
	// A zero MaxSessionAge is `max_session_age: never` and must stay
	// expressible (spec §5.6): it leaves SessionExpires zero, which Task 10
	// reads as no ceiling rather than as expired at the epoch.
	//
	// Nothing else is guarded here, and a token carrying a ceiling with no
	// AuthTime to anchor it is deliberately left to compute a SessionExpires
	// in the distant past. That denies, loudly and visibly, where dropping the
	// ceiling instead would hand out an unbounded session that looks exactly
	// like a legitimate `never` and that nothing logs.
	if winner.MaxSessionAge > 0 {
		newCtx.SessionExpires = winner.AuthTime.Add(winner.MaxSessionAge)
	}
	err = s.h.store.PutContext(ctx, ck, newCtx, s.h.contextTTL)
	s.h.metrics.StoreOps.WithLabelValues("put_context", storeOutcome(err)).Inc()
	if err != nil {
		// The token is already redeemed, but without a context a later authorization
		// request has nothing to check against: ERROR, not a PASS we can't back up.
		return s.storeError(rec)
	}
	err = s.h.store.IndexContext(ctx, winner.Principal, winner.Credential.Sid,
		store.CertKey(winner.Credential.Issuer, winner.Credential.Serial),
		store.ContextRef{NAS: s.peer.NAS, Username: username}, s.h.indexTTL)
	s.h.metrics.StoreOps.WithLabelValues("index_context", storeOutcome(err)).Inc()
	// An index write that fails does not fail the login: the operator is
	// authenticated and the context exists. What is lost is reach — a later
	// revocation will not find this context — so it is counted AND put on the
	// record that is about to be emitted anyway. That record carries the ctx_id
	// and the principal, which is the join an incident responder needs; the
	// metric only says it happened somewhere on the fleet.
	if err != nil {
		rec.IndexError = "context not indexed; revocation by sid, principal or certificate will not reach it"
	}
	rec.Principal = winner.Principal
	rec.Session.CtxID = ctxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}

// escalate records the new privilege on the incumbent context and keeps
// everything else, ctx_id foremost: an escalation is not a new session, so the
// log join across it must not depend on replaced_ctx_id (spec §5.6 row 1, §7).
// Nothing is indexed here either — the context was indexed when it was created,
// and the principal, sid and certificate it is indexed under have not changed.
func (s *Session) escalate(ctx context.Context, rec decision.Record, ck store.ContextKey, c store.Context) (wire.AuthenReply, bool) {
	c.PrivLvl = s.start.PrivLvl
	c.LastTouchedAt = s.h.now()
	err := s.h.store.PutContext(ctx, ck, c, s.h.contextTTL)
	s.h.metrics.StoreOps.WithLabelValues("put_context", storeOutcome(err)).Inc()
	if err != nil {
		// On the token path the enable token is already spent, but without the
		// new privilege on the context every later authorization would answer
		// from the old one: ERROR, not a PASS the context cannot back up.
		return s.storeError(rec)
	}
	return s.finish(rec, wire.AuthenStatusPass, decision.EscalationGranted)
}

// storeOutcome maps a store error to the StoreOps metric's outcome label.
func storeOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	default:
		return "error"
	}
}

// finish records the outcome and ends the session: every path that reaches it
// returns done == true, so phaseDone is set here unconditionally.
func (s *Session) finish(rec decision.Record, status uint8, reason decision.Reason) (wire.AuthenReply, bool) {
	s.phase = phaseDone
	rec.Verdict = decision.VerdictPermit
	if status != wire.AuthenStatusPass {
		rec.Verdict = decision.VerdictDeny
	}
	rec.Reason = reason
	s.h.log.Emit(rec)
	s.h.metrics.Decisions.WithLabelValues(rec.Event, rec.Verdict, string(reason)).Inc()
	return wire.AuthenReply{Status: status}, true
}

// fail replies FAIL after the per-(nas, username) failure delay. The sleep is
// cancellable, but by the server's context, not the connection's: a device
// that hangs up mid-delay does not shorten it, and only shutdown does. The
// delay therefore holds the connection's single read goroutine for its
// duration, which on a single-connect connection is head-of-line blocking for
// every other session on it. That cost is still an open question for the
// project owner.
//
// The ceiling is no longer one. L13 measured device reply timeouts — about 3s
// on both Junos images, 5.0s on vEOS, about 6s on the N9Kv, above 12s on
// IOS-XE — and auth_failure_delay_max now defaults to 2s so that a FAIL is
// delivered while every one of them is still waiting for it (spec §15, L13).
// Past a device's timeout a delayed FAIL is indistinguishable from an
// unreachable server, and the device falls through to the local password.
func (s *Session) fail(ctx context.Context, rec decision.Record, reason decision.Reason) (wire.AuthenReply, bool) {
	delay := s.h.limits.AuthFailure(s.peer.NAS, Canonical(s.user))
	s.h.metrics.AuthFailures.Inc()
	timer := time.NewTimer(delay)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
	}
	rec.ServerMsg = "port49: authentication failed, mint a new token with `port49 token`"
	reply, done := s.finish(rec, wire.AuthenStatusFail, reason)
	reply.ServerMsg = []byte(rec.ServerMsg)
	return reply, done
}

// unsupported replies ERROR and logs one redeem record with reason
// ServiceUnsupported: a non-login action, an authentication type this package
// does not implement, or a packet sent to a session that has already finished
// or is not expecting one.
func (s *Session) unsupported(serverMsg string) (wire.AuthenReply, bool) {
	rec := s.newRecord("", [32]byte{})
	reply, done := s.finish(rec, wire.AuthenStatusError, decision.ServiceUnsupported)
	reply.ServerMsg = []byte(serverMsg)
	return reply, done
}

// storeError replies ERROR and logs one redeem record with reason
// StoreUnavailable, for any store failure other than store.ErrNotFound.
func (s *Session) storeError(rec decision.Record) (wire.AuthenReply, bool) {
	reply, done := s.finish(rec, wire.AuthenStatusError, decision.StoreUnavailable)
	reply.ServerMsg = []byte("port49: store unavailable")
	return reply, done
}
