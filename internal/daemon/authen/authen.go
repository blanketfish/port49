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
	// tags is the window of tag keys a presented token may be tagged under
	// (internal/token). The daemon computes the tag for the peer and compares
	// it before any store access, so a token cut for another device is
	// recognized rather than merely absent (design §8). It is a window and not
	// one key because the tag key is derived from an encryption key: a token
	// must stay acceptable for as long as its store record opens, which is the
	// whole of the crypt read window.
	tags token.TagWindow
}

// New builds the authentication handler. tags are the keys the token tag may be
// derived under (token.TagKey, one per encryption key in the read window); the
// minter's key must be among them, or every token presented is a
// device_mismatch.
func New(s store.Store, e decision.Emitter, l *limits.Limiter, m *metrics.Metrics, now func() time.Time,
	newCtxID func() string, receiptIdleTTL, receiptMaxAge, contextTTL, indexTTL time.Duration,
	tags token.TagWindow) *Handler {
	return &Handler{store: s, log: e, limits: l, metrics: m, now: now, newCtxID: newCtxID,
		receiptIdleTTL: receiptIdleTTL, receiptMaxAge: receiptMaxAge, contextTTL: contextTTL,
		indexTTL: indexTTL, tags: tags}
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
		if tag, ok := token.Parse(presented); ok && !s.h.tags.Matches(tag, s.peer.NAS) {
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
		// The ceiling the token was minted with, read through the one helper
		// the authorizer's clamp also uses: a zero MaxPrivilege is no ceiling,
		// not a ceiling of zero (store.Context.PrivilegeCeiling).
		if ceiling, ok := c.PrivilegeCeiling(); ok && s.start.PrivLvl > ceiling {
			return s.fail(ctx, rec, decision.CeilingExceeded)
		}
		// Defense in depth, and a high-signal event worth alerting on
		// (spec §5.6). rem_addr is a bare address on both platforms measured.
		if c.RemAddr != "" && remAddr != "" && c.RemAddr != remAddr {
			return s.fail(ctx, rec, decision.RemAddrMismatch)
		}
		// Revocation and the session ceiling are checked HERE, not left to the
		// authorizer. `enable: auto` consults no token at all, so nothing else
		// on this path would ever look: the context alone decides. On a
		// per-command platform Task 10 would catch it on the next command, but
		// a session-only platform asks once at login and never again (spec §13,
		// decision 21; measured over 26 Junos sessions,
		// tests/lab/results/L18-*.md), and there the enable exchange is the
		// last decision port49 gets to make about this shell.
		if !c.RevokedAt.IsZero() {
			return s.fail(ctx, rec, decision.CredentialRevoked)
		}
		if !c.SessionExpires.IsZero() && s.h.now().After(c.SessionExpires) {
			return s.fail(ctx, rec, decision.SessionExpired)
		}
		// `auto` PASSes on the context alone, any password accepted (spec §7).
		// That is only safe because `enable_username: enab` cannot load
		// (config.Load), so this context is always the operator's own and never
		// a shared `$enab15$` pseudo-user's.
		if c.Enable == "auto" {
			return s.escalate(ctx, rec, ck, decision.EscalationGranted)
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
		// A receipt replays only onto the context it was written for (spec
		// §5.6). The check is here, before the extension, so a refused
		// presentation does not slide the window on its way to the refusal.
		switch live, ok, lerr := s.receiptContext(ctx, ck, r.CtxID, enable, incumbent); {
		case lerr != nil:
			return s.storeError(rec)
		case !ok:
			return s.fail(ctx, rec, decision.TokenSpent)
		case !live.RevokedAt.IsZero():
			// Answered from what the context says now, not from what the
			// receipt stored: a revoked context admits nothing, whether the
			// revocation landed after the login or the login wrote it (spec
			// §5.6). Refused before the extension, so it does not slide.
			return s.revoked(ctx, rec, live.Principal, live.CtxID, live.RevokedAt)
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
		// The live context is the one this receipt was written for (checked
		// above), so the replay acts on it. For an enable that means replaying
		// the escalation's EFFECT and not only its answer: the privilege may
		// never have landed if that escalation's SetPrivilege failed. The gate
		// above already re-checked the mechanism, the ceiling, revocation,
		// expiry and rem_addr against the live context, so this grants nothing
		// the cold path would not. A receipt marked Failed replays its
		// refusal, whatever Status it was written with.
		if enable && r.Status == wire.AuthenStatusPass && !r.Failed {
			return s.escalate(ctx, rec, ck, decision.ReceiptReplayed)
		}
		return s.replay(ctx, rec, r)
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
	// The receipt carries the ctx_id this redemption lands on, so that id is
	// settled before the redemption rather than after it: the receipt is what
	// answers a retransmission, and a ctx_id minted here and stored nowhere
	// would be replayed into the log naming a context that does not exist.
	// An escalation keeps the context's id (spec §5.6 row 1, §7). A login
	// joins the live context when it may (spec §5.6), and then it is that
	// context's id too; otherwise it is a fresh one.
	//
	// The login's read is here, before the token is spent, for a second
	// reason: a store that cannot be reached cannot say whether there is a
	// context to join, and JoinContext below would fail on it anyway.
	// Refusing now leaves the token unspent, so the operator's retry works
	// once the store is back, instead of replaying a PASS that nothing backs.
	// A record that is there but will not open — sealed under a key that has
	// left the window — is not that: it is replaced, with a fresh id
	// (store.UnreadableContextError; spec §5.6).
	//
	// The read and JoinContext's own are not one operation, and when they
	// disagree the receipt names the id predicted here while the redeem
	// record names the one written. Three ways: the context is reclaimed,
	// replaced by another principal's login, or carried past its ceiling,
	// between the two; or — the one
	// that needs no other principal — two first logins by the same principal
	// both read nothing, both mint an id, and the one whose swap loses joins
	// the other's context. Its receipt then names an id no context holds, so
	// its retransmission is refused `token_spent` (receiptContext) and the
	// device prompts again. Each needs two logins under one username on one
	// device inside a few milliseconds.
	ctxID := incumbent.CtxID
	var login store.Context
	// revokedAt is set when the login would join a context whose revocation
	// its token, minted before it, cannot lift (store.CarryRevocation). Such a
	// login is refused `credential_revoked`, the enable gate's answer for the
	// same state (spec §5.6), before anything is written to the context. The
	// token is still spent, and the receipt records the refusal: a retry of a
	// token the revocation was meant to stop must not get a second chance.
	// This is the case the login can see before it writes; the check after
	// the join below catches the ones it cannot.
	var revokedAt time.Time
	if !enable {
		login = s.loginContext(winner, username, port, remAddr)
		prev, perr := s.h.store.GetContext(ctx, ck)
		s.h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(perr)).Inc()
		var unreadable *store.UnreadableContextError
		switch {
		case perr == nil && store.Joinable(prev, login, s.h.now()):
			// The receipt names the context this login predicts it joins,
			// but the login's own context still gets an id of its own.
			// JoinContext decides again after the token is spent: a join
			// keeps the live id whatever login carries (store.Join starts
			// from the live record), and a replace — the ceiling passed, or
			// another principal's login landed, in between — writes login
			// as it is. Carrying the predicted id there would write the
			// fresh context under the id it displaced, and one ctx_id would
			// name two contexts.
			ctxID = prev.CtxID
			login.CtxID = s.h.newCtxID()
			revokedAt = store.CarryRevocation(prev.RevokedAt, winner.MintedAt)
		case perr == nil || errors.Is(perr, store.ErrNotFound) || errors.As(perr, &unreadable):
			ctxID = s.h.newCtxID()
			login.CtxID = ctxID
		default:
			return s.storeError(rec)
		}
	}
	// The retention is deliberately longer than both bounds: a presentation
	// past a bound has to find the receipt in order to be answered
	// `token_spent` rather than `token_not_found` (store.Receipt; spec §5.7).
	now := s.h.now()
	status := uint8(wire.AuthenStatusPass)
	if !revokedAt.IsZero() {
		status = wire.AuthenStatusFail
	}
	receipt := store.Receipt{CredentialSHA256: credHash, Status: status, CtxID: ctxID,
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
				// An enable replays onto the context it was written for, as a
				// retransmission does. A login that lost is not checked: it
				// presented the winner's own credential, and the winner's
				// JoinContext is still in flight, so a read here would race the
				// winner's write and refuse the duplicate for nothing. It can
				// therefore answer PASS from the receipt of a winner that, after
				// its join, is refused credential_revoked, if it reads the receipt
				// before the winner's FailReceipt lands: the one replay the §5.6
				// rule does not reach. It takes two byte-identical
				// presentations inside one join; every authorization on the
				// revoked context is denied, and the next retransmission reads
				// the live context and is refused (plan 3, pre-flight F16).
				if enable {
					switch _, ok, lerr := s.receiptContext(ctx, ck, r.CtxID, enable, incumbent); {
					case lerr != nil:
						return s.storeError(rec)
					case !ok:
						return s.fail(ctx, rec, decision.TokenSpent)
					}
				}
				// The concurrent-escalation case, and it has the same shape as
				// the retransmission above: the winner's receipt says PASS, but
				// only replaying the effect puts the privilege on the context
				// this session actually read.
				if enable && r.Status == wire.AuthenStatusPass && !r.Failed {
					return s.escalate(ctx, rec, ck, decision.ReceiptReplayed)
				}
				return s.replay(ctx, rec, r)
			}
			return s.fail(ctx, rec, decision.TokenNotFound)
		}
		return s.storeError(rec)
	}

	// The enable token is spent and the receipt is written under this
	// context's own ctx_id: all that is left is the new privilege. This
	// returns above the join deliberately — an escalation displaces no
	// context, so `replaced_ctx_id` must stay absent on its record.
	if enable {
		return s.escalate(ctx, rec, ck, decision.EscalationGranted)
	}
	// Refused, and nothing is written to the context: it is revoked already,
	// and a join would only swap in a broker decision nobody may use.
	if !revokedAt.IsZero() {
		return s.revoked(ctx, rec, winner.Principal, ctxID, revokedAt)
	}

	// Join, or write fresh (spec §5.6). A live context of the same principal
	// is this operator's other window on this device, and the login merges
	// into it: the ctx_id, the privilege already granted, the bound sessions
	// and a revocation the token predates are all kept, so window A loses
	// nothing to window B. Another principal under the same username, or a
	// context past its ceiling, is replaced, and the record names the ctx_id
	// it displaced. A record the sealing layer cannot open is replaced too,
	// keeping its plaintext revocation, and the record says it was unreadable
	// because its ctx_id is sealed. JoinContext reads, merges and swaps on the
	// revision it read, so a revocation or annotation landing mid-login is
	// merged rather than erased, and two simultaneous logins both land.
	out, err := store.JoinContext(ctx, s.h.store, ck, login, winner.MintedAt, s.h.now(), s.h.contextTTL)
	s.h.metrics.StoreOps.WithLabelValues("join_context", storeOutcome(err)).Inc()
	if err != nil {
		// The token is already redeemed, but without a context a later authorization
		// request has nothing to check against: ERROR, not a PASS we can't back up.
		return s.storeError(rec)
	}
	rec.Session.ReplacedCtxID = out.Replaced
	rec.Session.ReplacedUnreadable = out.ReplacedUnreadable
	if out.ClampedFrom != 0 {
		rec.Session.PrivilegeClamped = &decision.PrivilegeClamp{From: out.ClampedFrom, To: out.Context.PrivLvl}
	}
	// A replace unindexes the credential it displaced before this login is
	// indexed. The index keeps every sid and certificate a context was
	// indexed under, so that a join stays revocable by either login's; left
	// in place after a replace, the displaced login's would keep reaching
	// this context, and a back-channel logout of that principal would revoke
	// this one (spec §5.6). A failure is counted and does not fail the login:
	// what it leaves is a revocation that can reach too far, never one that
	// cannot reach.
	//
	// Another principal's replace clears every key the ref was indexed
	// under (UnindexRef), not only what Prior names: a joined context was
	// indexed under each of its logins' sids and certificates, and the record
	// keeps only the last login's. Nothing of the displaced principal's is
	// this login's to keep. An unreadable replace does the same, because it
	// has no Prior to compare — the displaced record's principal and
	// credential are sealed — and anything it left would be re-stamped by
	// every extension of this context for as long as it lives, not only until
	// index_ttl. When the unreadable record was this principal's own, its own
	// keys go too, and the IndexContext below puts this login's back.
	//
	// The same principal's replace — past its ceiling — unindexes only the
	// keys this login does not share. A key both logins hold is one this
	// login is about to index anyway, and unindexing it first would leave a
	// moment in which a revocation by it finds nothing, and the context
	// written in that moment would never be marked. An earlier joined
	// login's sid that Prior does not name stays, and a revocation of it can
	// mark this context: the same person, and fail-closed.
	ref := store.ContextRef{NAS: s.peer.NAS, Username: username}
	switch {
	case out.ReplacedUnreadable:
		uerr := s.h.store.UnindexRef(ctx, ref)
		s.h.metrics.StoreOps.WithLabelValues("unindex_ref", storeOutcome(uerr)).Inc()
	case out.Prior.CtxID == "":
	case out.Prior.Principal != winner.Principal:
		uerr := s.h.store.UnindexRef(ctx, ref)
		s.h.metrics.StoreOps.WithLabelValues("unindex_ref", storeOutcome(uerr)).Inc()
	default:
		sid := out.Prior.Credential.Sid
		certKey := store.CertKey(out.Prior.Credential.Issuer, out.Prior.Credential.Serial)
		if sid == winner.Credential.Sid {
			sid = ""
		}
		if certKey == store.CertKey(winner.Credential.Issuer, winner.Credential.Serial) {
			certKey = ""
		}
		if sid != "" || certKey != "" {
			uerr := s.h.store.UnindexContext(ctx, "", sid, certKey, ref)
			s.h.metrics.StoreOps.WithLabelValues("unindex_context", storeOutcome(uerr)).Inc()
		}
	}
	// Indexed under this login's credential even on a join, and added to what
	// the context was indexed under rather than replacing it: revocation by
	// either login's sid or certificate has to reach the joined context.
	err = s.h.store.IndexContext(ctx, winner.Principal, winner.Credential.Sid,
		store.CertKey(winner.Credential.Issuer, winner.Credential.Serial), ref, s.h.indexTTL)
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
	// One check on what the login actually wrote (spec §5.6). The pre-read
	// refuses the case it can see before writing; three it cannot see end
	// here: the same principal's context past its ceiling, replaced carrying a
	// revocation the token predates; a record under a retired key, replaced
	// carrying its plaintext revocation; and a revocation that landed between
	// the pre-read and the join, merged by it. Each wrote a context whose every
	// authorization is denied, so a PASS would put a permit in the log for a
	// login that can do nothing, with nothing on it saying why. The token is
	// spent.
	//
	// The receipt was written PASS before the join, so the refusal marks it
	// failed (FailReceipt). A retransmission is refused credential_revoked
	// while the context is revoked (receiptContext), and replays the refusal
	// after a token minted later has lifted the revocation on the same ctx_id
	// (decision 15): the token the revocation was meant to stop gets no
	// second try either way. A mark that does not land is counted and put on
	// the record; the answer is still FAIL, and what is lost is only the
	// replay after a lift. ErrNotFound lost nothing: a revocation by principal
	// deleted the receipt, and a deleted receipt replays nothing.
	//
	// After the index bookkeeping, not before: the context exists and is
	// revoked, and a revocation of this credential must still reach it.
	//
	// A revocation that lands after the join's swap is not seen here, and that
	// login answers PASS; its first authorization is denied.
	if !out.Context.RevokedAt.IsZero() {
		ferr := s.h.store.FailReceipt(ctx, rk)
		s.h.metrics.StoreOps.WithLabelValues("fail_receipt", storeOutcome(ferr)).Inc()
		if ferr != nil && !errors.Is(ferr, store.ErrNotFound) {
			lost := "receipt not marked failed; a retransmission after the revocation is lifted will replay PASS"
			if rec.IndexError != "" {
				lost = rec.IndexError + "; " + lost
			}
			rec.IndexError = lost
		}
		return s.revoked(ctx, rec, winner.Principal, out.Context.CtxID, out.Context.RevokedAt)
	}
	rec.Principal = winner.Principal
	rec.Session.CtxID = out.Context.CtxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}

// loginContext is the context this login would create on its own, in its
// §5.1.1 shape: everything a later authorization has to answer from without
// reaching the broker again. Its CtxID is left for the caller. JoinContext
// writes it as it is on a first login and merges it into the live context on
// a second.
func (s *Session) loginContext(winner *store.Token, username, port, remAddr string) store.Context {
	now := s.h.now()
	c := store.Context{Principal: winner.Principal, Username: username,
		Port: port, RemAddr: remAddr, PrivLvl: s.start.PrivLvl, BlobHash: winner.BlobHash,
		Credential: winner.Credential, AuthTime: winner.AuthTime, RefreshedAt: now,
		LastTouchedAt: now, Enable: winner.Enable, MaxPrivilege: winner.MaxPrivilege, CreatedAt: now}
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
		c.SessionExpires = winner.AuthTime.Add(winner.MaxSessionAge)
	}
	return c
}

// receiptContext reports whether a replayed receipt may act, and returns the
// live context it would act on: whether the ctx_id it froze is still the live
// context's (spec §5.6). The join keeps ctx_id across one principal's logins,
// so a match is exactly "the context this receipt was written for", and a
// mismatch is a context replaced — another principal, past its ceiling,
// unreadable — or reclaimed since. A receipt for a context that no longer
// exists answers nothing that exists: PASS from it would admit a session whose
// authorizations answer from someone else's context, or raise that context
// with another principal's enable.
//
// The context is returned because a match is not the whole answer: a context
// revoked since the receipt was written — or revoked by the login that wrote
// it — admits nothing, and the caller refuses the replay on it.
//
// An enable already holds the live context from its gate; a login reads it.
// The error is a store error only — an absent or unopenable context is a
// plain no.
func (s *Session) receiptContext(ctx context.Context, ck store.ContextKey, receiptCtxID string,
	enable bool, incumbent store.Context) (store.Context, bool, error) {
	if enable {
		return incumbent, incumbent.CtxID == receiptCtxID, nil
	}
	c, err := s.h.store.GetContext(ctx, ck)
	s.h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(err)).Inc()
	var unreadable *store.UnreadableContextError
	switch {
	case err == nil:
		return c, c.CtxID == receiptCtxID, nil
	case errors.Is(err, store.ErrNotFound), errors.As(err, &unreadable):
		return store.Context{}, false, nil
	default:
		return store.Context{}, false, err
	}
}

// revoked refuses a login, or its retransmission, into a revoked context:
// FAIL `credential_revoked`, the enable gate's answer for the same state, with
// the revocation on the record so the refusal explains itself (spec §5.6).
func (s *Session) revoked(ctx context.Context, rec decision.Record, principal, ctxID string,
	at time.Time) (wire.AuthenReply, bool) {
	rec.Principal = principal
	rec.Session.CtxID = ctxID
	rec.Session.RevokedAt = decision.FormatTime(at)
	return s.fail(ctx, rec, decision.CredentialRevoked)
}

// escalate records the new privilege on the incumbent context and keeps
// everything else, ctx_id foremost: an escalation is not a new session, so the
// log join across it must not depend on replaced_ctx_id (spec §5.6 row 1, §7).
//
// SetPrivilege and TouchContext, never PutContext, and deliberately WITHOUT the
// store.Context this request read at the top of the enable. Writing that record
// back is how a revocation landing mid-enable is erased: RevokeByPrincipal
// stamps RevokedAt and deletes this principal's receipts, the re-put restores a
// copy whose RevokedAt is zero, and nothing ever sets it again — the receipts
// that would have re-marked it are already gone. The operator is told one
// context was touched, the authorizer reads a zero RevokedAt, and the session
// keeps authorizing for the rest of the idle TTL with nothing in the log
// connecting the two. The same write would discard an accounting annotation, a
// session discriminator and a broker refresh.
//
// The two narrow setters between them write exactly what an escalation is
// entitled to change — the level, and the expiry this exchange's activity
// extends — and they cannot erase a field they do not name (store.Store's
// comment on TouchContext). Nothing is indexed here either: the context was
// indexed when it was created, and the principal, sid and certificate it is
// indexed under have not changed; TouchContext carries those entries forward.
//
// reason is a parameter because a replayed escalation re-applies this same
// effect under ReceiptReplayed: the decision is replayed, and so is what it did.
func (s *Session) escalate(ctx context.Context, rec decision.Record, ck store.ContextKey,
	reason decision.Reason) (wire.AuthenReply, bool) {
	err := s.h.store.SetPrivilege(ctx, ck, s.start.PrivLvl)
	s.h.metrics.StoreOps.WithLabelValues("set_privilege", storeOutcome(err)).Inc()
	if err != nil {
		// On the token path the enable token is already spent, but without the
		// new privilege on the context every later authorization would answer
		// from the old one: ERROR, not a PASS the context cannot back up. The
		// retransmission that follows replays through the receipt and lands the
		// privilege then, because that path escalates rather than only
		// reporting. ErrNotFound is one of these: the context is gone, and so
		// is the escalation.
		return s.storeError(rec)
	}
	// The extension is this exchange's activity, not the escalation itself. A
	// context reclaimed or revoked between the two writes denies this session on
	// its next authorization on its own terms, so the outcome is counted and the
	// PASS stands on the privilege that did land — the same reading author.Handle
	// gives its own TouchContext.
	terr := s.h.store.TouchContext(ctx, ck, s.h.contextTTL)
	s.h.metrics.StoreOps.WithLabelValues("touch_context", storeOutcome(terr)).Inc()
	return s.finish(rec, wire.AuthenStatusPass, reason)
}

// replay answers from a receipt's stored decision. A refusal — a login refused
// `credential_revoked`, written FAIL before its join or marked Failed after it
// (spec §5.6) — replays as a refusal does, after the failure delay and with its
// server_msg, so a device that retransmits it learns nothing a FAIL would not
// have told it.
func (s *Session) replay(ctx context.Context, rec decision.Record, r store.Receipt) (wire.AuthenReply, bool) {
	rec.Session.CtxID = r.CtxID
	if r.Failed || r.Status == wire.AuthenStatusFail {
		return s.fail(ctx, rec, decision.ReceiptReplayed)
	}
	return s.finish(rec, r.Status, decision.ReceiptReplayed)
}

// storeOutcome maps a store error to the StoreOps metric's outcome label.
func storeOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.As(err, new(*store.UnreadableContextError)):
		// The record is there and the store answered; the sealing layer
		// could not open it. Counted apart from "error" so a key rotation
		// does not read as a store outage (spec §5.6).
		return "unreadable"
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
