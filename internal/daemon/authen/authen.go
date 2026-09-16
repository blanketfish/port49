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
	store      store.Store
	log        decision.Emitter
	limits     *limits.Limiter
	metrics    *metrics.Metrics
	now        func() time.Time
	newCtxID   func() string
	receiptTTL time.Duration
	contextTTL time.Duration
}

func New(s store.Store, e decision.Emitter, l *limits.Limiter, m *metrics.Metrics, now func() time.Time,
	newCtxID func() string, receiptTTL, contextTTL time.Duration) *Handler {
	return &Handler{store: s, log: e, limits: l, metrics: m, now: now, newCtxID: newCtxID, receiptTTL: receiptTTL, contextTTL: contextTTL}
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
	port := string(s.start.Port)
	remAddr := string(s.start.RemAddr)
	rk := store.ReceiptKey{NAS: s.peer.NAS, Port: port, Username: username}

	// 1. Receipt: a retransmission replays; a different credential on the same line fails.
	r, err := s.h.store.GetReceipt(ctx, rk)
	s.h.metrics.StoreOps.WithLabelValues("get_receipt", storeOutcome(err)).Inc()
	switch {
	case err == nil:
		if r.CredentialSHA256 == credHash {
			rec.Session.CtxID = r.CtxID
			return s.finish(rec, r.Status, decision.ReceiptReplayed)
		}
		return s.fail(ctx, rec, decision.CredentialMismatch)
	case !errors.Is(err, store.ErrNotFound):
		return s.storeError(rec)
	}

	// 2. Candidates under (nas, username), filtered by kind: a login token for a
	// login START, an enable token for an enable START. A credential that matches
	// a token of the other kind is a kind mismatch, not a missing token.
	kind := store.KindLogin
	if s.start.Service == wire.AuthenServiceEnable {
		kind = store.KindEnable
	}
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
	ctxID := s.h.newCtxID()
	receipt := store.Receipt{CredentialSHA256: credHash, Status: wire.AuthenStatusPass, CtxID: ctxID, ExpiresAt: s.h.now().Add(s.h.receiptTTL)}
	err = s.h.store.RedeemAndReceipt(ctx, store.TokenKey{NAS: s.peer.NAS, Username: username}, winner.Secret, rk, receipt)
	s.h.metrics.StoreOps.WithLabelValues("redeem", storeOutcome(err)).Inc()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			r, rerr := s.h.store.GetReceipt(ctx, rk)
			s.h.metrics.StoreOps.WithLabelValues("get_receipt", storeOutcome(rerr)).Inc()
			if rerr == nil && r.CredentialSHA256 == credHash {
				rec.Session.CtxID = r.CtxID
				return s.finish(rec, r.Status, decision.ReceiptReplayed)
			}
			return s.fail(ctx, rec, decision.TokenNotFound)
		}
		return s.storeError(rec)
	}

	err = s.h.store.PutContext(ctx, store.ContextKey{NAS: s.peer.NAS, Port: port},
		store.Context{CtxID: ctxID, Username: username, RemAddr: remAddr, PrivLvl: s.start.PrivLvl, CreatedAt: s.h.now()}, s.h.contextTTL)
	s.h.metrics.StoreOps.WithLabelValues("put_context", storeOutcome(err)).Inc()
	if err != nil {
		// The token is already redeemed, but without a context a later authorization
		// request has nothing to check against: ERROR, not a PASS we can't back up.
		return s.storeError(rec)
	}
	rec.Session.CtxID = ctxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
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

// fail replies FAIL after the per-(nas, username) failure delay, cancellable by
// ctx so a closed connection does not pin a goroutine on the sleep.
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
