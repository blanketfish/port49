// Package authen runs the RFC 8907 authentication exchange against the token
// set in the store (design §8; spec §5.6, §5.7). It never sees a broker.
package authen

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
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

type Session struct {
	h     *Handler
	peer  Peer
	start wire.AuthenStart
	user  string // as typed
	phase int    // 0 new, 1 waiting for user, 2 waiting for password
}

func (h *Handler) NewSession(peer Peer) *Session { return &Session{h: h, peer: peer} }

func (s *Session) Start(ctx context.Context, p wire.AuthenStart) (wire.AuthenReply, bool) {
	s.start = p
	s.user = string(p.User)
	if p.Action != wire.AuthenActionLogin {
		return wire.AuthenReply{Status: wire.AuthenStatusFail}, true
	}
	switch p.AuthenType {
	case wire.AuthenTypePAP:
		return s.verify(ctx, "pap", p.Data, p.Data)
	case wire.AuthenTypeCHAP:
		return s.verifyCHAP(ctx, p.Data)
	case wire.AuthenTypeASCII:
		if s.user == "" {
			s.phase = 1
			return wire.AuthenReply{Status: wire.AuthenStatusGetUser, ServerMsg: []byte("Username: ")}, false
		}
		s.phase = 2
		return wire.AuthenReply{Status: wire.AuthenStatusGetPass, Flags: wire.AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}, false
	default:
		return wire.AuthenReply{Status: wire.AuthenStatusError, ServerMsg: []byte("port49: authentication type not supported")}, true
	}
}

func (s *Session) Continue(ctx context.Context, p wire.AuthenContinue) (wire.AuthenReply, bool) {
	if p.Flags&wire.AuthenContinueFlagAbort != 0 {
		return wire.AuthenReply{}, true
	}
	switch s.phase {
	case 1:
		s.user = string(p.UserMsg)
		s.phase = 2
		return wire.AuthenReply{Status: wire.AuthenStatusGetPass, Flags: wire.AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}, false
	case 2:
		return s.verify(ctx, "ascii", p.UserMsg, p.UserMsg)
	}
	return wire.AuthenReply{Status: wire.AuthenStatusError}, true
}

// verify handles PAP and ASCII, where the presented credential is the token itself.
func (s *Session) verify(ctx context.Context, method string, presented, secret []byte) (wire.AuthenReply, bool) {
	return s.redeem(ctx, method, presented, func(t store.Token) bool { return bytes.Equal(t.Secret, secret) })
}

func (s *Session) verifyCHAP(ctx context.Context, data []byte) (wire.AuthenReply, bool) {
	if len(data) < 1+1+md5.Size {
		return wire.AuthenReply{Status: wire.AuthenStatusFail}, true
	}
	id, challenge, response := data[0], data[1:len(data)-md5.Size], data[len(data)-md5.Size:]
	return s.redeem(ctx, "chap", data, func(t store.Token) bool {
		m := md5.New()
		m.Write([]byte{id})
		m.Write(t.Secret)
		m.Write(challenge)
		return bytes.Equal(m.Sum(nil), response)
	})
}

func (s *Session) redeem(ctx context.Context, method string, presented []byte, match func(store.Token) bool) (wire.AuthenReply, bool) {
	username := Canonical(s.user)
	port := string(s.start.Port)
	remAddr := string(s.start.RemAddr)
	rk := store.ReceiptKey{NAS: s.peer.NAS, Port: port, Username: username}
	credHash := sha256.Sum256(presented)
	rec := decision.Record{TS: s.h.now(), Event: decision.EventRedeem,
		Auth:    &decision.Auth{Method: method, CredentialSHA256: decision.CredentialHash(presented)},
		Device:  &decision.Device{NAS: s.peer.NASAddr, Name: s.peer.NAS, Platform: s.peer.Platform},
		Session: &decision.Session{Port: port, RemAddr: remAddr, Privilege: s.start.PrivLvl}}

	// 1. Receipt: a retransmission replays; a different credential on the same line fails.
	if r, err := s.h.store.GetReceipt(ctx, rk); err == nil {
		if r.CredentialSHA256 == credHash {
			rec.Session.CtxID = r.CtxID
			return s.finish(rec, r.Status, decision.ReceiptReplayed)
		}
		return s.fail(rec, decision.CredentialMismatch)
	}

	// 2. Candidates under (nas, username), filtered by kind.
	kind := "login"
	if s.start.Service == wire.AuthenServiceEnable {
		kind = "enable"
	}
	cands, err := s.h.store.Candidates(ctx, store.TokenKey{NAS: s.peer.NAS, Username: username})
	if err != nil {
		return wire.AuthenReply{Status: wire.AuthenStatusError, ServerMsg: []byte("port49: store unavailable")}, true
	}
	var winner *store.Token
	for i := range cands {
		if match(cands[i]) {
			winner = &cands[i]
			break
		}
	}
	if winner == nil {
		return s.fail(rec, decision.TokenNotFound)
	}
	if winner.Kind != kind {
		return s.fail(rec, decision.TokenKindMismatch)
	}

	// 3. Atomic redemption; the loser of a race adopts the winner's receipt.
	ctxID := s.h.newCtxID()
	receipt := store.Receipt{CredentialSHA256: credHash, Status: wire.AuthenStatusPass, CtxID: ctxID, ExpiresAt: s.h.now().Add(s.h.receiptTTL)}
	if err := s.h.store.RedeemAndReceipt(ctx, store.TokenKey{NAS: s.peer.NAS, Username: username}, winner.Secret, rk, receipt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if r, rerr := s.h.store.GetReceipt(ctx, rk); rerr == nil && r.CredentialSHA256 == credHash {
				rec.Session.CtxID = r.CtxID
				return s.finish(rec, r.Status, decision.ReceiptReplayed)
			}
			return s.fail(rec, decision.TokenNotFound)
		}
		return wire.AuthenReply{Status: wire.AuthenStatusError, ServerMsg: []byte("port49: store unavailable")}, true
	}
	_ = s.h.store.PutContext(ctx, store.ContextKey{NAS: s.peer.NAS, Port: port},
		store.Context{CtxID: ctxID, Username: username, RemAddr: remAddr, PrivLvl: s.start.PrivLvl, CreatedAt: s.h.now()}, s.h.contextTTL)
	rec.Session.CtxID = ctxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}

func (s *Session) finish(rec decision.Record, status uint8, reason decision.Reason) (wire.AuthenReply, bool) {
	rec.Verdict = decision.VerdictPermit
	if status != wire.AuthenStatusPass {
		rec.Verdict = decision.VerdictDeny
	}
	rec.Reason = reason
	s.h.log.Emit(rec)
	s.h.metrics.Decisions.WithLabelValues(rec.Event, rec.Verdict, string(reason)).Inc()
	return wire.AuthenReply{Status: status}, true
}

func (s *Session) fail(rec decision.Record, reason decision.Reason) (wire.AuthenReply, bool) {
	delay := s.h.limits.AuthFailure(s.peer.NAS, Canonical(s.user))
	s.h.metrics.AuthFailures.Inc()
	time.Sleep(delay)
	rec.ServerMsg = "port49: authentication failed — mint a new token with `port49 token`"
	reply, done := s.finish(rec, wire.AuthenStatusFail, reason)
	reply.ServerMsg = []byte(rec.ServerMsg)
	return reply, done
}
