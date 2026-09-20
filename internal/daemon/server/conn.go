package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// maxLiveSessions bounds the per-connection session map. Only a single-connect
// connection can hold more than one unfinished session, and the session_id is
// chosen by the device, so without a bound one connection could name new
// session_ids until the daemon runs out of memory.
const maxLiveSessions = 64

// unadmittedHeaderDeadline bounds how long a source that is not in the
// inventory may hold a connection before sending its first header. An
// admitted device gets the configured idle timeout; an unadmitted one has no
// claim on it, and today the only global connection cap is EMFILE — the worst
// one there is, since it refuses admitted devices too and fails the
// accounting spool's own file open. Thirty seconds times the per-source cap,
// per address, is a cheap way to sit on descriptors. Admission is already
// known at Accept, so this costs nothing to apply.
//
// This is not the global cap, which is plan 12 along with its sizing and its
// alarm. It is the part of it that is cheap to pull forward.
const unadmittedHeaderDeadline = 5 * time.Second

type conn struct {
	d        Deps
	c        net.Conn
	src      netip.Addr
	dev      admission.Resolved
	admitted bool
	keys     keyring.Set

	version  int  // 0 until the first packet validates; then the only version this connection uses
	single   bool // the first packet asked to keep the connection open
	sessions map[uint32]*authen.Session
}

// unvalidated records a packet no accepted key validated. It carries the
// cleartext header fields, the source, and a hash of whatever bytes arrived —
// never the bytes, which at this point are either not ours or not decodable.
// body is nil on the header-only paths (an unadmitted source, a header that
// fails Validate): no bytes were read, so BodySHA256 is left empty rather
// than reporting the hash of nothing.
func (s *conn) unvalidated(h wire.Header, body []byte, diag keyring.Diagnosis, version int) {
	var sum string
	if body != nil {
		digest := sha256.Sum256(body)
		sum = hex.EncodeToString(digest[:])
	}
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Unvalidated: &decision.Unvalidated{
		Source: s.src.String(), Diagnosis: string(diag), KeyRef: s.dev.KeyRef, Version: version,
		Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length, BodySHA256: sum}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(diag)).Inc()
}

// backoff holds the connection for the limiter's per-source delay before it is
// closed, so a source that floods malformed packets pays a growing cost while
// every other source is untouched. It is cancellable so shutdown is not stuck
// behind it. event is the ConnectionEvents label: callers pass a diagnosis
// distinct from "malformed_backoff" when the strike isn't itself a malformed
// packet (an unadmitted source), so the two are distinguishable in metrics.
func (s *conn) backoff(ctx context.Context, event string) {
	d := s.d.Limits.Malformed(s.src)
	s.d.Metrics.ConnectionEvents.WithLabelValues(event).Inc()
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// protocolError closes a connection whose key validated but whose packet
// port49 cannot answer: a CONTINUE naming a session this connection never
// started, a seq_no of 255, or more unfinished sessions than maxLiveSessions
// holds (spec §10, "malformed after validation"). A real device is failing a
// real login here, and the strike counter rightly carries no device label, so
// without a record nothing at all says which device it was.
//
// The record carries header fields and no body hash. Unlike the other
// malformed_after_validation path, the bytes in hand here are cleartext that
// may include a credential, and BodySHA256 is documented as the hash of what
// arrived on the wire.
func (s *conn) protocolError(ctx context.Context, h wire.Header) {
	s.unvalidated(h, nil, keyring.DiagMalformedAfterValidation, s.version)
	s.backoff(ctx, "malformed_backoff")
}

func (s *conn) serve(ctx context.Context) {
	defer s.c.Close()
	for {
		// The deadline is wall-clock I/O, so it uses the real clock even when a
		// test injects Deps.Now for record timestamps.
		deadline := s.d.IdleTimeout
		if !s.admitted && deadline > unadmittedHeaderDeadline {
			deadline = unadmittedHeaderDeadline
		}
		if err := s.c.SetReadDeadline(time.Now().Add(deadline)); err != nil {
			return
		}
		hb := make([]byte, wire.HeaderLen)
		if _, err := io.ReadFull(s.c, hb); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.d.Metrics.ConnectionEvents.WithLabelValues("idle_closed").Inc()
			}
			return
		}
		h, err := wire.DecodeHeader(hb)
		if err != nil {
			return // unreachable: ReadFull delivered exactly HeaderLen bytes
		}

		// An unadmitted source never costs more than one header read: no body is
		// read, no key is tried, nothing is decoded. Counted separately from
		// malformed_backoff so an operator can tell "unknown device" from
		// "known device sending garbage" at a glance.
		if !s.admitted {
			s.unvalidated(h, nil, keyring.DiagUnadmittedSource, 0)
			s.backoff(ctx, "unadmitted_source")
			return
		}

		// Header checks come before anything that would touch the body, so an
		// unencrypted packet is refused without its cleartext ever being read.
		if err := h.Validate(); err != nil {
			diag := keyring.DiagNotTACACS
			if errors.Is(err, wire.ErrUnencrypted) {
				diag = keyring.DiagUnencrypted
			}
			s.unvalidated(h, nil, diag, 0)
			s.backoff(ctx, "malformed_backoff")
			return
		}

		obf := make([]byte, h.Length) // Validate has already bounded Length at wire.MaxBodyLen
		if _, err := io.ReadFull(s.c, obf); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.d.Metrics.ConnectionEvents.WithLabelValues("idle_closed").Inc()
			}
			return
		}

		body, ok := s.deobfuscate(ctx, h, obf)
		if !ok {
			return
		}

		if h.SeqNo == 255 {
			// RFC 8907: seq_no wraps after 255, and the reply would need
			// seq_no 256, which does not fit a uint8. The session must be
			// restarted, not continued, so this sends nothing and closes.
			delete(s.sessions, h.SessionID)
			s.protocolError(ctx, h)
			return
		}

		reply, done, protoErr := s.dispatch(ctx, h, body)
		if protoErr {
			// The key validated, so this is a real device speaking a sequence
			// port49 cannot answer. There is no reply that would help it; count
			// the strike and hang up.
			s.protocolError(ctx, h)
			return
		}
		if reply != nil && !s.write(h, reply) {
			return
		}
		if done && !s.single {
			return
		}
	}
}

// deobfuscate turns the packet body into cleartext. The first packet decides
// which key version this connection speaks; every later packet is held to that
// one, so a device cannot walk the keyring packet by packet.
func (s *conn) deobfuscate(ctx context.Context, h wire.Header, obf []byte) ([]byte, bool) {
	if s.version == 0 {
		r := s.keys.Resolve(h, obf)
		s.d.Metrics.KeyValidations.WithLabelValues(s.keys.Ref, strconv.Itoa(r.Version), string(r.Diagnosis)).Inc()
		if r.Diagnosis != keyring.DiagValidated {
			// A retired version identifies the sender in the record and nothing
			// more: no admission, no reply.
			s.unvalidated(h, obf, r.Diagnosis, r.Version)
			s.backoff(ctx, "malformed_backoff")
			return nil, false
		}
		s.version = r.Version
		if h.Flags&wire.FlagSingleConnect != 0 {
			s.single = true
		}
		return r.Body, true
	}
	body := wire.Obfuscate(h, s.keys.Secret(s.version), obf)
	if !keyring.Validates(h, body) {
		s.unvalidated(h, obf, keyring.DiagMalformedAfterValidation, s.version)
		s.backoff(ctx, "malformed_backoff")
		return nil, false
	}
	return body, true
}

// write sends one reply, obfuscated with the version that validated the request.
func (s *conn) write(h wire.Header, body []byte) bool {
	flags := uint8(0)
	if s.single {
		flags = wire.FlagSingleConnect
	}
	rh := wire.Header{MajorVersion: h.MajorVersion, MinorVersion: h.MinorVersion, Type: h.Type, SeqNo: h.SeqNo + 1,
		Flags: flags, SessionID: h.SessionID, Length: uint32(len(body))}
	if err := s.c.SetWriteDeadline(time.Now().Add(s.d.IdleTimeout)); err != nil {
		return false
	}
	_, err := s.c.Write(append(rh.Encode(), wire.Obfuscate(rh, s.keys.Secret(s.version), body)...))
	return err == nil
}

// dispatch runs one packet through the right handler and returns the reply
// body. done reports whether the session on this connection has finished;
// protoErr reports a packet this connection cannot answer at all, which closes
// it without a reply.
func (s *conn) dispatch(ctx context.Context, h wire.Header, body []byte) (reply []byte, done, protoErr bool) {
	peer := authen.Peer{NAS: s.dev.Device.Name, NASAddr: s.src.String(), Platform: s.dev.Device.Platform}
	start := s.d.Now()
	defer func() { s.d.Metrics.Latency.WithLabelValues(exchange(h.Type)).Observe(s.d.Now().Sub(start).Seconds()) }()

	switch h.Type {
	case wire.TypeAuthen:
		return s.authenticate(ctx, h, body, peer)
	case wire.TypeAuthor:
		p, err := wire.DecodeAuthorRequest(body)
		if err != nil {
			return nil, true, true
		}
		resp := s.d.Author.Handle(ctx, peer, p)
		s.d.Metrics.Requests.WithLabelValues("author", authorOutcome(resp.Status)).Inc()
		return resp.Encode(), true, false
	case wire.TypeAcct:
		p, err := wire.DecodeAcctRequest(body)
		if err != nil {
			return nil, true, true
		}
		// acct.Handle counts its own request metric.
		return s.d.Acct.Handle(ctx, peer, p).Encode(), true, false
	}
	return nil, true, true // unreachable: Validate rejected every other type
}

func (s *conn) authenticate(ctx context.Context, h wire.Header, body []byte, peer authen.Peer) (reply []byte, done, protoErr bool) {
	if h.SeqNo == 1 {
		p, err := wire.DecodeAuthenStart(body)
		if err != nil {
			return nil, true, true
		}
		if len(s.sessions) >= maxLiveSessions {
			return nil, true, true
		}
		sess := s.d.Authen.NewSession(peer)
		s.sessions[h.SessionID] = sess // a START on a live session_id starts it over
		r, fin := sess.Start(ctx, p)
		return s.finish(h, r, fin)
	}
	sess, ok := s.sessions[h.SessionID]
	if !ok {
		// A CONTINUE for a session_id this connection never started, or one that
		// already finished: there is nothing to continue.
		return nil, true, true
	}
	p, err := wire.DecodeAuthenContinue(body)
	if err != nil {
		return nil, true, true
	}
	r, fin := sess.Continue(ctx, p)
	return s.finish(h, r, fin)
}

// finish applies a Session's reply to the connection: it drops a finished
// session from the map and honours the "send nothing" reply (a zero Status with
// done set, which is how the session layer reports a client ABORT).
func (s *conn) finish(h wire.Header, r wire.AuthenReply, done bool) (reply []byte, fin, protoErr bool) {
	if done {
		delete(s.sessions, h.SessionID)
	}
	if done && r.Status == 0 {
		return nil, true, false
	}
	if done {
		s.d.Metrics.Requests.WithLabelValues("authen", authenOutcome(r.Status)).Inc()
	}
	return r.Encode(), done, false
}

func exchange(t wire.Type) string {
	switch t {
	case wire.TypeAuthen:
		return "authen"
	case wire.TypeAuthor:
		return "author"
	}
	return "acct"
}

func authenOutcome(status uint8) string {
	switch status {
	case wire.AuthenStatusPass:
		return "pass"
	case wire.AuthenStatusError:
		return "error"
	default:
		return "fail"
	}
}

func authorOutcome(status uint8) string {
	switch status {
	case wire.AuthorStatusPassAdd, wire.AuthorStatusPassRepl:
		return "pass"
	case wire.AuthorStatusError:
		return "error"
	default:
		return "fail"
	}
}
