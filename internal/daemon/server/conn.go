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
	"slices"
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
	d Deps
	c net.Conn
	// raw is the TCP connection: c itself on the RFC 8907 listener, and
	// beneath the TLS connection on the RFC 9887 one. A reset is made on it.
	raw      net.Conn
	mismatch bool        // admitted, on the listener its transport is not (spec §10)
	tls      *tlsSession // set once a TLS handshake ends
	src      netip.Addr
	dev      admission.Resolved
	admitted bool
	refused  bool // in inventory, and admission refused it (spec §10)
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
	rec := decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Unvalidated: &decision.Unvalidated{
		Source: s.src.String(), Diagnosis: string(diag), KeyRef: s.dev.KeyRef, Version: version,
		Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length, BodySHA256: sum,
		Transport: s.transportName()}}
	if s.d.TLS != nil {
		rec.Device = s.deviceBlock()
	}
	s.d.Log.Emit(rec)
	s.d.Metrics.Unvalidated.WithLabelValues(string(diag)).Inc()
}

// quarantine records a packet from a quarantined device: the header's
// cleartext fields, the source and the device, and the reason
// device_quarantined (spec §5.7, §10). No body was read, so none is hashed.
func (s *conn) quarantine(h wire.Header) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Reason: decision.DeviceQuarantined,
		Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagDeviceQuarantined),
			KeyRef: s.dev.KeyRef, Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length,
			Transport: s.transportName()}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagDeviceQuarantined)).Inc()
}

// refusedAdmission records a packet from a device the inventory names and
// admission refuses: no key group admits it, two tie on it, or its key_ref is
// one port49d holds no key for. Nothing is read past the header and there is
// no strike (spec §10); decline closes the connection. The fault is port49's
// configuration, not the device's, so the device falls to its local method at
// once, as for a quarantine; the start line and `port49 policy test` say why.
func (s *conn) refusedAdmission(h wire.Header) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated,
		Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagAdmissionRefused),
			KeyRef: s.dev.KeyRef, Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length,
			Transport: s.transportName()}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagAdmissionRefused)).Inc()
}

// readmitted asks admission in force about this connection's source at the
// time of this packet, so a reload that refuses, removes, renames, re-keys or
// re-platforms or re-transports the device ends its open connections rather than leaving them
// on the admission they began with: a busy single-connect connection resets
// its idle timer on every packet and so has no end (spec §10). A platform or
// `based_on:` change counts: the connection would be denied
// blob_platform_mismatch at every command, and its records redacted under a
// platform no longer in force. It returns the diagnosis naming why, or ""
// while the connection's admission still holds. On the RFC 9887 listener a
// change to the device's addresses also withdraws it: its certificate may
// have named it by an address it no longer has, and its next handshake is
// judged against the record in force (decision 50 ruling 6). On 49 an
// address change is not a withdrawal.
func (s *conn) readmitted() keyring.Diagnosis {
	now, found := s.d.Admission.Lookup(s.src)
	switch {
	case !found:
		return keyring.DiagUnadmittedSource
	case now.Refused != "":
		return keyring.DiagAdmissionRefused
	case now.Device.Name != s.dev.Device.Name || now.KeyRef != s.dev.KeyRef ||
		now.Device.Platform != s.dev.Device.Platform || now.WirePlatform != s.dev.WirePlatform ||
		now.Device.EffectiveTransport() != s.dev.Device.EffectiveTransport() ||
		(s.tls != nil && !slices.Equal(now.Device.Addresses, s.dev.Device.Addresses)):
		return keyring.DiagAdmissionWithdrawn
	}
	return ""
}

// admissionWithdrawn records a packet on a connection whose admission a
// reload withdrew and closes it with a reset, with nothing read past the
// header and no strike: the change is port49d's, not the device's. The
// record names the device and key_ref the connection was admitted as, and
// device_unknown, since that admission is no longer one port49d knows (spec
// §5.7). A reload that refused or removed the device also opens a decline
// window (decline), as a refusal does. How a device takes this reset is
// unmeasured (L29).
func (s *conn) admissionWithdrawn(h wire.Header, diag keyring.Diagnosis) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Reason: decision.DeviceUnknown,
		Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(diag), KeyRef: s.dev.KeyRef,
			Version: s.version, Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length,
			Transport: s.transportName()}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(diag)).Inc()
	s.d.Metrics.ConnectionEvents.WithLabelValues("admission_closed").Inc()
	if diag == keyring.DiagAdmissionWithdrawn {
		// Renamed, re-keyed or re-platformed: still admitted, so its next
		// connection is served and there is nothing to decline.
		s.reset()
		return
	}
	s.decline()
}

// quarantined asks the policy about this connection's device at the time of
// this packet, so a single-connection session opened before a grant's expiry
// is closed from it, and one opened during a quarantine is served once it ends.
func (s *conn) quarantined() bool {
	if !s.admitted || s.d.Quarantined == nil {
		return false
	}
	_, ok := s.d.Quarantined(s.dev.Device.Name, s.d.Now())
	return ok
}

// backoff holds the connection for the limiter's per-source delay before it is
// closed, so a source that floods malformed packets pays a growing cost while
// every other source is untouched. It is cancellable so shutdown is not stuck
// behind it. event is the ConnectionEvents label.
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

// reset makes c's close a TCP reset rather than a FIN. On a server's FIN the
// C8000V waits out its own timeout before it falls to local; a reset it acts
// on at once (tests/lab/results/L28-fin-cisco_iosxe.md, L28-cisco_iosxe.md).
func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
}

// reset ends the connection with a TCP reset. A TLS connection is
// abandoned, not closed: no close_notify goes out before the reset (L73 has
// not measured what a device does with one).
func (s *conn) reset() {
	s.c = s.raw
	reset(s.raw)
}

// keyMiss closes a connection whose packet no accepted key validates — a
// first packet, or one past its version's retire_after — as L28 branch H
// does: the record, a strike, and a reset at once, never a silent hold. The
// next connection inside the strike's backoff is refused at Accept.
func (s *conn) keyMiss(h wire.Header, obf []byte, diag keyring.Diagnosis, version int) {
	s.unvalidated(h, obf, diag, version)
	s.d.Limits.Malformed(s.src)
	s.reset()
	s.d.Metrics.ConnectionEvents.WithLabelValues("key_miss_closed").Inc()
}

// unadmitted closes a connection from a source the inventory does not name
// the way keyMiss closes a key miss (L28 branch H): the record, a strike, and
// a reset at once, never a hold for the backoff. The strike's backoff then
// refuses the source's next connections at Accept, before the device writes.
// With single-connection on, IOS-XE and NX-OS wait out their 5 s timeout
// after a reset that follows their request, and fall to their local method at
// once after one that comes before it (spec §15 L31).
func (s *conn) unadmitted(h wire.Header) {
	s.unvalidated(h, nil, keyring.DiagUnadmittedSource, 0)
	s.d.Limits.Malformed(s.src)
	s.reset()
	s.d.Metrics.ConnectionEvents.WithLabelValues("unadmitted_source").Inc()
}

// decline closes a connection port49d declines through no fault of the
// device's: admission refuses it, it is quarantined, or a reload refused or
// removed it. The close is a key miss's without the strike: a reset at once,
// and a window in which the source's next connections are refused at Accept,
// before the device writes (spec §10, "A declined source is refused at
// Accept"; §15 L31). The caller has written the record. The window is
// opened before the reset, so it is in force by the time the device sees the
// reset.
func (s *conn) decline() {
	s.d.Limits.Decline(s.src)
	s.reset()
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
	s.c = s.raw // a TLS connection is dropped without close_notify, as a reset's is
}

func (s *conn) serve(ctx context.Context) {
	// s.c becomes the TLS connection after a handshake: Close it as it is
	// then, so a TLS peer gets close_notify.
	defer func() { s.c.Close() }()
	if s.d.TLS != nil && !s.startTLS(ctx) {
		return
	}
	for {
		// The deadline is wall-clock I/O, so it uses the real clock even when a
		// test injects Deps.Now for record timestamps.
		deadline := s.d.IdleTimeout
		if (!s.admitted || s.mismatch) && deadline > unadmittedHeaderDeadline {
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
			if s.refused {
				s.refusedAdmission(h)
				s.decline()
				return
			}
			s.unadmitted(h)
			return
		}

		if diag := s.readmitted(); diag != "" {
			s.admissionWithdrawn(h, diag)
			return
		}

		// An admitted device on the RFC 8907 listener whose transport is tls:
		// startTLS ended the converse case before any byte (spec §13 decision
		// 50 ruling 4). Nothing past the header is read, and the fault is
		// configuration, not the device's, so it is declined, not struck.
		if s.mismatch {
			s.transportMismatch(h)
			s.decline()
			return
		}

		// A quarantined device gets silence, not FAIL (spec §10; §13 decision
		// 20): one header read, nothing decrypted, no reply, so the device
		// declares the server dead and falls to its local method exactly as in
		// an outage. A server that stays silent costs the device ~5 s per
		// command on IOS-XE, EOS and NX-OS (tests/lab/results/L4-error-*.md),
		// so the close is a reset at once. With single-connection on, IOS-XE
		// and NX-OS also wait out that timeout after a reset that follows their
		// request, unless the retry is refused at Accept, so the close opens a
		// decline window. With it, break-glass on a quarantined Cisco device
		// took 1.78 s on the C8000V and 2.61 s on the N9Kv, against a key
		// miss's 1.28 s and 2.61 s, where it took 16-21 s before (spec §15 L31,
		// tests/lab/results/L31-cisco_*.md). The device is not suspect, so it
		// takes no strike, and its connections inside the window are counted,
		// not recorded.
		if s.quarantined() {
			s.quarantine(h)
			s.decline()
			return
		}

		// On the RFC 9887 listener every packet is judged again against the
		// material in force now (ruling 9), before its body is read.
		if s.tls != nil && !s.recheckTLS(h) {
			return
		}

		// Header checks come before anything that would touch the body. On
		// the RFC 8907 listener an unencrypted packet is refused without its
		// cleartext ever being read; on the RFC 9887 listener the flag is
		// required, and one without it is answered ERROR (RFC 9887 §4).
		if s.tls != nil {
			if err := h.ValidateTLS(); err != nil {
				if errors.Is(err, wire.ErrObfuscatedOverTLS) {
					s.obfuscatedOverTLS(h)
					return
				}
				s.unvalidated(h, nil, keyring.DiagNotTACACS, 0)
				s.backoff(ctx, "malformed_backoff")
				return
			}
		} else if err := h.Validate(); err != nil {
			diag := keyring.DiagNotTACACS
			if errors.Is(err, wire.ErrUnencrypted) {
				diag = keyring.DiagUnencrypted
			}
			s.unvalidated(h, nil, diag, 0)
			s.backoff(ctx, "malformed_backoff")
			return
		}

		raw := make([]byte, h.Length) // a Validate has already bounded Length at wire.MaxBodyLen
		if _, err := io.ReadFull(s.c, raw); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.d.Metrics.ConnectionEvents.WithLabelValues("idle_closed").Inc()
			}
			return
		}

		body := raw
		if s.tls != nil {
			// No key over TLS (RFC 9887 §4): the first packet's
			// single-connect flag decides, as the first validated one does on 49.
			if !s.tls.started {
				s.tls.started = true
				s.single = h.Flags&wire.FlagSingleConnect != 0
			}
		} else {
			var ok bool
			if body, ok = s.deobfuscate(ctx, h, raw); !ok {
				return
			}
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
// one, so a device cannot walk the keyring packet by packet. Each packet is
// judged at its own time: a connection opened before its version's
// retire_after is refused at the first packet past it, so holding a
// connection open never extends a key's life.
func (s *conn) deobfuscate(ctx context.Context, h wire.Header, obf []byte) ([]byte, bool) {
	if s.version == 0 {
		r := s.keys.Resolve(h, obf, s.d.Now())
		s.d.Metrics.KeyValidations.WithLabelValues(s.keys.Ref, strconv.Itoa(r.Version), string(r.Diagnosis)).Inc()
		if r.Diagnosis != keyring.DiagValidated {
			// A retired version identifies the sender in the record and nothing
			// more: no admission, no reply. The strike is counted, and the next
			// connection inside its backoff is refused at Accept; this one is
			// closed at once with a reset, never held silent (L28 branch H).
			if s.d.Held != nil {
				s.d.Held.Put(s.dev.Device.Name, s.src, h, obf, s.d.Now())
			}
			s.keyMiss(h, obf, r.Diagnosis, r.Version)
			return nil, false
		}
		s.version = r.Version
		if s.d.KeySeen != nil {
			s.d.KeySeen(s.dev.Device.Name, s.keys.Ref, r.Version)
		}
		if h.Flags&wire.FlagSingleConnect != 0 {
			s.single = true
		}
		return r.Body, true
	}
	if s.pastDate(s.d.Now()) {
		// matches_retired here means the connection's version is past its
		// retire_after; this packet is not trial-decrypted, since nothing it
		// could say would change the answer (spec §10). It is closed as a
		// first-packet miss is: struck, and reset at once.
		s.d.Metrics.KeyValidations.WithLabelValues(s.keys.Ref, strconv.Itoa(s.version),
			string(keyring.DiagMatchesRetired)).Inc()
		s.keyMiss(h, obf, keyring.DiagMatchesRetired, s.version)
		return nil, false
	}
	body := wire.Obfuscate(h, s.keys.Secret(s.version), obf)
	if !keyring.Validates(h, body) {
		s.unvalidated(h, obf, keyring.DiagMalformedAfterValidation, s.version)
		s.backoff(ctx, "malformed_backoff")
		return nil, false
	}
	return body, true
}

// pastDate reports whether the version this connection validated under has
// been retired since, by its retire_after passing.
func (s *conn) pastDate(now time.Time) bool {
	for i, v := range s.keys.Versions {
		if v.Number == s.version {
			return s.keys.State(i, now) == "retired"
		}
	}
	return true
}

// write sends one reply, obfuscated with the version that validated the request.
func (s *conn) write(h wire.Header, body []byte) bool {
	flags := uint8(0)
	if s.single {
		flags = wire.FlagSingleConnect
	}
	out := body
	if s.tls != nil {
		flags |= wire.FlagUnencrypted // every reply over TLS (RFC 9887 §4)
	}
	rh := wire.Header{MajorVersion: h.MajorVersion, MinorVersion: h.MinorVersion, Type: h.Type, SeqNo: h.SeqNo + 1,
		Flags: flags, SessionID: h.SessionID, Length: uint32(len(body))}
	if err := s.c.SetWriteDeadline(time.Now().Add(s.d.IdleTimeout)); err != nil {
		return false
	}
	if s.tls == nil {
		out = wire.Obfuscate(rh, s.keys.Secret(s.version), body)
	}
	_, err := s.c.Write(append(rh.Encode(), out...))
	return err == nil
}

// dispatch runs one packet through the right handler and returns the reply
// body. done reports whether the session on this connection has finished;
// protoErr reports a packet this connection cannot answer at all, which closes
// it without a reply.
func (s *conn) dispatch(ctx context.Context, h wire.Header, body []byte) (reply []byte, done, protoErr bool) {
	// The failure delay keeps the server's context and counts from now,
	// the packet's arrival (authen.DelayContext): the deadline is for the
	// store, never the brute-force delay (re-check N1).
	delay, arrived := ctx, time.Now()
	if s.d.PacketDeadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.d.PacketDeadline)
		defer cancel()
	}
	ctx = authen.WithDelayContext(ctx, delay, arrived)
	peer := authen.Peer{NAS: s.dev.Device.Name, NASAddr: s.src.String(), Platform: s.dev.Device.Platform,
		KeyRef: s.dev.KeyRef, KeyVersion: s.version, WirePlatform: s.dev.WirePlatform}
	if s.tls != nil {
		peer.Transport, peer.CertSHA256 = admission.TransportTLS, s.tls.certSHA
	}
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
