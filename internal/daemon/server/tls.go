package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// TLS is the RFC 9887 listener's part of Deps (spec §13 decision 50). Serve
// runs the RFC 8907 listener when Deps.TLS is nil and the RFC 9887 one when
// it is set: one accept loop, one per-source limiter for both (ruling 17).
type TLS struct {
	// Material is the listener's files as loaded now, read at each Accept and
	// at each packet: a reload reaches the next handshake, and ends an open
	// connection whose chain no longer verifies (rulings 9, 15).
	Material func() *Material
	// ServerNames, when not empty, are the SNI names a ClientHello may ask
	// for, lower case; an absent SNI is accepted (ruling 10).
	ServerNames      []string
	HandshakeTimeout time.Duration
	// Seen notes a device certificate that verified (devicecert.Expiry.Seen);
	// Said is told each refusal, for port49d's throttled line. Nil is
	// nothing.
	Seen func(device string, leaf *x509.Certificate, now time.Time)
	Said func(device, source string, v devicecert.Verdict)
}

// Material is one load of the listener's files (ruling 15). Config is the
// base each connection's is cloned from: TLS 1.3 only, the server
// certificate, RequireAnyClientCert (port49 verifies the chain itself, at a
// full handshake and a resumption alike), and the ticket settings.
type Material struct {
	Config   *tls.Config
	Verifier *devicecert.Verifier
	// Unidentifiable is devicecert.Rule.Unidentifiable's map for the loaded
	// inventory: a device name to why this rule cannot tell its certificate
	// from another's. A tls device in it is refused identity_mismatch, with
	// the reason, whatever its certificate says.
	Unidentifiable map[string]string
}

// Details for a handshake that failed with no verdict of its own. They are
// fixed lines: crypto/tls's error text, which can echo peer-controlled
// bytes, never reaches a record.
const (
	handshakeFailedDetail = "the TLS handshake did not complete"
	deviceAbortedDetail   = "the device aborted the handshake (it may refuse port49's certificate; see " +
		"port49_tls_server_certificate_lifetime_left_ratio)"
)

// failureDetail is the line for a handshake refused with no verdict from
// the listener's own checks.
func failureDetail(o devicecert.Outcome, deviceAborted bool) string {
	switch o {
	case devicecert.HandshakeTimeout:
		return "the handshake did not finish within handshake_timeout"
	case devicecert.EarlyDataRefused:
		return "the ClientHello carried early_data, which RFC 9887 §5.1.2 forbids"
	case devicecert.NoClientCertificate:
		return "the device sent no certificate"
	case devicecert.VersionRefused:
		return "the device offered no TLS 1.3, which RFC 9887 requires"
	}
	if deviceAborted {
		return deviceAbortedDetail
	}
	return handshakeFailedDetail
}

// tlsSession is what a connection on the RFC 9887 listener holds once its
// handshake ends.
type tlsSession struct {
	mat     *Material
	verdict devicecert.Verdict
	peer    []*x509.Certificate // as the device sent them, for a full re-verify
	certSHA string
	started bool // the first packet was read; its single-connect flag decides
}

// judgeDevice is the local, cheap judgement of certs for the device: the
// verifier's path and identity, then the loaded inventory's list of devices
// this rule cannot identify.
func judgeDevice(mat *Material, certs []*x509.Certificate, dev admission.Device) devicecert.Verdict {
	v := mat.Verifier.Verify(certs, dev)
	if v.Outcome != devicecert.OK {
		return v
	}
	if why, bad := mat.Unidentifiable[dev.Name]; bad {
		return devicecert.Verdict{Outcome: devicecert.IdentityMismatch, Leaf: v.Leaf,
			Detail: printsafe.Line(why, 300)}
	}
	return v
}

// startTLS decides a connection on the RFC 9887 listener before any TLS
// byte is read (ruling 5): nothing it refuses here costs a key exchange.
// Then it runs the handshake. It reports whether the connection goes on to
// its packets.
func (s *conn) startTLS(ctx context.Context) bool {
	switch {
	case s.refused:
		s.acceptRecord(keyring.DiagAdmissionRefused, "", "")
		s.decline()
	case !s.admitted:
		s.acceptRecord(keyring.DiagUnadmittedSource, "", "")
		s.d.Limits.Malformed(s.src)
		reset(s.raw)
		s.d.Metrics.ConnectionEvents.WithLabelValues("unadmitted_source").Inc()
	case s.mismatch:
		s.acceptRecord(keyring.DiagTransportMismatch, "", mismatchDetail(s.dev.Device, "the RFC 9887 listener"))
		s.d.Metrics.ConnectionEvents.WithLabelValues("transport_mismatch").Inc()
		s.decline()
	case s.quarantined():
		s.acceptRecord(keyring.DiagDeviceQuarantined, decision.DeviceQuarantined, "")
		s.decline()
	default:
		return s.handshake(ctx)
	}
	return false
}

// mismatchDetail says which transport the device record names and which
// listener it reached. EffectiveTransport is tcp or tls here: admission
// refuses any other.
func mismatchDetail(dev admission.Device, listener string) string {
	return "the device record says transport " + dev.EffectiveTransport() + "; this is " + listener
}

// transportMismatch records a packet from a device on the listener its
// transport is not, on the RFC 8907 listener (the RFC 9887 one decides this
// at Accept).
func (s *conn) transportMismatch(h wire.Header) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTransportMismatch),
			Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length,
			Detail: mismatchDetail(s.dev.Device, "the RFC 8907 listener")}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTransportMismatch)).Inc()
	s.d.Metrics.ConnectionEvents.WithLabelValues("transport_mismatch").Inc()
}

// acceptRecord records a connection the RFC 9887 listener ended at Accept.
// No header was read, so the record carries none.
func (s *conn) acceptRecord(diag keyring.Diagnosis, reason decision.Reason, detail string) {
	rec := decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Reason: reason,
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(diag), Transport: admission.TransportTLS,
			Detail: detail}}
	if s.admitted || s.refused {
		rec.Device = s.deviceBlock()
	}
	s.d.Log.Emit(rec)
	s.d.Metrics.Unvalidated.WithLabelValues(string(diag)).Inc()
}

// handshake runs TLS 1.3 with the material in force. The ClientHello is
// read first for its versions and its SNI. The device's path and identity
// are judged in VerifyConnection, which crypto/tls runs on a full handshake
// and a resumption alike. crypto/tls runs it before it checks the client's
// CertificateVerify (handshake_server_tls13.go, Go 1.26), so the peer has
// proven nothing there: the status, which may wait on the network, is asked
// only once HandshakeContext has returned, inside the same deadline (ruling
// 8). A ticket crypto/tls sends before the client's Finished therefore
// precedes the status check; a resumption with it runs VerifyConnection and
// the status check again.
func (s *conn) handshake(ctx context.Context) bool {
	mat := s.d.TLS.Material()
	hctx, cancel := context.WithTimeout(ctx, s.d.TLS.HandshakeTimeout)
	defer cancel()
	var v devicecert.Verdict
	cfg := mat.Config.Clone()
	cfg.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		if !slices.Contains(hi.SupportedVersions, tls.VersionTLS13) {
			// crypto/tls refuses it next with protocol_version; this only
			// names why.
			v = devicecert.Verdict{Outcome: devicecert.VersionRefused,
				Detail: fmt.Sprintf("offered TLS versions %x; RFC 9887 requires TLS 1.3", hi.SupportedVersions)}
			return nil, nil
		}
		if name := hi.ServerName; name != "" && len(s.d.TLS.ServerNames) > 0 &&
			!slices.Contains(s.d.TLS.ServerNames, strings.ToLower(name)) {
			v = devicecert.Verdict{Outcome: devicecert.SNIMismatch,
				Detail: "asked for server name " + printsafe.Line(name, 253)}
			return nil, &devicecert.Refusal{Verdict: v}
		}
		return nil, nil
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		// The path and the identity: local and cheap (ruling 8).
		v = judgeDevice(mat, cs.PeerCertificates, s.dev.Device)
		if v.Outcome != devicecert.OK {
			return &devicecert.Refusal{Verdict: v}
		}
		return nil
	}
	tc := tls.Server(s.raw, cfg)
	err := tc.HandshakeContext(hctx)
	if err == nil && (v.Outcome != devicecert.OK || v.Leaf == nil) {
		err = fmt.Errorf("the handshake ended with no verdict on the device's certificate")
		v = devicecert.Verdict{}
	}
	if err != nil {
		if ctx.Err() != nil {
			return false // shutdown, not the device
		}
		if v.Outcome == "" || v.Outcome == devicecert.OK {
			// The device sent the alert when the text says "remote error":
			// most often it refused port49's own certificate (expired, or a
			// name it was not configured with). Every device then fails
			// alike (pre-flight M3). Only the fixed line is recorded.
			o := devicecert.Classify(err, hctx.Err() != nil)
			v = devicecert.Verdict{Outcome: o,
				Detail: failureDetail(o, strings.HasPrefix(err.Error(), "remote error: tls:")), Leaf: v.Leaf}
		}
		s.tlsRefused(v)
		return false
	}
	// Possession is proven: the chain's status now, within the handshake's
	// deadline. A refusal here is a reset after a completed handshake; the
	// device sees no alert (ruling 8).
	if v = mat.Verifier.CheckStatus(hctx, v); v.Outcome != devicecert.OK {
		if ctx.Err() != nil {
			return false
		}
		s.tlsRefused(v)
		return false
	}
	cs := tc.ConnectionState()
	outcome := devicecert.OK
	if cs.DidResume {
		outcome = devicecert.Resumed
	}
	s.d.Metrics.TLSHandshakes.WithLabelValues(string(outcome)).Inc()
	s.c = tc
	s.tls = &tlsSession{mat: mat, verdict: v, peer: cs.PeerCertificates, certSHA: devicecert.Fingerprint(v.Leaf)}
	if s.d.TLS.Seen != nil {
		s.d.TLS.Seen(s.dev.Device.Name, v.Leaf, s.d.Now())
	}
	return true
}

// tlsRefused records a refused handshake and ends the connection: struck
// and reset, as a key miss is, or for status_unavailable, which is port49's
// fault, declined under a window that stands until it lapses (ruling 8). An
// alert crypto/tls wrote before this is best-effort: the reset can discard
// it before it leaves the host (ruling 16).
func (s *conn) tlsRefused(v devicecert.Verdict) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTLSRefused),
			Transport: admission.TransportTLS, TLSOutcome: string(v.Outcome), Detail: v.Detail,
			CertSHA256: devicecert.Fingerprint(v.Leaf)}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTLSRefused)).Inc()
	s.d.Metrics.TLSHandshakes.WithLabelValues(string(v.Outcome)).Inc()
	if s.d.TLS.Said != nil {
		s.d.TLS.Said(s.dev.Device.Name, s.src.String(), v)
	}
	if !v.Outcome.Struck() {
		s.declineStatus()
		return
	}
	s.d.Limits.Malformed(s.src)
	reset(s.raw)
	s.d.Metrics.ConnectionEvents.WithLabelValues("tls_refused").Inc()
}

// declineStatus is decline for status_unavailable: the window it opens
// stands at the next Accept until it lapses, though the device is admitted
// on this listener, since nothing there can tell the status is back without
// the handshake the window spares (ruling 8).
func (s *conn) declineStatus() {
	s.d.Limits.DeclineStatus(s.src)
	reset(s.raw)
}

// recheckTLS judges the open connection's certificate again at a packet
// whose header has been read (ruling 9): against the anchors and rules in
// force now when a reload replaced them, then for expiry and the status as
// the checker holds it, with no network wait. A refusal here ends the
// connection with a reset and a decline window, never a strike: the
// handshake verified this certificate, and what changed is the chain's or
// port49's, not proof the device misbehaved. It reports whether the packet
// may go on.
func (s *conn) recheckTLS(h wire.Header) bool {
	mat := s.d.TLS.Material()
	v := s.tls.verdict
	if mat != s.tls.mat {
		v = judgeDevice(mat, s.tls.peer, s.dev.Device)
	}
	if v = mat.Verifier.Recheck(v); v.Outcome != devicecert.OK {
		s.tlsPacketRefused(h, v)
		return false
	}
	s.tls.mat, s.tls.verdict = mat, v
	return true
}

// tlsPacketRefused records a packet refused on the open connection by
// recheckTLS and ends it. status_unavailable keeps the window DeclineStatus
// marks; any other refusal opens a plain decline window. Neither is a
// strike, and neither is a handshake, so port49_tls_handshakes_total does
// not count it.
func (s *conn) tlsPacketRefused(h wire.Header, v devicecert.Verdict) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTLSRefused),
			Transport: admission.TransportTLS, TLSOutcome: string(v.Outcome), Detail: v.Detail,
			CertSHA256: s.tls.certSHA, Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTLSRefused)).Inc()
	s.d.Metrics.ConnectionEvents.WithLabelValues("tls_closed").Inc()
	if s.d.TLS.Said != nil {
		s.d.TLS.Said(s.dev.Device.Name, s.src.String(), v)
	}
	if v.Outcome == devicecert.StatusUnavailable {
		s.declineStatus()
		return
	}
	s.decline()
}

// obfuscatedOverTLS answers a packet whose unencrypted flag is clear on the
// RFC 9887 listener as RFC 9887 §4 requires: its type's ERROR with the flag
// set, then the connection closes (serve's deferred Close sends
// close_notify). The body, which ValidateTLS bounded at wire.MaxBodyLen, is
// read and discarded first, never hashed or logged: a socket closed with
// unread data sends a reset, which can drop the ERROR still queued
// (pre-flight M1). The peer's certificate verified, so it is no strike
// (ruling 13).
func (s *conn) obfuscatedOverTLS(h wire.Header) {
	s.unvalidated(h, nil, keyring.DiagObfuscatedOverTLS, 0)
	if _, err := io.CopyN(io.Discard, s.c, int64(h.Length)); err != nil {
		return // the peer is gone, or the read deadline passed: nothing to answer
	}
	rh, body := wire.ErrorReply(h)
	if err := s.c.SetWriteDeadline(time.Now().Add(s.d.IdleTimeout)); err == nil {
		_, _ = s.c.Write(append(rh.Encode(), body...))
	}
	s.d.Metrics.ConnectionEvents.WithLabelValues("obfuscated_over_tls").Inc()
}

// deviceBlock names the device this connection's source is; on the RFC
// 9887 listener it says so, with the certificate once one verified.
func (s *conn) deviceBlock() *decision.Device {
	d := &decision.Device{NAS: s.src.String(), Name: s.dev.Device.Name, Platform: s.dev.Device.Platform}
	if s.d.TLS != nil {
		d.Transport = admission.TransportTLS
		if s.tls != nil {
			d.CertSHA256 = s.tls.certSHA
		}
	}
	return d
}

// transportName is "tls" on the RFC 9887 listener and "" on the RFC 8907
// one, whose records are unchanged.
func (s *conn) transportName() string {
	if s.d.TLS != nil {
		return admission.TransportTLS
	}
	return ""
}
