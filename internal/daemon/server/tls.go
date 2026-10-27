package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
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
	// for, each as CanonicalServerName gives it; an absent SNI is accepted
	// (ruling 10).
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
	// Tickets is the guard Apply keyed on Config; nil is
	// session_ticket_lifetime 0s, and no ticket is issued or resumed.
	Tickets *TicketGuard
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

// judgeDevice is the verifier's judgement of certs for the device, then the
// loaded inventory's list of devices this rule cannot identify. The
// handshake leaves the list to Accept (startTLS); a reload that changes it
// mid-connection is caught here, at the next packet.
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
	// The material is read once: this load decides the connection at Accept,
	// runs its handshake, and is what recheckTLS compares later loads to, so
	// a reload between them is caught at the first packet.
	mat := s.d.TLS.Material()
	if mat == nil {
		sayNoMaterial()
		s.d.Metrics.ConnectionEvents.WithLabelValues("tls_refused").Inc()
		s.decline()
		return false
	}
	switch {
	case s.refused:
		s.acceptRecord(keyring.DiagAdmissionRefused, "", "")
		s.decline()
	case !s.admitted:
		s.acceptRecord(keyring.DiagUnadmittedSource, "", "")
		s.d.Limits.Malformed(s.src)
		s.reset()
		s.d.Metrics.ConnectionEvents.WithLabelValues("unadmitted_source").Inc()
	case s.mismatch:
		s.acceptRecord(keyring.DiagTransportMismatch, "", mismatchDetail(s.dev.Device, "the RFC 9887 listener"))
		s.d.Metrics.ConnectionEvents.WithLabelValues("transport_mismatch").Inc()
		s.decline()
	case s.quarantined():
		s.acceptRecord(keyring.DiagDeviceQuarantined, decision.DeviceQuarantined, "")
		s.decline()
	case s.unidentifiable(mat) != "":
		// The rule cannot tell this device's certificate from another's, so
		// no certificate can admit it. That is the loaded files' fault and
		// needs no TLS byte to know: no handshake, no strike (a peer holding
		// only the device's public certificate gets nothing to strike or to
		// exploit), and a window that stands while the device stays in the
		// map (declining).
		s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
			Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTLSRefused),
				Transport: admission.TransportTLS, TLSOutcome: string(devicecert.IdentityMismatch),
				Detail: printsafe.Line(s.unidentifiable(mat), 300)}})
		s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTLSRefused)).Inc()
		s.d.Metrics.ConnectionEvents.WithLabelValues("tls_refused").Inc()
		if s.d.TLS.Said != nil {
			s.d.TLS.Said(s.dev.Device.Name, s.src.String(), devicecert.Verdict{Outcome: devicecert.IdentityMismatch,
				Detail: printsafe.Line(s.unidentifiable(mat), 300)})
		}
		s.decline()
	default:
		return s.handshake(ctx, mat)
	}
	return false
}

// unidentifiable is why the loaded material cannot identify this
// connection's device, or "".
func (s *conn) unidentifiable(mat *Material) string {
	return mat.Unidentifiable[s.dev.Device.Name]
}

var noMaterialSaid atomic.Bool

// sayNoMaterial says once that the RFC 9887 listener has no material to
// judge a device by, a fault in port49d: every connection is then declined.
func sayNoMaterial() {
	if noMaterialSaid.CompareAndSwap(false, true) {
		log.Print("server: the RFC 9887 listener has no loaded material; declining its connections")
	}
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
// the status check again. A resumption is no different: crypto/tls sends
// its new ticket in the server's first flight, before VerifyConnection and
// the status check, so a device whose resumption is then refused (revoked
// since) still received one. Every redemption is judged again, and the new
// ticket carries the chain's origin time, so it ends with the chain.
func (s *conn) handshake(ctx context.Context, mat *Material) bool {
	hctx, cancel := context.WithTimeout(ctx, s.d.TLS.HandshakeTimeout)
	defer cancel()
	var v devicecert.Verdict
	cfg := mat.Config.Clone()
	// Whatever Material holds, RFC 9887 is TLS 1.3 with a client certificate.
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.ClientAuth = tls.RequireAnyClientCert
	// A ticket is single-use and age-bounded or it is not issued: whatever
	// hooks the base carries are dropped, and only Material.Tickets binds
	// the guard's.
	cfg.WrapSession, cfg.UnwrapSession = nil, nil
	if mat.Tickets != nil {
		mat.Tickets.bind(cfg)
	} else {
		cfg.SessionTicketsDisabled = true
	}
	cfg.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		if !slices.Contains(hi.SupportedVersions, tls.VersionTLS13) {
			// crypto/tls refuses it next with protocol_version; this only
			// names why.
			v = devicecert.Verdict{Outcome: devicecert.VersionRefused, Detail: failureDetail(devicecert.VersionRefused, false)}
			return nil, nil
		}
		if name := hi.ServerName; name != "" && len(s.d.TLS.ServerNames) > 0 &&
			!serverNameListed(s.d.TLS.ServerNames, name) {
			v = devicecert.Verdict{Outcome: devicecert.SNIMismatch,
				Detail: "asked for server name " + printsafe.Line(name, 253)}
			return nil, &devicecert.Refusal{Verdict: v}
		}
		return nil, nil
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		// The path and the identity: local and cheap (ruling 8).
		v = mat.Verifier.Verify(cs.PeerCertificates, s.dev.Device)
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
	s.tlsc.Store(tc)
	s.tls = &tlsSession{mat: mat, verdict: v, peer: cs.PeerCertificates, certSHA: devicecert.Fingerprint(v.Leaf)}
	if s.d.TLS.Seen != nil {
		s.d.TLS.Seen(s.dev.Device.Name, v.Leaf, s.d.Now())
	}
	return true
}

// serverNameListed reports whether sni is one of names, which are
// CanonicalServerName's. An address is compared by address, so any spelling
// of a listed address matches; anything else, a zoned or bracketed address
// included, is compared exactly and matches nothing config accepts. There
// is no trailing-dot trim: crypto/tls refuses a ClientHello whose SNI ends
// in a dot before this is asked.
func serverNameListed(names []string, sni string) bool {
	return slices.Contains(names, CanonicalServerName(sni))
}

// CanonicalServerName is name as server_names holds it (decision 50 ruling
// 10): an IP address with no zone in canonical form (IPv4-mapped folded to
// IPv4, IPv6 as RFC 5952 text), and anything else in lower case.
func CanonicalServerName(name string) string {
	name = strings.ToLower(name)
	if a, err := netip.ParseAddr(name); err == nil && a.Zone() == "" {
		return a.Unmap().String()
	}
	return name
}

// tlsRefused records a refused handshake and ends the connection: struck
// and reset, as a key miss is, or, for status_unavailable (port49's fault)
// and sni_mismatch (a misconfiguration, not hostility), declined under a
// window that stands until it lapses (rulings 8, 10). An alert crypto/tls
// wrote before this is best-effort: the reset can discard it before it
// leaves the host (ruling 16).
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
		s.declineStanding()
		return
	}
	s.d.Limits.Malformed(s.src)
	s.reset()
	s.d.Metrics.ConnectionEvents.WithLabelValues("tls_refused").Inc()
}

// declineStanding is decline for status_unavailable and sni_mismatch: the
// window it opens stands at the next Accept until it lapses, though the
// device is admitted on this listener, since nothing there can tell the
// status is back, or the server name fixed, without the handshake the window
// spares (rulings 8, 10).
func (s *conn) declineStanding() {
	s.d.Limits.DeclineStanding(s.src)
	s.reset()
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
	if mat == nil {
		mat = s.tls.mat // no new load to judge by: the one it was verified under stands
	}
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
// recheckTLS and ends it. status_unavailable keeps the window
// DeclineStanding marks; any other refusal is reset with no window. Neither
// is a strike, and neither is a handshake, so port49_tls_handshakes_total
// does not count it.
func (s *conn) tlsPacketRefused(h wire.Header, v devicecert.Verdict) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Device: s.deviceBlock(),
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagTLSRefused),
			Transport: admission.TransportTLS, TLSOutcome: string(v.Outcome), Detail: v.Detail,
			CertSHA256: s.tls.certSHA, Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagTLSRefused)).Inc()
	s.d.Metrics.ConnectionEvents.WithLabelValues("admission_closed").Inc()
	if s.d.TLS.Said != nil {
		s.d.TLS.Said(s.dev.Device.Name, s.src.String(), v)
	}
	// A bare RST: no close_notify first (L73 has not measured what a device
	// does with one before a reset). Only a status that cannot be
	// established keeps a window; the spec (decision 50 ruling 9) gives no
	// window to another refusal, and the device is still admitted, so a plain
	// one would be dropped at the next Accept.
	if v.Outcome == devicecert.StatusUnavailable {
		s.declineStanding()
		return
	}
	s.reset()
}

// obfuscatedOverTLS answers a packet whose unencrypted flag is clear on the
// RFC 9887 listener as RFC 9887 §4 requires: its type's ERROR with the flag
// set, then the connection closes (serve's deferred Close sends
// close_notify). The body, which ValidateTLS bounded at wire.MaxBodyLen, is
// read and discarded first, never hashed or logged: a socket closed with
// unread data sends a reset, which can drop the ERROR still queued
// (pre-flight M1). At seq_no 255 it is closed without a reply. The peer's certificate verified, so it is no strike
// (ruling 13).
func (s *conn) obfuscatedOverTLS(h wire.Header) {
	s.unvalidated(h, nil, keyring.DiagObfuscatedOverTLS, 0)
	if _, err := io.CopyN(io.Discard, s.c, int64(h.Length)); err != nil {
		return // the peer is gone, or the read deadline passed: nothing to answer
	}
	if h.SeqNo == 255 {
		return // no reply: seq_no + 1 would wrap, and the seq 255 rule closes (conn.go)
	}
	rh, body := wire.ErrorReply(h)
	s.wmu.Lock()
	defer s.wmu.Unlock()
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
