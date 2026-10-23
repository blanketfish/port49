// Package server owns the TACACS+ listeners, RFC 8907 and RFC 9887, and the per-connection loop: admission,
// key trial, dispatch, and every limit of design §11.
//
// Shutdown is orderly on purpose. When ctx is cancelled the listener closes so
// no new connection is accepted, every open connection is closed, and Serve
// returns only once their goroutines have finished — so the caller can then
// wait on the accounting spool knowing nothing more will be offered to it.
package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/platform"
)

// Admitter answers which device a source address is and which key_ref admits
// it (spec §10). port49d passes the policy in force's index. It is read at
// each Accept and again at every packet, so a reload reaches the next
// connection, and one that refuses, removes, renames, re-keys or
// re-platforms a device ends that device's open connections at their next
// packet; *admission.Trie is one.
type Admitter interface {
	Lookup(netip.Addr) (admission.Resolved, bool)
}

type Deps struct {
	Admission Admitter
	// Quarantined reports whether an admitted device is quarantined by the
	// loaded policy at now (spec §10): (*policy.Policy).Quarantined, or nil
	// with no broker. It is asked at every packet, with Now, because a grant's
	// expiry can start or end a quarantine while a connection is open.
	Quarantined func(device string, now time.Time) (cause string, ok bool)
	Keys        map[string]keyring.Set
	// KeySeen marks the key version each admitted device's connection
	// validated under (keyring.Seen.Mark); nil marks nothing.
	KeySeen func(device, keyRef string, version int)
	// Held keeps each admitted device's last unvalidated packet for `port49
	// keys diagnose` (spec §10); nil keeps nothing. port49d sets it only with
	// admin_socket configured.
	Held        *keyring.Held
	Authen      *authen.Handler
	Author      *author.Handler
	Acct        *acct.Handler
	Limits      *limits.Limiter
	Metrics     *metrics.Metrics
	Log         decision.Emitter
	Now         func() time.Time
	IdleTimeout time.Duration
	// PacketDeadline bounds the store work of one packet (the session store's packet_deadline;
	// plan 7d): past it every store call returns, the handler answers
	// store_unavailable, and the device hears that before its own timeout.
	// It never shortens the authentication failure delay. Zero is none.
	PacketDeadline time.Duration
	// Abort reports, when the server's context ends, whether it ended for
	// a store gone (plan 7d; re-check R-M0): held connections are then
	// reset (linger 0), not closed with a FIN, since a reset is what L28
	// measured devices falling to their local method on at once. Nil is a
	// shutdown, closed as before.
	Abort func() bool
	// TLS, when set, makes this the RFC 9887 listener (spec §13 decision 50);
	// nil is the RFC 8907 listener.
	TLS *TLS
	// offers is the per-source count of open offered connections
	// (decision 50 ruling 20); nil makes a new one. A test sets it to watch.
	offers *offers
}

func Serve(ctx context.Context, ln net.Listener, d Deps) error {
	var wg sync.WaitGroup
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-closed:
		}
	}()
	defer func() {
		close(closed)
		wg.Wait()
	}()

	var lastAcceptLog time.Time
	offered := d.offers
	if offered == nil {
		offered = newOffers()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err // the listener is gone for good; retrying would spin
			}
			// Accept-queue pressure: back off briefly rather than spin; the
			// kernel sheds. EMFILE is the realistic cause, and it is not a
			// detail: while it lasts, no admitted device can connect at all,
			// and the same exhaustion fails the spool's own file open. Count
			// and say so — a cap that engages silently is indistinguishable
			// from a bug (design §11) — but throttle the line, since this
			// retries every 10ms for as long as the condition holds.
			d.Metrics.ConnectionEvents.WithLabelValues("accept_error").Inc()
			if time.Since(lastAcceptLog) >= time.Minute {
				log.Printf("server: accept failed, no new connection can be admitted while this lasts: %v", err)
				lastAcceptLog = time.Now()
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil {
			c.Close() // not an IP peer; nothing here can identify it
			continue
		}
		src := ap.Addr().Unmap()

		release, ok := d.Limits.Acquire(src)
		if !ok {
			d.Metrics.ConnectionEvents.WithLabelValues("refused_cap").Inc()
			c.Close()
			continue
		}
		if d.Limits.Holding(src) {
			release()
			d.Metrics.ConnectionEvents.WithLabelValues("held_refused").Inc()
			reset(c)
			c.Close()
			continue
		}
		// Admitted is Refused == "", never an index hit or a key_ref alone: a
		// refused device is in the index, and is given no key (spec §10).
		dev, found := d.Admission.Lookup(src)
		admitted := found && dev.Refused == ""
		listener := admission.TransportTCP
		if d.TLS != nil {
			listener = admission.TransportTLS
		}
		// A device speaks one transport, and the other listener declines it
		// (spec §13 decision 50 ruling 4).
		mismatch := admitted && dev.Device.EffectiveTransport() != listener
		// A source inside a decline window is refused at Accept, before the
		// device writes, but only while port49d still declines it. A reload
		// that admits it again, or the end of its quarantine, drops the
		// window, and this connection is served (spec §10, "A declined source
		// is refused at Accept").
		//
		// Declined, the re-ask and Undecline are not one atomic step, and a
		// reload can land between them. That fails closed: this connection
		// keeps the admission it was just given, serve asks admission and the
		// quarantine again at every packet, and declines the packet if either
		// has changed, reopening the window. At worst the device meets one
		// decline more than an atomic check would give it, never an admission
		// port49d does not hold. A Decline from another connection that lands
		// before Undecline is dropped with it. That also fails closed: the
		// device is asked again at its next packet, so the loss costs one more
		// record and, on IOS-XE and NX-OS with single-connection on, one ~5 s
		// wait, never an admission. A refusal here opens no new window.
		if d.Limits.Declined(src) {
			if declining(d, src, dev, admitted, listener) {
				release()
				d.Metrics.ConnectionEvents.WithLabelValues("declined_refused").Inc()
				reset(c)
				c.Close()
				continue
			}
			d.Limits.Undecline(src)
		}
		// A device port49 offered single-connect to keeps the one connection
		// while it honors the offer. A second one served while an offered one
		// is open says it ignored it: counted here, once the connection is
		// past every refusal at Accept, before its connections reach
		// refused_cap, with no device label (decision 50 rulings 16 and 20).
		if d.TLS != nil && admitted && offered.any(src) && platform.TLSServerSingleConnect(wirePlatform(dev)) {
			d.Metrics.ConnectionEvents.WithLabelValues("single_connect_second_connection").Inc()
		}
		d.Metrics.Connections.WithLabelValues("open").Inc()

		cc := &conn{d: d, c: c, raw: c, src: src, dev: dev, admitted: admitted, mismatch: mismatch,
			refused: found && dev.Refused != "", offers: offered, sessions: map[uint32]*authen.Session{}}
		if cc.admitted && !mismatch && d.TLS == nil {
			cc.keys = d.Keys[dev.KeyRef]
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer release()
			defer d.Metrics.Connections.WithLabelValues("open").Dec()
			// A panic in one connection must never take the daemon down with it,
			// or every other admitted device loses service at once. Never log the
			// packet itself: only the source, the recovered value, and the stack.
			// The stack is function names, files and line numbers — port49's own
			// code, no packet bytes and no arguments — and without it a panic
			// counter tells an operator that something broke and nothing about
			// where.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("conn %s: panic: %v\n%s", src, r, debug.Stack())
					d.Metrics.ConnectionEvents.WithLabelValues("panic").Inc()
					c.Close()
				}
			}()
			// Close the connection on shutdown rather than waiting out its idle
			// timeout; serve's own defer closes it on the normal path. A store
			// gone resets at once (L28). Otherwise a TLS connection is closed
			// with close_notify, as an idle close is, not a bare FIN: an
			// offered connection is held by the device between requests
			// (decision 50 ruling 20). The idle close is the one measured (L80
			// idle35); how an NX-OS device takes a close_notify at shutdown
			// in the middle of a session is not measured, and the L80 restart
			// cell (port49d restarted during a command loop) measures it.
			// crypto/tls bounds the alert's write at 5 s.
			done := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					if d.Abort != nil && d.Abort() {
						reset(c)
						c.Close()
					} else if tc := cc.tlsc.Load(); tc != nil {
						tc.Close()
					} else {
						c.Close()
					}
				case <-done:
				}
			}()
			defer close(done)
			cc.serve(ctx)
		}()
	}
}

// declining reports whether port49d would decline a connection from dev on
// this listener as admission and the policy stand now: a source the
// inventory does not name, a device admission refuses, one of the other
// transport, a quarantined one, or one whose last decline stands until it
// lapses (Limiter.DeclineStanding: a certificate status that could not be
// established, or a server name not in server_names; spec §13 decision 50
// rulings 8 and 10). It is asked only at an Accept inside a decline window.
func declining(d Deps, src netip.Addr, dev admission.Resolved, admitted bool, listener string) bool {
	if !admitted || dev.Device.EffectiveTransport() != listener || d.Limits.DeclinedStanding(src) {
		return true
	}
	if d.TLS != nil {
		mat := d.TLS.Material()
		if mat == nil {
			return true // startTLS says so and declines it
		}
		if _, bad := mat.Unidentifiable[dev.Device.Name]; bad {
			return true
		}
	}
	if d.Quarantined == nil {
		return false
	}
	_, q := d.Quarantined(dev.Device.Name, d.Now())
	return q
}
