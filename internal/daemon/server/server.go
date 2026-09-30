// Package server owns the TCP listener and the per-connection loop: admission,
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
)

// Admitter answers which device a source address is and which key_ref admits
// it (spec §10). port49d passes the policy in force's index, read at each
// Accept, so a reload reaches the next connection and a connection finishes
// on the index it began with; *admission.Trie is one.
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
	KeySeen     func(device, keyRef string, version int)
	Authen      *authen.Handler
	Author      *author.Handler
	Acct        *acct.Handler
	Limits      *limits.Limiter
	Metrics     *metrics.Metrics
	Log         decision.Emitter
	Now         func() time.Time
	IdleTimeout time.Duration
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
		d.Metrics.Connections.WithLabelValues("open").Inc()

		// Admitted is Refused == "", never an index hit or a key_ref alone: a
		// refused device is in the index, and is given no key (spec §10).
		dev, found := d.Admission.Lookup(src)
		cc := &conn{d: d, c: c, src: src, dev: dev, admitted: found && dev.Refused == "",
			refused: found && dev.Refused != "", sessions: map[uint32]*authen.Session{}}
		if cc.admitted {
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
			// timeout; serve's own defer closes it on the normal path.
			done := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					c.Close()
				case <-done:
				}
			}()
			defer close(done)
			cc.serve(ctx)
		}()
	}
}
