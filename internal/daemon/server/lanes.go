package server

import (
	"context"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// lanes answers the packets of a single-connect connection, one lane per
// session_id: packets of one session in the order they came, packets of
// different sessions at once (spec §13 decision 59; audit F2-1). The read
// loop stays the only reader, and every check before dispatch (admission, the
// quarantine, the TLS recheck, key validation) still runs in it, packet by
// packet; only the dispatch and the reply's write run in the lane. Without
// lanes one session's failure delay or slow store answer held every other
// session's reply on the connection behind it, past a device's reply timeout.
//
// At most maxInFlight packets are read and not yet answered. Past that the
// read loop stops reading until one is answered, so the device's next packet
// waits in the socket and its reply comes late: the head-of-line wait of
// before, behind maxInFlight packets rather than one.
type lanes struct {
	mu sync.Mutex
	// queues holds each session's packets not yet begun. A session_id is a
	// key exactly while its lane's goroutine runs.
	queues map[uint32][]job
	slots  chan struct{} // one per packet read and not yet answered
	wg     sync.WaitGroup
	stop   chan struct{} // closed by abort; a packet not yet begun is then dropped
	once   sync.Once
	why    abortion // set before stop closes
}

// job is one packet read and validated, waiting for its session's lane.
type job struct {
	h       wire.Header
	body    []byte
	secret  []byte    // the key version's secret that validated it; nil over TLS
	arrived time.Time // when its body was read: the failure delay counts from here
}

// abortion is why a lane stopped the connection.
type abortion struct {
	h        wire.Header
	protocol bool // a packet port49 cannot answer: the read loop records it and holds the backoff
}

func newLanes() *lanes {
	return &lanes{queues: map[uint32][]job{}, slots: make(chan struct{}, maxInFlight), stop: make(chan struct{})}
}

// busy reports whether a packet is read and not yet answered: a connection
// owing a reply is not idle.
func (l *lanes) busy() bool { return len(l.slots) > 0 }

// enqueue hands j to its session's lane, starting the lane if it is not
// running. It waits for a slot while maxInFlight packets are in flight, and
// returns false if the connection is aborted or the server shuts down
// meanwhile.
func (s *conn) enqueue(ctx context.Context, j job) bool {
	l := s.lanes
	select {
	case l.slots <- struct{}{}:
	case <-l.stop:
		return false
	case <-ctx.Done():
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	q, running := l.queues[j.h.SessionID]
	l.queues[j.h.SessionID] = append(q, j)
	if !running {
		l.wg.Add(1)
		go s.lane(ctx, j.h.SessionID)
	}
	return true
}

// lane answers session sid's packets in order until none is waiting.
func (s *conn) lane(ctx context.Context, sid uint32) {
	l := s.lanes
	defer l.wg.Done()
	// A panic here is a connection's: recovered, counted and logged by the
	// same code, and the connection is dropped. Nothing more is written to it.
	defer recoverConn(s.src, s.d.Metrics, func() {
		s.halt()
		s.tlsc.Store(nil)
		s.abort(abortion{})
		_ = s.raw.Close()
	})
	for {
		l.mu.Lock()
		q := l.queues[sid]
		if len(q) == 0 {
			delete(l.queues, sid)
			l.mu.Unlock()
			return
		}
		j := q[0]
		l.queues[sid] = q[1:]
		l.mu.Unlock()
		s.answer(ctx, j)
		<-l.slots
	}
}

// answer dispatches one packet and writes its reply. A protocol error, or a
// write that fails, ends the connection through the read loop.
func (s *conn) answer(ctx context.Context, j job) {
	select {
	case <-s.lanes.stop:
		// The connection is ending: a packet not yet begun is dropped, as
		// bytes unread at a close are.
		return
	default:
	}
	reply, _, protoErr := s.dispatch(ctx, j.h, j.body, j.arrived)
	if protoErr {
		s.abort(abortion{h: j.h, protocol: true})
		return
	}
	if reply != nil && !s.write(j.h, reply, j.secret) {
		s.abort(abortion{})
	}
}

// abort stops the connection from a lane: the first reason stands, and the
// read loop is woken from its read by a deadline in the past.
func (s *conn) abort(a abortion) {
	l := s.lanes
	l.once.Do(func() {
		l.why = a
		close(l.stop)
	})
	_ = s.raw.SetReadDeadline(time.Now())
}

// aborted reports whether a lane stopped the connection, and for a protocol
// error records it and holds the backoff as the read loop's own do. The read
// loop asks it whenever a read ends early or a slot wait ends.
func (s *conn) aborted(ctx context.Context) bool {
	select {
	case <-s.lanes.stop:
	default:
		return false
	}
	if s.lanes.why.protocol {
		s.protocolError(ctx, s.lanes.why.h)
	}
	return true
}

// endLanes waits for every lane before serve closes the connection, so no
// session's work outlives it. A dropped connection is closed first: its reset
// is not delayed by another session's failure delay, and nothing more is
// written to it. Any other close waits first, so a reply already owed is
// still written.
func (s *conn) endLanes() {
	s.wmu.Lock()
	dropped := s.dropped
	s.wmu.Unlock()
	if dropped {
		s.abort(abortion{})
		s.c.Close()
		s.lanes.wg.Wait()
		return
	}
	s.lanes.wg.Wait()
	s.c.Close()
}
