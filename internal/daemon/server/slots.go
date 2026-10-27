package server

import (
	"fmt"
	"sync"
	"time"
)

// Slots is port49d's global connection cap (design §11; decision 53 ruling
// 8): one pool across both TACACS+ listeners, held by accepted connections
// alone. It is taken after Accept and after the per-source checks, so those
// bind first, and a full pool sheds: the connection is reset at once and the
// device takes its next server, since "a request answered after the device
// has already given up is worse than a refused connection". Nil is no cap.
type Slots struct {
	c   chan struct{}
	now func() time.Time

	// The shed line's state. Shed runs only after a shed, off the served
	// path, and from at most one accept loop per listener, so a mutex costs
	// nothing and keeps the line exact: one onset line, counts that sum.
	// The times are time.Time from the clock given, so with time.Now they
	// carry the monotonic reading and a wall-clock step is no step.
	mu        sync.Mutex
	lastShed  time.Time // the last shed, to tell a new run of shedding
	said      time.Time // when a shedding line was last said
	sinceSaid int       // sheds since then
}

func NewSlots(n int, now func() time.Time) *Slots {
	return &Slots{c: make(chan struct{}, n), now: now}
}

// TryAcquire takes a slot if one is free, never waiting. release frees it
// once, however often it is called.
func (s *Slots) TryAcquire() (release func(), ok bool) {
	if s == nil {
		return func() {}, true
	}
	select {
	case s.c <- struct{}{}:
	default:
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(func() { <-s.c }) }, true
}

// shedQuiet is how long without a shed ends a run of shedding, and how often
// a run that goes on is said.
const shedQuiet = time.Minute

// Shed counts one shed connection and returns the line to say now (spec §12,
// "Connection shedding"): at once when shedding begins, then at most once a
// minute with the number shed since, so a cap that engages is seen the
// moment it bites and never silently (design §11).
func (s *Slots) Shed() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// An elapsed time below zero is a clock that stepped back where the
	// reading carries no monotonic part: a line is due, never silence.
	due := func(since time.Time) bool {
		d := now.Sub(since)
		return d < 0 || d >= shedQuiet
	}
	begins := s.lastShed.IsZero() || due(s.lastShed)
	s.lastShed = now
	s.sinceSaid++
	switch {
	case begins:
		s.said, s.sinceSaid = now, 0
		return fmt.Sprintf("port49d: shedding: all %d TACACS+ connection slots (limits.max_connections) are in "+
			"use; each new connection is reset at Accept and the device tries its next server", cap(s.c))
	case due(s.said):
		n := s.sinceSaid
		s.said, s.sinceSaid = now, 0
		return fmt.Sprintf("port49d: still shedding: %d connections reset at Accept in the last minute; %d of %d "+
			"slots in use", n, len(s.c), cap(s.c))
	}
	return ""
}

func (s *Slots) Cap() int   { return cap(s.c) }
func (s *Slots) InUse() int { return len(s.c) }
