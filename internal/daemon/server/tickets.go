package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"sync"
	"time"
)

// TicketGuard makes the RFC 9887 listener's session tickets single-use and
// bounds their age at session_ticket_lifetime (RFC 9887 §3.6; spec §13
// decision 50 ruling 11). A ticket it will not resume is ignored, never an
// error: the device gets a full handshake, which verifies everything again.
type TicketGuard struct {
	lifetime time.Duration
	now      func() time.Time
	start    time.Time // when the guard began: a stamp is the time since

	base *tls.Config // the Config Apply keyed; its keys encrypt and decrypt

	mu     sync.Mutex
	used   map[[32]byte]int64 // a resumed ticket's hash, and the stamp it carried (ns since start)
	pruned time.Time          // when used was last scanned
}

// NewTicketGuard is a guard for tickets lifetime long.
func NewTicketGuard(lifetime time.Duration, now func() time.Time) *TicketGuard {
	return &TicketGuard{lifetime: lifetime, now: now, start: now(), used: map[[32]byte]int64{}}
}

// Apply sets c, the base config every connection's is cloned from, to issue
// tickets under a fresh random key held only in memory. There is one key
// per load and no rotation within it: age comes from the stamp in each
// ticket, and a reload, which applies a new guard to a new base, must
// invalidate every ticket outstanding. A connection issues and resumes
// under the guard only through bind.
func (g *TicketGuard) Apply(c *tls.Config) error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	c.SessionTicketsDisabled = false
	c.SetSessionTicketKeys([][32]byte{key})
	g.base = c
	return nil
}

// bind sets one connection's cloned config to issue and resume under g. A
// ticket carries its chain's full-handshake time: one issued on a
// resumption carries the resumed ticket's time, so no chain of resumptions
// outlives the lifetime. A guard Apply never keyed issues nothing.
func (g *TicketGuard) bind(cfg *tls.Config) {
	if g == nil || g.base == nil {
		cfg.SessionTicketsDisabled = true
		return
	}
	var origin int64
	cfg.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := g.base.DecryptTicket(identity, cs)
		if err != nil || ss == nil {
			return nil, nil
		}
		at, ok := stamp(ss)
		if !ok || !g.fresh(at) || !g.firstUse(identity, at) {
			return nil, nil
		}
		origin = at
		return ss, nil
	}
	cfg.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		at := g.elapsed()
		if cs.DidResume { // crypto/tls sets it before it sends tickets
			at = origin
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(at))
		ss.Extra = append(ss.Extra, b[:])
		return g.base.EncryptTicket(cs, ss)
	}
}

// elapsed is the time since the guard began, in nanoseconds. A ticket's key
// lives only in this process, so no ticket outlives it and a stamp needs no
// wall clock: Sub uses Go's monotonic reading, which a wall-clock step cannot
// move.
func (g *TicketGuard) elapsed() int64 { return int64(g.now().Sub(g.start)) }

// stamp is the elapsed time a ticket's state carries.
func stamp(ss *tls.SessionState) (int64, bool) {
	if len(ss.Extra) == 0 || len(ss.Extra[len(ss.Extra)-1]) != 8 {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(ss.Extra[len(ss.Extra)-1])), true
}

// fresh is whether a ticket stamped at (elapsed ns) is within the lifetime.
func (g *TicketGuard) fresh(at int64) bool {
	return g.elapsed()-at <= int64(g.lifetime)
}

// firstUse records identity, a ticket stamped at, as used and reports
// whether it was not before. An entry leaves when fresh would refuse its
// ticket anyway; the scan runs at most four times a lifetime.
func (g *TicketGuard) firstUse(identity []byte, at int64) bool {
	sum := sha256.Sum256(identity)
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.pruned) >= g.lifetime/4 {
		for k, s := range g.used {
			if !g.fresh(s) {
				delete(g.used, k)
			}
		}
		g.pruned = now
	}
	if _, seen := g.used[sum]; seen {
		return false
	}
	g.used[sum] = at
	return true
}
