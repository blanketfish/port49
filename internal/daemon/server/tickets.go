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

	mu   sync.Mutex
	used map[[32]byte]time.Time // a resumed ticket's hash, and when it was used
}

// NewTicketGuard is a guard for tickets lifetime long.
func NewTicketGuard(lifetime time.Duration, now func() time.Time) *TicketGuard {
	return &TicketGuard{lifetime: lifetime, now: now, used: map[[32]byte]time.Time{}}
}

// Apply sets c, the base config every connection's is cloned from, to issue
// tickets under a fresh random key held only in memory, each stamped with
// its issue time, and to resume a ticket only once and only within the
// lifetime. A new load of the listener's files applies a new guard, so a
// reload invalidates every ticket outstanding.
func (g *TicketGuard) Apply(c *tls.Config) error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	c.SessionTicketsDisabled = false
	c.SetSessionTicketKeys([][32]byte{key})
	c.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		var at [8]byte
		binary.BigEndian.PutUint64(at[:], uint64(g.now().Unix()))
		ss.Extra = append(ss.Extra, at[:])
		return c.EncryptTicket(cs, ss)
	}
	c.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := c.DecryptTicket(identity, cs)
		if err != nil || ss == nil || !g.fresh(ss) || !g.firstUse(identity) {
			return nil, nil
		}
		return ss, nil
	}
	return nil
}

// fresh is whether ss carries an issue time within the lifetime.
func (g *TicketGuard) fresh(ss *tls.SessionState) bool {
	if len(ss.Extra) == 0 || len(ss.Extra[len(ss.Extra)-1]) != 8 {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(ss.Extra[len(ss.Extra)-1])), 0)
	age := g.now().Sub(issued)
	return age >= -time.Minute && age <= g.lifetime
}

// firstUse records identity as used and reports whether it was not before.
// Entries older than the lifetime are dropped: such a ticket is refused as
// stale anyway.
func (g *TicketGuard) firstUse(identity []byte) bool {
	sum := sha256.Sum256(identity)
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, at := range g.used {
		if now.Sub(at) > g.lifetime {
			delete(g.used, k)
		}
	}
	if _, seen := g.used[sum]; seen {
		return false
	}
	g.used[sum] = now
	return true
}

// guarded is whether c carries a guard's hooks: Apply sets both, and nothing
// else in port49 does.
func guarded(c *tls.Config) bool {
	return c.WrapSession != nil && c.UnwrapSession != nil
}
