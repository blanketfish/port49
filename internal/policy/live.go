package policy

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Live is the policy in force: one pointer, replaced whole when port49d
// reloads the file (plan 4b). A loaded Policy is never edited, so everything
// that holds one reads a single version throughout; the swap is what changes
// the version, and it changes the broker's answers and the daemon's quarantine
// in one step, because both read this pointer.
//
// Two kinds of reader. The daemon's per-packet quarantine question and the
// quarantine gauge Load the pointer and take no lock: they are one lookup. A
// mint Holds it — a read lock across the resolution and the token write — so
// that once Swap returns, no mint is still writing a token resolved against
// the policy it replaced. The refresh that follows a swap relies on that: it
// deletes the tokens the old policy minted and the new one would not have,
// and a mint still in flight on the old policy would write one after it.
type Live struct {
	mu sync.RWMutex
	p  atomic.Pointer[Policy]
}

// NewLive returns a Live holding p.
func NewLive(p *Policy) *Live {
	l := &Live{}
	l.p.Store(p)
	return l
}

// Load is the policy in force now.
func (l *Live) Load() *Policy { return l.p.Load() }

// Hold is Load for a mint: the policy in force, which stays in force until
// release is called. release must be called exactly once.
func (l *Live) Hold() (p *Policy, release func()) {
	l.mu.RLock()
	return l.p.Load(), l.mu.RUnlock
}

// Swap puts p in force and returns the policy it replaced. It waits for every
// Hold on the old policy to be released, and a Hold after it returns sees p.
func (l *Live) Swap(p *Policy) *Policy {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.p.Swap(p)
}

// Quarantined is (*Policy).Quarantined on the policy in force: the daemon's
// question at every packet (spec §10), answered by whichever version is in
// force when the packet arrives.
func (l *Live) Quarantined(device string, now time.Time) (string, bool) {
	return l.Load().Quarantined(device, now)
}

// NextChange is the first instant after t at which a grant expires, and so at
// which a resolution may change with no edit to the file (spec §5.1). A
// policy-driven refresh runs then as well as at a reload, or a live context
// would keep an expired grant's rules until the next edit. ok is false when no
// grant expires after t.
func (p *Policy) NextChange(t time.Time) (at time.Time, ok bool) {
	for _, g := range p.grants {
		if g.Expires.After(t) && (!ok || g.Expires.Before(at)) {
			at, ok = g.Expires, true
		}
	}
	return at, ok
}

// Principals is every identity a subject lists, sorted: every principal this
// policy can mint for. A group subject lists none; it mints for no one until
// plan 7's directory resolves membership.
func (p *Policy) Principals() []string {
	out := make([]string, 0, len(p.byID))
	for id := range p.byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// UsernameOf is the device-facing username a principal mints under: its
// subject's (spec §2). A token and a login context are keyed by it.
func (p *Policy) UsernameOf(principal string) (string, bool) {
	name, ok := p.byID[principal]
	if !ok {
		return "", false
	}
	return p.subs[name].Username, true
}
