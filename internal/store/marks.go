package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Marks is the daemon's copy of the standing revocation marks (plan 7d;
// spec §13, decision 35). The store is the authority: port49d loads every
// mark from it at start, before any listener binds, and the broker adds a
// mark before its write is sent, keeping it unless the store refused the
// write, and removes one once its lift has. The
// authorizer, the enable gate and a receipt's replay read it on every
// request, so a context its principal or certificate names is denied
// whatever the record says: a record put back from before the revocation,
// or a context a revocation never reached (a start that kept it). It has
// no minted-after exception, unlike CarryRevocation: a mint reads the
// marks first and after its last write and deletes what it wrote if one
// appeared (decision 32), so no live token was minted after a standing
// mark. A nil *Marks names nothing. It is safe for concurrent use.
type Marks struct {
	mu sync.RWMutex
	m  map[[2]string]time.Time
	// unwritten is each mark put in force before the store was known to
	// hold it (Pend): a load that lacks it keeps it (Ruling T9-b).
	unwritten map[[2]string]bool
}

// NewMarks is an empty set: no mark stands.
func NewMarks() *Marks { return &Marks{m: map[[2]string]time.Time{}, unwritten: map[[2]string]bool{}} }

// Set puts r in force, or lifts it when on is false. A mark already in
// force keeps its first time, as PutRevocation keeps it. A lift lifts an
// unwritten mark too.
func (m *Marks) Set(r Revocation, on bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{r.Kind, r.Key}
	if !on {
		delete(m.m, k)
		delete(m.unwritten, k)
		return
	}
	if _, ok := m.m[k]; !ok {
		m.m[k] = r.At
	}
}

// Pend puts r in force as Set does, before its store write is known to
// have landed: the broker's mark ahead of its PutRevocation, kept when
// that write fails (Revoke). Until a load or the marks feed shows the
// store holds it, or Put says so, a load that lacks it keeps it standing
// (LoadMarks; Ruling T9-b): a reload is not a lift, and a mark this
// process could not record is denied here until a lift or a restart.
func (m *Marks) Pend(r Revocation) {
	if m == nil {
		return
	}
	m.Set(r, true)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unwritten[[2]string{r.Kind, r.Key}] = true
}

// stored says the store holds the mark for (kind, key): it is unwritten
// no longer.
func (m *Marks) stored(kind, key string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.unwritten, [2]string{kind, key})
}

// unwrittenHeld reports whether the mark for (kind, key) is unwritten.
func (m *Marks) unwrittenHeld(kind, key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.unwritten[[2]string{kind, key}]
}

// Put puts r in force at r.At, replacing the time of a mark already in
// force: the broker's correction once the store says which mark stands,
// so it is unwritten no longer.
func (m *Marks) Put(r Revocation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{r.Kind, r.Key}
	m.m[k] = r.At
	delete(m.unwritten, k)
}

// Holds reports whether a mark for (kind, key) is in force.
func (m *Marks) Holds(kind, key string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.m[[2]string{kind, key}]
	return ok
}

// RevokedAt is when c stands revoked: the later of its own RevokedAt and
// a mark standing for its principal or its certificate (CertKey of its
// credential; a blank key names no certificate). Zero when neither.
func (m *Marks) RevokedAt(c Context) time.Time {
	return later(c.RevokedAt, m.Standing(c.Principal, CertKey(c.Credential.Issuer, c.Credential.Serial)))
}

// Standing is the later of the marks standing for principal and for
// certKey, zero when neither stands. An empty principal or a blank
// certificate key names nothing. A receipt's replay asks it of the
// credential presented, which a context need not name (plan 7d).
func (m *Marks) Standing(principal, certKey string) time.Time {
	var at time.Time
	if m == nil {
		return at
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.m[[2]string{RevocationPrincipal, principal}]; ok && principal != "" {
		at = later(at, t)
	}
	if !BlankCertKey(certKey) {
		if t, ok := m.m[[2]string{RevocationCert, certKey}]; ok {
			at = later(at, t)
		}
	}
	return at
}

// Len is how many marks stand.
func (m *Marks) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.m)
}

// All is every mark in force, sorted by kind and key.
func (m *Marks) All() []Revocation {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Revocation, 0, len(m.m))
	for k, at := range m.m {
		out = append(out, Revocation{Kind: k[0], Key: k[1], At: at})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// MarkChange is one change applied to a process's marks (plan 7e, Ruling
// 5): a mark that now stands, or one lifted. Reloaded is a change a load
// found by difference, not an event the watch delivered: a mark missing
// from a load may be a lift made in a gap, or a mark an etcd restore lost
// (Ruling 12).
type MarkChange struct {
	Revocation
	Standing, Reloaded bool
}

// LoadMarks makes m the store's marks (plan 7e, Ruling 5): every mark feed
// holds is put in, every mark m holds that feed lacks is lifted, unless it
// is unwritten (Pend; Ruling T9-b), and on is told of each change, as
// Reloaded (nil tells nothing). It returns the
// revision read at, which FollowMarks follows from.
func LoadMarks(ctx context.Context, feed MarkFeed, m *Marks, on func(MarkChange)) (uint64, error) {
	rev, rs, err := feed.Revocations(ctx)
	if err != nil {
		return 0, err
	}
	stored := map[[2]string]bool{}
	for _, r := range rs {
		stored[[2]string{r.Kind, r.Key}] = true
		m.stored(r.Kind, r.Key)
		if !m.Holds(r.Kind, r.Key) {
			m.Set(r, true)
			if on != nil {
				on(MarkChange{Revocation: r, Standing: true, Reloaded: true})
			}
		}
	}
	for _, r := range m.All() {
		if !stored[[2]string{r.Kind, r.Key}] && !m.unwrittenHeld(r.Kind, r.Key) {
			m.Set(r, false)
			if on != nil {
				on(MarkChange{Revocation: r, Reloaded: true})
			}
		}
	}
	return rev, nil
}

// FollowMarks keeps m current from feed after `from` until ctx ends, and
// returns ctx's error then (plan 7e, Ruling 5). Each put and lift is
// applied to m and told to on, a put making its mark the store's (no
// longer unwritten); one that changes nothing (a put of a mark
// standing, a lift of one that does not) tells nothing. A compacted watch
// loads the marks again (LoadMarks), telling on only of the difference,
// tells rescanned, and goes on from the later of the load's revision and
// the last change delivered. A watch that fails is tried again every
// second, from the last change delivered: watched again from where the
// follow began, a put whose lift came after would stand again for a
// moment, and close the held connections of a principal already let back
// in. up and logf are as crypt.FollowContexts's.
func FollowMarks(ctx context.Context, feed MarkFeed, m *Marks, from uint64, on func(MarkChange),
	up func(bool), rescanned func(), logf func(string, ...any)) error {
	failing := false
	for {
		up(true)
		err := feed.WatchRevocations(ctx, from, func(r Revocation, lifted bool, rev uint64) {
			from = max(from, rev)
			if !lifted {
				m.stored(r.Kind, r.Key)
			}
			if m.Holds(r.Kind, r.Key) == !lifted {
				return
			}
			m.Set(r, !lifted)
			if on != nil {
				on(MarkChange{Revocation: r, Standing: !lifted})
			}
		})
		up(false)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrCompacted) {
			logf("store: the marks feed's revision was compacted; loading the marks again")
			rescanned()
			if rev, lerr := LoadMarks(ctx, feed, m, on); lerr == nil {
				from, failing = max(from, rev), false
				continue
			} else {
				err = lerr
			}
		}
		if !failing {
			logf("store: the marks feed stopped (%v); trying again every second", err)
			failing = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
