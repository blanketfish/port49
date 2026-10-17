package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// LogoutEntry is a back-channel logout's record and when it lapses.
type LogoutEntry struct {
	Logout
	Until time.Time
}

// LogoutSet is a process's copy of the directory store's logout records
// (plan 11a, R26), loaded and followed as the marks are, so a mint's check
// never waits on the directory. It is safe for concurrent use.
type LogoutSet struct {
	mu  sync.RWMutex
	now func() time.Time
	m   map[string]LogoutEntry
}

func NewLogoutSet(now func() time.Time) *LogoutSet {
	return &LogoutSet{now: now, m: map[string]LogoutEntry{}}
}

// Put keeps the later At (with its origin) and the later Until, as
// PutLogout keeps them.
func (s *LogoutSet) Put(e LogoutEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[e.Key]; ok {
		if cur.At.After(e.At) {
			e.At, e.Origin = cur.At, cur.Origin
		}
		if cur.Until.After(e.Until) {
			e.Until = cur.Until
		}
	}
	s.m[e.Key] = e
}

func (s *LogoutSet) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

// Get is the live logout under key.
func (s *LogoutSet) Get(key string) (Logout, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[key]
	if !ok || !s.now().Before(e.Until) {
		return Logout{}, false
	}
	return e.Logout, true
}

// Merge is a load: each entry of es is put as Put does, each live entry
// the load lacks is kept, and each lapsed one is dropped. A load is a snapshot
// that a concurrent Put (an ingestion, a forward) may have outrun, and
// a logout must never be erased by one (fail closed); the cost is a logout
// lingering until its own Until. It returns the entries it did not hold
// before, by key and At, for the runner to reach (I4).
func (s *LogoutSet) Merge(es []LogoutEntry) []LogoutEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	m := make(map[string]LogoutEntry, len(s.m)+len(es))
	for k, e := range s.m {
		if now.Before(e.Until) {
			m[k] = e
		}
	}
	var fresh []LogoutEntry
	for _, e := range es {
		cur, ok := m[e.Key]
		if !ok || !cur.At.Equal(e.At) {
			fresh = append(fresh, e)
		}
		if ok {
			if cur.At.After(e.At) {
				e.At, e.Origin = cur.At, cur.Origin
			}
			if cur.Until.After(e.Until) {
				e.Until = cur.Until
			}
		}
		m[e.Key] = e
	}
	s.m = m
	return fresh
}

// All is every live entry, for a takeover's reach and the directory
// snapshot (R19, R29).
func (s *LogoutSet) All() []LogoutEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := make([]LogoutEntry, 0, len(s.m))
	for _, e := range s.m {
		if now.Before(e.Until) {
			out = append(out, e)
		}
	}
	return out
}

// Len counts the live entries, as the operator line says them.
func (s *LogoutSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, n := s.now(), 0
	for _, e := range s.m {
		if now.Before(e.Until) {
			n++
		}
	}
	return n
}

// LogoutFeed is the directory's logout records as a stream.
type LogoutFeed interface {
	Logouts(ctx context.Context) (uint64, []LogoutEntry, error)
	WatchLogouts(ctx context.Context, after uint64, fn func(e LogoutEntry, deleted bool, rev uint64),
		progress func(rev uint64)) error
}

// FollowLogouts keeps set current from feed after from until ctx ends (R26).
// A from of 0 loads first. Each put the watch delivers is put in set and told
// to on (nil tells nothing): the runner reaches it; so is each record a load
// brings that the set did not hold (I4); a delete (the record's lease) is
// dropped. A compacted watch loads again; a failed one is tried
// again every second, from the last change or progress delivered, the set
// served meanwhile. up says whether the watch runs.
func FollowLogouts(ctx context.Context, feed LogoutFeed, set *LogoutSet, from uint64, on func(LogoutEntry),
	up func(bool), logf func(string, ...any)) error {
	failing := false
	for {
		var err error
		if from == 0 {
			var rev uint64
			var es []LogoutEntry
			if rev, es, err = feed.Logouts(ctx); err == nil {
				fresh := set.Merge(es)
				from = max(rev, 1)
				for _, e := range fresh {
					if on != nil {
						on(e)
					}
				}
			}
		}
		if from != 0 {
			up(true)
			err = feed.WatchLogouts(ctx, from, func(e LogoutEntry, deleted bool, rev uint64) {
				from = max(from, rev)
				if deleted {
					set.Delete(e.Key)
					return
				}
				set.Put(e)
				if on != nil {
					on(e)
				}
			}, func(rev uint64) { from = max(from, rev) })
			up(false)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrCompacted) {
			from = 0
			continue
		}
		if !failing {
			logf("store: the logouts feed stopped (%v); serving the logouts this process holds, trying again every second", err)
			failing = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
