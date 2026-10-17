package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLogoutSetKeepsTheLaterAndExpires(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s := NewLogoutSet(func() time.Time { return now })
	s.Put(LogoutEntry{Logout: Logout{Key: "sid 1:i 1:s", At: now, Origin: "a"}, Until: now.Add(time.Hour)})
	s.Put(LogoutEntry{Logout: Logout{Key: "sid 1:i 1:s", At: now.Add(-time.Minute), Origin: "b"}, Until: now.Add(2 * time.Hour)})
	if l, ok := s.Get("sid 1:i 1:s"); !ok || !l.At.Equal(now) || l.Origin != "a" {
		t.Fatalf("%+v %v: the later At stands", l, ok)
	}
	now = now.Add(90 * time.Minute) // past the first Until, inside the second
	if _, ok := s.Get("sid 1:i 1:s"); !ok {
		t.Fatal("the later Until was not kept")
	}
	now = now.Add(time.Hour)
	if _, ok := s.Get("sid 1:i 1:s"); ok {
		t.Fatal("an expired logout is still served")
	}
	fresh := s.Merge([]LogoutEntry{{Logout: Logout{Key: "sub 1:i 1:u", At: now}, Until: now.Add(time.Hour)}})
	if s.Len() != 1 || len(fresh) != 1 || len(s.All()) != 1 {
		t.Fatalf("Merge left %d, told %d new", s.Len(), len(fresh))
	}
	if again := s.Merge(s.All()); len(again) != 0 {
		t.Fatalf("a load of what the set holds told %d as new", len(again))
	}
	s.Delete("sub 1:i 1:u")
	if _, ok := s.Get("sub 1:i 1:u"); ok {
		t.Fatal("a deleted logout is served")
	}
}

// fakeLogoutFeed fails its first load, then holds es; its watch delivers each
// entry sent on ch.
type fakeLogoutFeed struct {
	mu    sync.Mutex
	fails int
	es    []LogoutEntry
	ch    chan LogoutEntry
}

func (f *fakeLogoutFeed) Logouts(context.Context) (uint64, []LogoutEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return 0, nil, ErrUnavailable
	}
	return 3, f.es, nil
}

func (f *fakeLogoutFeed) WatchLogouts(ctx context.Context, _ uint64, fn func(LogoutEntry, bool, uint64),
	_ func(uint64)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-f.ch:
			fn(e, false, 4)
		}
	}
}

func TestFollowLogoutsLoadsThenTellsEachPut(t *testing.T) {
	now := time.Now()
	set := NewLogoutSet(time.Now)
	f := &fakeLogoutFeed{fails: 1, ch: make(chan LogoutEntry),
		es: []LogoutEntry{{Logout: Logout{Key: "k1", At: now}, Until: now.Add(time.Hour)}}}
	told := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowLogouts(ctx, f, set, 0, func(e LogoutEntry) { told <- e.Key }, func(bool) {}, func(string, ...any) {})
	select {
	case k := <-told: // I4: what a load brings is told, as a put is
		if k != "k1" {
			t.Fatalf("the load told %q", k)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the load's record was never told")
	}
	f.ch <- LogoutEntry{Logout: Logout{Key: "k2", At: now}, Until: now.Add(time.Hour)}
	if k := <-told; k != "k2" {
		t.Fatalf("told %q", k)
	}
	if _, ok := set.Get("k2"); !ok {
		t.Fatal("the delivered logout is not in the set")
	}
}

// A load is a snapshot a concurrent Put may have outrun: the logout it lacks
// stays (fail closed), and one that has lapsed goes.
func TestLogoutSetMergeNeverErasesALiveLogout(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s := NewLogoutSet(func() time.Time { return now })
	stale := s.All() // the snapshot, taken before the logout below
	s.Put(LogoutEntry{Logout: Logout{Key: "sid 1:i 1:s", At: now}, Until: now.Add(time.Hour)})
	s.Put(LogoutEntry{Logout: Logout{Key: "sid 1:i 1:old", At: now}, Until: now.Add(time.Minute)})
	s.Merge(stale)
	if _, ok := s.Get("sid 1:i 1:s"); !ok {
		t.Fatal("a load from before a logout erased it")
	}
	now = now.Add(2 * time.Minute)
	s.Merge(stale)
	if s.Len() != 1 {
		t.Fatalf("a lapsed logout survived the reload: %d held", s.Len())
	}
	now = now.Add(2 * time.Hour) // the kept logout lapses with no reload
	if s.Len() != 0 {
		t.Fatalf("Len counts %d lapsed logouts, want only the live", s.Len())
	}
}
