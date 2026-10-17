package placement

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// twoRegions is two routers sharing one directory, each on a session store
// of its own (R13 as ruled).
func twoRegions(reach *bool) (a, b store.Store, sa, sb, dir *memory.Store) {
	sa, sb, dir = memory.New(clock), memory.New(clock), memory.New(clock)
	mk := func(s *memory.Store) store.Store {
		return Wrap(Config{Session: s, Directory: dir, Members: dir, Marks: store.NewMarks(),
			Reachable: func() bool { return reach == nil || *reach }, CallTimeout: time.Second, BulkTimeout: time.Second})
	}
	return mk(sa), mk(sb), sa, sb, dir
}

func member(entry string, at time.Time) store.Membership {
	return store.Membership{Principal: alice, EntryID: entry, Username: "alice", GroupNames: []string{"neteng"},
		MapKeys: []string{"k1"}, VerifiedAt: at}
}

// counting is a directory that counts its pin writes, and refuses one with
// a lease (R13: a directory pin has none).
type counting struct {
	Members
	puts int
}

func (c *counting) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	c.puts++
	if ttl != store.NoExpiry {
		return errors.New("a directory pin written with a lease")
	}
	return c.Members.PutMembership(ctx, m, ttl)
}

// A first bind writes the pin to the directory, with no lease and no groups;
// a refresh with the same pin writes the session store alone.
func TestAFirstBindPinsInTheDirectoryAndARefreshDoesNot(t *testing.T) {
	ctx := context.Background()
	sa, dir := memory.New(clock), memory.New(clock)
	writes := &counting{Members: dir}
	a := Wrap(Config{Session: sa, Directory: dir, Members: writes, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	pin, err := dir.GetMembership(ctx, alice)
	if err != nil || pin.EntryID != "uuid:1" || len(pin.GroupNames) != 0 || writes.puts != 1 {
		t.Fatalf("the directory's pin: %+v %v after %d write(s) (it holds no groups)", pin, err, writes.puts)
	}
	if err := a.PutMembership(ctx, member("uuid:1", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := sa.GetMembership(ctx, alice); err != nil || !got.VerifiedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("the session's record: %+v %v", got, err)
	}
	if writes.puts != 1 {
		t.Fatalf("a refresh with the same pin wrote the directory (%d writes)", writes.puts)
	}
}

// C1: a pin outlives its principal's session record and any lease: a day
// and more on, with this region's record gone and the cache cold, a read
// still answers the pin, so Resolver.pinned refuses any other entry.
func TestAPinOutlivesItsTTL(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	tick := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	sess, dir := memory.New(tick), memory.New(tick)
	a := Wrap(Config{Session: sess, Directory: dir, Members: dir, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := a.PutMembership(ctx, member("uuid:1", t0), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(48 * time.Hour)
	mu.Unlock()
	a.(*placed).dropPins() // a restart's cold cache
	if _, err := sess.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("setup: the session record should have lapsed: %v", err)
	}
	got, err := a.GetMembership(ctx, alice)
	if err != nil || got.EntryID != "uuid:1" || !got.VerifiedAt.IsZero() || len(got.GroupNames) != 0 {
		t.Fatalf("%+v %v: want the pin alone, a day on", got, err)
	}
}

// C1: a pin the directory lost (an older backup restored) while this
// region's record holds it is put back from the record, said, and served;
// it is never read as unpinned.
func TestAPinTheDirectoryLostIsPutBackFromTheRegionsRecord(t *testing.T) {
	ctx := context.Background()
	sess, dir := memory.New(clock), memory.New(clock)
	var said []string
	a := Wrap(Config{Session: sess, Directory: dir, Members: dir, Marks: store.NewMarks(),
		Say: func(f string, _ ...any) { said = append(said, f) }, CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := sess.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
		t.Fatalf("%+v %v: want this region's pin", got, err)
	}
	if pin, err := dir.GetMembership(ctx, alice); err != nil || pin.EntryID != "uuid:1" || len(said) != 1 {
		t.Fatalf("the directory's pin: %+v %v, said %d", pin, err, len(said))
	}
}

// One forget, in region a, frees the principal in region b: b's read takes
// the pin from the directory, which has forgotten it.
func TestOneForgetReachesEveryRegion(t *testing.T) {
	ctx := context.Background()
	a, b, _, sb, _ := twoRegions(nil)
	if err := b.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.GetMembership(ctx, alice); err != nil {
		t.Fatalf("setup: region b's own copy should still be there: %v", err)
	}
	if _, err := b.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("region b still reads a pin region a forgot: %v", err)
	}
	if err := b.PutMembership(ctx, member("uuid:2", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatalf("the re-created entry could not be pinned after the forget: %v", err)
	}
	a.(*placed).dropPin(alice) // what a's FollowPins does at b's re-pin
	if got, _ := a.GetMembership(ctx, alice); got.EntryID != "uuid:2" {
		t.Fatalf("region a reads pin %q, want region b's new one", got.EntryID)
	}
}

// I2: after a forget and a re-pin to another entry in region a, region b's
// read answers the new pin with none of the old entry's groups.
func TestARePinHidesTheOldEntrysFreshness(t *testing.T) {
	ctx := context.Background()
	a, b, _, _, _ := twoRegions(nil)
	if err := b.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	other := member("uuid:2", t0.Add(time.Minute))
	other.GroupNames = []string{"ops"}
	if err := a.PutMembership(ctx, other, time.Hour); err != nil {
		t.Fatal(err)
	}
	b.(*placed).dropPin(alice) // b's FollowPins at a's re-pin
	got, err := b.GetMembership(ctx, alice)
	if err != nil || got.EntryID != "uuid:2" || len(got.GroupNames) != 0 || !got.VerifiedAt.IsZero() {
		t.Fatalf("%+v %v: want the new pin with no freshness from the old entry", got, err)
	}
}

// I2: a re-verify of the same entry after a forget pins it again, though
// this region's record already names that entry.
func TestAReVerifyAfterAForgetPinsAgain(t *testing.T) {
	ctx := context.Background()
	a, b, _, _, dir := twoRegions(nil)
	if err := b.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	b.(*placed).dropPin(alice)
	if err := b.PutMembership(ctx, member("uuid:1", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatal(err)
	}
	if pin, err := dir.GetMembership(ctx, alice); err != nil || pin.EntryID != "uuid:1" {
		t.Fatalf("the directory after the re-verify: %+v %v, want uuid:1 pinned again", pin, err)
	}
}

// racing is a directory whose next pin read runs during() after it reads:
// a feed change landing between a miss's read and its fill.
type racing struct {
	Members
	during func()
}

func (r *racing) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	m, err := r.Members.GetMembership(ctx, p)
	if f := r.during; f != nil {
		r.during = nil
		f()
	}
	return m, err
}

// I3: a fill read before a change the feed brought is not cached: the next
// read goes to the directory and sees the change.
func TestAFillRacedByTheFeedIsNotCached(t *testing.T) {
	ctx := context.Background()
	sess, dir := memory.New(clock), memory.New(clock)
	r := &racing{Members: dir}
	s := Wrap(Config{Session: sess, Directory: dir, Members: r, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := s.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	r.during = func() {
		if _, err := dir.DeleteMembership(ctx, alice); err != nil { // a forget in another region
			t.Error(err)
		}
		s.(*placed).dropPin(alice) // the feed's delivery of it
	}
	if _, err := s.GetMembership(ctx, alice); err != nil {
		t.Fatalf("the raced read answers what it read: %v", err)
	}
	if s.(*placed).cachedPin(alice) {
		t.Fatal("a fill read before the feed's change was cached")
	}
	if _, err := s.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the next read did not see the forget: %v", err)
	}
}

// switchable is a directory that answers through Store until hang is set,
// and then never answers, as a blackholed etcd does.
type switchable struct {
	store.Store
	hang bool
}

func (s *switchable) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	if s.hang {
		<-ctx.Done()
		return store.Membership{}, ctx.Err()
	}
	return s.Store.GetMembership(ctx, p)
}

// R4: a pin read is the watched cache's: with the directory blackholed, a
// read of a cached pin answers at once, never waiting on etcd; a change the
// feed brings drops the entry, and the next read goes to the directory.
func TestAPinReadIsTheCaches(t *testing.T) {
	ctx := context.Background()
	sess, dir := memory.New(clock), &switchable{Store: memory.New(clock)}
	s := Wrap(Config{Session: sess, Directory: dir.Store, Members: dir, Marks: store.NewMarks(),
		CallTimeout: 5 * time.Second, BulkTimeout: 5 * time.Second})
	if err := s.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMembership(ctx, alice); err != nil { // the miss fills the cache
		t.Fatal(err)
	}
	dir.hang = true
	start := time.Now()
	got, err := s.GetMembership(ctx, alice)
	if err != nil || got.EntryID != "uuid:1" || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("%+v %v after %v: a cached pin waited on the directory", got, err, time.Since(start))
	}
	s.(*placed).dropPin(alice) // what FollowPins does at a change
	dir.hang = false
	if _, err := dir.Store.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after the feed's change the read did not go to the directory: %v", err)
	}
}

// fakePinFeed delivers each principal sent on ch as a change.
type fakePinFeed struct{ ch chan string }

func (f fakePinFeed) Revision(context.Context) (uint64, error) { return 1, nil }
func (f fakePinFeed) WatchMemberships(ctx context.Context, _ uint64, fn func(string, uint64), _ func(uint64)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p := <-f.ch:
			fn(p, 2)
		}
	}
}

func TestFollowPinsDropsAChangedPin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, _, _, _, _ := twoRegions(nil)
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	feed := fakePinFeed{ch: make(chan string)}
	up := make(chan bool, 4)
	go FollowPins(ctx, a, feed, func(b bool) { up <- b }, func(string, ...any) {})
	if !<-up { // after the start's dropPins, before the watch
		t.Fatal("the pins watch did not start")
	}
	a.GetMembership(ctx, alice)
	if !a.(*placed).cachedPin(alice) {
		t.Fatal("setup: the read did not fill the cache")
	}
	feed.ch <- alice
	deadline := time.Now().Add(2 * time.Second)
	for a.(*placed).cachedPin(alice) {
		if time.Now().After(deadline) {
			t.Fatal("the feed's change did not drop the cached pin")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With the directory cut: a pinned member's refresh and read keep working
// from the cached pin, and say so; a first bind and a forget fail closed.
func TestACutDirectoryServesTheCachedPinAndRefusesNewPins(t *testing.T) {
	ctx := context.Background()
	reach := true
	a, _, _, _, _ := twoRegions(&reach)
	var said []string
	a.(*placed).c.Say = func(f string, args ...any) { said = append(said, f) }
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	reach = false
	if err := a.PutMembership(ctx, member("uuid:1", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatalf("a pinned member's refresh during the cut: %v", err)
	}
	if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" || len(said) != 1 {
		t.Fatalf("the cached pin: %+v %v, said %d", got, err, len(said))
	}
	bob := member("uuid:9", t0)
	bob.Principal = "user:bob@example.com"
	if err := a.PutMembership(ctx, bob, time.Hour); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a first bind during the cut: %v, want ErrUnavailable", err)
	}
	if _, err := a.DeleteMembership(ctx, alice); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a forget during the cut: %v, want ErrUnavailable", err)
	}
}
