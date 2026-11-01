package placement

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
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

// counting is a directory that counts its pin writes (PutPin has no lease
// to give: R13, a directory pin has none).
type counting struct {
	Members
	puts int
}

func (c *counting) PutPin(ctx context.Context, m store.Membership, expect store.PinExpect) error {
	c.puts++
	return c.Members.PutPin(ctx, m, expect)
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

// A pin the watched copy already holds, read while the directory is cut, is
// served and said, as a miss served from this region's record is (spec §13
// d51 R13; run 8 diagnosis, L75 (f)). Said once per principal, not per read.
func TestACutReadOfAWatchedPinIsSaid(t *testing.T) {
	ctx := context.Background()
	reach := true
	a, _, _, _, _ := twoRegions(&reach)
	var said []string
	a.(*placed).c.Say = func(f string, args ...any) { said = append(said, fmt.Sprintf(f, args...)) }
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" || len(said) != 0 {
		t.Fatalf("the reachable read: %+v %v, said %q", got, err, said)
	}
	if _, ok := a.(*placed).cached(alice); !ok {
		t.Fatal("setup: the reachable read left no watched pin")
	}
	reach = false
	for i := 0; i < 2; i++ {
		if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
			t.Fatalf("read %d during the cut: %+v %v", i, got, err)
		}
	}
	if len(said) != 1 || !strings.Contains(said[0], "serving "+alice+"'s cached directory membership") {
		t.Fatalf("said %q, want the cached-pin line once", said)
	}
}

// The cached-pin line is at most once per principal per 10 minutes: a second cut within the window is
// silent, and a cut that starts 10 minutes or more after the last line says it again.
func TestACutTenMinutesAfterTheLastLineSaysTheCachedPinAgain(t *testing.T) {
	ctx := context.Background()
	reach := true
	a, _, _, _, _ := twoRegions(&reach)
	at := t0
	a.(*placed).c.Now = func() time.Time { return at }
	var said []string
	a.(*placed).c.Say = func(f string, args ...any) { said = append(said, fmt.Sprintf(f, args...)) }
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	read := func(up bool, after time.Duration) {
		t.Helper()
		at = at.Add(after)
		reach = up
		if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
			t.Fatalf("read (up %v): %+v %v", up, got, err)
		}
	}
	read(true, 0)
	read(false, 0)
	read(false, time.Second)
	if len(said) != 1 {
		t.Fatalf("the first cut said %q, want one line", said)
	}
	read(true, time.Minute)
	read(false, time.Minute) // 2 minutes after the line
	if len(said) != 1 {
		t.Fatalf("a second cut inside the window said %d lines in all: %q", len(said), said)
	}
	read(true, time.Minute)
	read(false, 10*time.Minute) // past the window
	if len(said) != 2 {
		t.Fatalf("a cut past the window said %d lines in all, want 2: %q", len(said), said)
	}
}

// failingMembers is a directory whose pin reads do not answer while its health check passes.
type failingMembers struct{ Members }

func (failingMembers) GetMembership(context.Context, string) (store.Membership, error) {
	return store.Membership{}, fmt.Errorf("%w: no answer", store.ErrUnavailable)
}

// Health up and reads failing is the worst case for the line: every authorization read serves the
// session's copy, and the line is still once per principal, not once per read.
func TestReadsThatFailWithTheHealthCheckUpSayTheCachedPinOnce(t *testing.T) {
	ctx := context.Background()
	sa, dir := memory.New(clock), memory.New(clock)
	seed := Wrap(Config{Session: sa, Directory: dir, Members: dir, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := seed.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	var said []string
	a := Wrap(Config{Session: sa, Directory: dir, Members: failingMembers{dir}, Marks: store.NewMarks(),
		Reachable: func() bool { return true }, CallTimeout: time.Second, BulkTimeout: time.Second,
		Say: func(f string, args ...any) { said = append(said, fmt.Sprintf(f, args...)) }})
	for i := 0; i < 5; i++ {
		if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
			t.Fatalf("read %d: %+v %v", i, got, err)
		}
	}
	if len(said) != 1 {
		t.Fatalf("5 failing reads said %d lines, want 1: %q", len(said), said)
	}
}

// More principals than the old table held, each read twice inside the window: one line each. A table
// that clears itself when full lifts the window for everyone.
func TestManyPrincipalsAreEachToldOnceInTheWindow(t *testing.T) {
	ctx := context.Background()
	sa, dir := memory.New(clock), memory.New(clock)
	seed := Wrap(Config{Session: sa, Directory: dir, Members: dir, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	const n = 1100
	for i := 0; i < n; i++ {
		m := member("uuid:1", t0)
		m.Principal = fmt.Sprintf("user:p%d@example.com", i)
		if err := seed.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	said := 0
	a := Wrap(Config{Session: sa, Directory: dir, Members: failingMembers{dir}, Marks: store.NewMarks(),
		Reachable: func() bool { return true }, CallTimeout: time.Second, BulkTimeout: time.Second,
		Say: func(string, ...any) { said++ }})
	for round := 0; round < 2; round++ {
		for i := 0; i < n; i++ {
			if _, err := a.GetMembership(ctx, fmt.Sprintf("user:p%d@example.com", i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if said != n {
		t.Fatalf("%d principals read twice said %d lines, want %d", n, said, n)
	}
}

// A full table prunes what is past the window and evicts its oldest, never clearing whole.
func TestTheCachedPinTableEvictsTheOldestWhenFull(t *testing.T) {
	at := t0
	p := Wrap(Config{Session: memory.New(clock), Say: func(string, ...any) {}, Now: func() time.Time { return at }}).(*placed)
	for i := 0; i < sayCachedCap; i++ {
		at = at.Add(time.Millisecond)
		p.sayCached(fmt.Sprintf("p%d", i))
	}
	p.sayCached("one-more")
	if len(p.said) != sayCachedCap {
		t.Fatalf("the table holds %d, want %d", len(p.said), sayCachedCap)
	}
	if _, ok := p.said["p0"]; ok {
		t.Fatal("the oldest entry was not the one evicted")
	}
	if _, ok := p.said["p1"]; !ok {
		t.Fatal("an entry inside the window was dropped")
	}
}

// C1 (review of 8a): a read with the directory cut, the pin not cached and
// no record here is unavailable. ErrNotFound would read as "unpinned", and a
// bind that follows could take the principal.
func TestACutReadOfAnUnheldPrincipalIsUnavailableNotUnpinned(t *testing.T) {
	reach := false
	a, _, _, _, _ := twoRegions(&reach)
	_, err := a.GetMembership(context.Background(), alice)
	if !errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v: want ErrUnavailable and not ErrNotFound", err)
	}
}

// flaky is a directory whose first pin read does not answer.
type flaky struct {
	Members
	failed bool
}

func (f *flaky) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	if !f.failed {
		f.failed = true
		return store.Membership{}, store.ErrUnavailable
	}
	return f.Members.GetMembership(ctx, p)
}

// C1: plan 7g Ruling 3's moved-entry attack. The victim is pinned; the
// attacker's bind reaches a region whose first directory read fails and
// whose second answers. The first read must not read as unpinned, and the
// write must not move the pin whatever the reads said.
func TestAMovedEntryCannotTakeAHeldPinAcrossAFlakyRead(t *testing.T) {
	ctx := context.Background()
	a, _, _, _, dir := twoRegions(nil)
	if err := a.PutMembership(ctx, member("uuid:victim", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	sess := memory.New(clock)
	b := Wrap(Config{Session: sess, Directory: dir, Members: &flaky{Members: dir}, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if _, err := b.GetMembership(ctx, alice); errors.Is(err, store.ErrNotFound) {
		t.Errorf("a failed pin read read as unpinned: %v", err)
	}
	if err := b.PutMembership(ctx, member("uuid:attacker", t0.Add(time.Minute)), time.Hour); err == nil {
		t.Fatal("the attacker's entry was pinned over the victim's")
	}
	if pin, err := dir.GetMembership(ctx, alice); err != nil || pin.EntryID != "uuid:victim" {
		t.Fatalf("the directory's pin: %+v %v, want the victim's", pin, err)
	}
}

// C1: even when a region believes the pin is held and is wrong about which
// entry, nothing moves a held pin but a forget.
func TestAHeldPinIsRefusedToAnotherEntry(t *testing.T) {
	ctx := context.Background()
	a, _, _, _, dir := twoRegions(nil)
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	err := a.PutMembership(ctx, member("uuid:2", t0.Add(time.Minute)), time.Hour)
	if !errors.Is(err, store.ErrPinHeld) || errors.Is(err, store.ErrRefused) {
		t.Fatalf("%v: want ErrPinHeld, which is no etcd-role refusal", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "uuid:1") || !strings.Contains(msg, "uuid:2") || !strings.Contains(msg, "forget") {
		t.Fatalf("%q: want the held and the attempted entry, and the way out", msg)
	}
	if pin, _ := dir.GetMembership(ctx, alice); pin.EntryID != "uuid:1" {
		t.Fatalf("the directory's pin moved to %q", pin.EntryID)
	}
}

// I1: region b's cache says "absent" (the feed lags or is down) after
// region a pinned. b's bind of another entry must not overwrite a's pin; b's
// bind of the same entry succeeds, having read the directory again.
func TestAStaleAbsentCacheCannotOverwriteAnotherRegionsPin(t *testing.T) {
	ctx := context.Background()
	a, b, _, _, dir := twoRegions(nil)
	if _, err := b.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if !b.(*placed).cachedPin(alice) {
		t.Fatal("setup: b did not cache the absent pin")
	}
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := b.PutMembership(ctx, member("uuid:2", t0.Add(time.Minute)), time.Hour); err == nil {
		t.Fatal("b overwrote a's pin from a stale cache")
	}
	if pin, _ := dir.GetMembership(ctx, alice); pin.EntryID != "uuid:1" {
		t.Fatalf("the directory's pin is %q, want a's uuid:1", pin.EntryID)
	}
	b.(*placed).dropPins()
	b.(*placed).fillAbsent(alice) // the stale state again
	if err := b.PutMembership(ctx, member("uuid:1", t0.Add(2*time.Minute)), time.Hour); err != nil {
		t.Fatalf("the same entry's verification after a stale read: %v", err)
	}
}

// I2: the directory lost the pin (an older backup restored) and region b's
// session copy holds it. A forget leaves a tombstone anyway, so b's copy
// cannot put the pin back, and the router says so (ErrNotFound only when
// nothing at all was held).
func TestAForgetOfALostPinStillTombstonesAndBlocksTheWriteBack(t *testing.T) {
	ctx := context.Background()
	a, b, _, sb, dir := twoRegions(nil)
	if err := sb.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("setup: the directory should hold nothing: %v", err)
	}
	if _, err := a.DeleteMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a held nothing: %v", err)
	}
	if _, err := dir.GetMembership(ctx, alice); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("the directory after the forget: %v, want a tombstone", err)
	}
	if _, err := b.GetMembership(ctx, alice); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("b's read: %v, want forgotten", err)
	}
	if _, err := dir.GetMembership(ctx, alice); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("b put the pin back: %v", err)
	}
}

// I2, the forgetting region's own copy: the forget removes it though the
// directory held nothing, and reports what it removed.
func TestAForgetOfALostPinRemovesTheForgettingRegionsCopy(t *testing.T) {
	ctx := context.Background()
	_, b, _, sb, dir := twoRegions(nil)
	if err := sb.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := b.DeleteMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
		t.Fatalf("%+v %v: want the removed copy", got, err)
	}
	if _, err := sb.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the region's own copy outlived the forget: %v", err)
	}
	if _, err := dir.GetMembership(ctx, alice); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("the directory: %v, want a tombstone", err)
	}
	if _, err := b.GetMembership(ctx, alice); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("b's read: %v", err)
	}
}

// fillAbsent caches "absent" for principal, as a read before another
// region's pin would have.
func (p *placed) fillAbsent(principal string) {
	p.fillPin(principal, p.genOf(principal), pinEntry{state: pinAbsent})
}

// conflicting is a directory whose pin writes always lose to another region's.
type conflicting struct{ Members }

func (conflicting) PutPin(context.Context, store.Membership, store.PinExpect) error {
	return store.ErrConflict
}

// Three lost compares in a row say what happened, not "context changed".
func TestAPinThatKeepsChangingSaysSo(t *testing.T) {
	sess, dir := memory.New(clock), memory.New(clock)
	s := Wrap(Config{Session: sess, Directory: dir, Members: conflicting{dir}, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	err := s.PutMembership(context.Background(), member("uuid:1", t0), time.Hour)
	if !errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "kept changing") {
		t.Fatalf("%v: want an unavailable that says the pin kept changing", err)
	}
}

// A forget of a principal held nowhere leaves the tombstone in the
// directory, the authority, and none in the session store.
func TestAForgetOfAnAbsentPrincipalLeavesNoSessionTombstone(t *testing.T) {
	ctx := context.Background()
	a, _, sa, _, dir := twoRegions(nil)
	if _, err := a.DeleteMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := dir.GetMembership(ctx, alice); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("the directory: %v", err)
	}
	if _, err := sa.GetMembership(ctx, alice); errors.Is(err, store.ErrForgotten) || !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session store: %v, want plain not found", err)
	}
}
