package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Marks is the daemon's copy of the standing marks (plan 7d; Ruling 17):
// a context its principal or certificate names stands revoked at the
// later of its own mark and the record's; a lifted mark names nothing; a
// blank certificate key names no certificate; nil names nothing.
func TestMarksNameAContextByPrincipalOrCertificate(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	m := NewMarks()
	alice := Context{Principal: "user:alice@example.com", Credential: Credential{Issuer: "CN=Corp CA", Serial: "0a"}}
	if !m.RevokedAt(alice).IsZero() {
		t.Fatal("no mark, revoked")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a principal's mark")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at.Add(time.Hour)}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a repeated mark moved the first one's time")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal}, false)
	if !m.RevokedAt(alice).IsZero() || m.Len() != 0 {
		t.Fatal("a lifted mark")
	}
	m.Set(Revocation{Kind: RevocationCert, Key: CertKey("CN=Corp CA", "0a"), At: at}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a certificate's mark")
	}
	oidc := Context{Principal: "user:bob@example.com"}
	m.Set(Revocation{Kind: RevocationCert, Key: "|", At: at}, true)
	if !m.RevokedAt(oidc).IsZero() {
		t.Fatal("a blank certificate key named an OIDC login")
	}
	later := alice
	later.RevokedAt = at.Add(time.Minute)
	if !m.RevokedAt(later).Equal(later.RevokedAt) {
		t.Fatal("the record's own later revocation")
	}
	var none *Marks
	if !none.RevokedAt(alice).IsZero() {
		t.Fatal("a nil Marks named a mark")
	}
}

// markFeed serves a set of marks at rev 7, and a watch that delivers what
// the test sends. The set is read on FollowMarks's goroutine at a reload,
// so it is behind a lock (pre-flight M4, the race). Each watch's after is
// sent on afters when afters is set, and a send on fail ends the watch
// with that error.
type markFeed struct {
	mu      sync.Mutex
	marks   []Revocation
	events  chan markEvent
	compact chan struct{}
	fail    chan error
	afters  chan uint64
	// progressed is each progress notification the watch tells.
	progressed chan uint64
	// failLoads is how many loads to come fail ErrUnavailable.
	failLoads int
}

type markEvent struct {
	r      Revocation
	lifted bool
	rev    uint64
}

func (f *markFeed) setMarks(rs []Revocation) { f.mu.Lock(); f.marks = rs; f.mu.Unlock() }

func (f *markFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLoads > 0 {
		f.failLoads--
		return 0, nil, ErrUnavailable
	}
	return 7, append([]Revocation(nil), f.marks...), nil
}

// told renders a change for the assertions: key, standing, reloaded.
func told(c MarkChange) string { return fmt.Sprintf("%s %v %v", c.Key, c.Standing, c.Reloaded) }
func (f *markFeed) WatchRevocations(ctx context.Context, after uint64, fn func(Revocation, bool, uint64),
	progress func(uint64)) error {
	if f.afters != nil {
		f.afters <- after
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-f.events:
			fn(e.r, e.lifted, e.rev)
		case rev := <-f.progressed:
			progress(rev)
		case <-f.compact:
			return ErrCompacted
		case err := <-f.fail:
			return err
		}
	}
}

// lines is a logf that keeps what it was told, for a follow's goroutine.
type lines struct {
	mu   sync.Mutex
	said []string
}

func (l *lines) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.said = append(l.said, fmt.Sprintf(format, args...))
}

// last is the last line said.
func (l *lines) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.said) == 0 {
		return ""
	}
	return l.said[len(l.said)-1]
}

// kinds is each line said, as "stopped" or "again", in order.
func (l *lines) kinds() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, s := range l.said {
		switch {
		case strings.Contains(s, "stopped"):
			out = append(out, "stopped")
		case strings.Contains(s, "follows the store again"):
			out = append(out, "again")
		}
	}
	return strings.Join(out, " ")
}

// A feed says each stop, not only its first, and says it follows the store
// again at the first change or progress a new watch delivers (final review
// 7e-1 I-2): at 3am the log tells tonight's outage, not only yesterday's.
func TestTheMarksFeedSaysEachStopAndEachReturn(t *testing.T) {
	f := &markFeed{events: make(chan markEvent), fail: make(chan error), progressed: make(chan uint64),
		compact: make(chan struct{})}
	var said lines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, NewMarks(), 7, nil, func(bool) {}, func() error { return nil }, said.logf)
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	f.fail <- ErrUnavailable
	f.events <- markEvent{r: alice, rev: 8} // the next watch, a second later
	waitFor(t, func() bool { return said.kinds() == "stopped again" })
	f.fail <- ErrUnavailable
	f.progressed <- 9
	waitFor(t, func() bool { return said.kinds() == "stopped again stopped again" })
	f.events <- markEvent{r: alice, lifted: true, rev: 10}
	f.progressed <- 11
	if got := said.kinds(); got != "stopped again stopped again" {
		t.Fatalf("said %q", got)
	}
	// A compacted watch whose reload fails is a stop; the next compacted
	// round's reload succeeds, and the first event after it says the feed
	// is back, once (re-review 1 M-8): a successful reload does not clear
	// the stop silently.
	f.mu.Lock()
	f.failLoads = 1
	f.mu.Unlock()
	f.compact <- struct{}{}
	waitFor(t, func() bool { return said.kinds() == "stopped again stopped again stopped" })
	f.compact <- struct{}{} // the next watch, a second later
	f.events <- markEvent{r: alice, rev: 12}
	waitFor(t, func() bool { return said.kinds() == "stopped again stopped again stopped again" })
	f.progressed <- 13
	if got := said.kinds(); got != "stopped again stopped again stopped again" {
		t.Fatalf("said %q", got)
	}
}

// A reload whose hook fails is not run (re-review 1 C-2): the hook puts
// back the marks an etcd restore lost, and a reload without them would
// lift each, for good. It is a failed watch, said and tried again in a
// second, and the next compacted round's hook and reload run as usual.
func TestAFailedRescanHookReloadsNothing(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	f := &markFeed{events: make(chan markEvent), compact: make(chan struct{})} // the store lacks alice
	m := NewMarks()
	m.Set(alice, true)
	var mu sync.Mutex
	var changes []string
	var ups []bool
	var hooks atomic.Int32
	var said lines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, m, 7, func(c MarkChange) {
		mu.Lock()
		changes = append(changes, told(c))
		mu.Unlock()
	}, func(up bool) {
		mu.Lock()
		ups = append(ups, up)
		mu.Unlock()
	}, func() error {
		if hooks.Add(1) == 1 {
			return errors.New("circuit open")
		}
		return nil
	}, said.logf)
	f.compact <- struct{}{}
	waitFor(t, func() bool { return strings.Contains(said.kinds(), "stopped") })
	mu.Lock()
	if !m.Holds(alice.Kind, alice.Key) || len(changes) != 0 || ups[len(ups)-1] {
		mu.Unlock()
		t.Fatalf("after a failed hook: holds %v, told %v, up %v", m.Holds(alice.Kind, alice.Key), changes, ups)
	}
	mu.Unlock()
	if s := said.last(); !strings.Contains(s, "circuit open") {
		t.Fatalf("the stop does not say the hook's error: %q", s)
	}
	f.compact <- struct{}{} // the next watch, a second later
	waitFor(t, func() bool { return !m.Holds(alice.Kind, alice.Key) })
	mu.Lock()
	defer mu.Unlock()
	if hooks.Load() != 2 || fmt.Sprint(changes) != "[user:alice@example.com false true]" {
		t.Fatalf("the second round: %d hooks, told %v", hooks.Load(), changes)
	}
}

// waitFor polls cond for up to 5s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("not within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// LoadMarks puts every stored mark in, takes out one the store lacks, and
// tells on of each change, each as Reloaded: a mark missing from a load
// may be a restore's loss, not a lift (Ruling 12).
func TestLoadMarksMakesTheCopyTheStores(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	gone := Revocation{Kind: RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(5, 0)}
	m := NewMarks()
	m.Set(gone, true)
	var got []string
	rev, err := LoadMarks(context.Background(), &markFeed{marks: []Revocation{alice}}, m,
		func(c MarkChange) { got = append(got, told(c)) })
	if err != nil || rev != 7 || !m.Holds(alice.Kind, alice.Key) || m.Holds(gone.Kind, gone.Key) {
		t.Fatalf("rev %d: %v; marks %v", rev, err, m.All())
	}
	sort.Strings(got)
	if fmt.Sprint(got) != "[user:alice@example.com true true user:bob@example.com false true]" {
		t.Fatalf("told %v", got)
	}
}

// FollowMarks applies each put and lift, told as events; a compacted
// watch loads them again and applies the difference, telling on of it
// alone, as reloaded.
func TestACompactedMarkFeedReloadsTheDifference(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	carol := Revocation{Kind: RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0)}
	dave := Revocation{Kind: RevocationPrincipal, Key: "user:dave@example.com", At: time.Unix(12, 0)}
	f := &markFeed{events: make(chan markEvent, 1), compact: make(chan struct{}, 1)}
	m := NewMarks()
	var mu sync.Mutex
	var got []string
	on := func(c MarkChange) { mu.Lock(); got = append(got, told(c)); mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, m, 7, on, func(bool) {}, func() error { return nil }, t.Logf)
	f.events <- markEvent{r: alice}
	f.events <- markEvent{r: dave}
	f.events <- markEvent{r: dave, lifted: true}
	waitFor(t, func() bool { return m.Holds(alice.Kind, alice.Key) && !m.Holds(dave.Kind, dave.Key) })
	f.setMarks([]Revocation{carol}) // alice lifted and carol marked while the watch was compacted away
	f.compact <- struct{}{}
	waitFor(t, func() bool { return m.Holds(carol.Kind, carol.Key) && !m.Holds(alice.Kind, alice.Key) })
	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"user:alice@example.com true false", "user:dave@example.com true false",
		"user:dave@example.com false false", // a lift the watch delivered: not reloaded
	}
	if len(got) != 5 || fmt.Sprint(got[:3]) != fmt.Sprint(want) {
		t.Fatalf("told %v", got)
	}
	rest := append([]string(nil), got[3:]...)
	sort.Strings(rest)
	if fmt.Sprint(rest) != "[user:alice@example.com false true user:carol@example.com true true]" {
		t.Fatalf("the reload told %v", rest)
	}
}

// A watch that fails is watched again from the last event it delivered,
// never from where the follow began: re-delivering a put whose lift came
// after would stand the mark again, and close the held connections of a
// principal already let back in. A compacted watch's reload never takes
// the follow back either: it goes on from the later of the load's
// revision and the last event. A put of a mark already standing tells
// nothing, and keeps the mark's first time.
func TestAMarkFeedResumesWhereItWas(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	f := &markFeed{events: make(chan markEvent), compact: make(chan struct{}), fail: make(chan error),
		afters: make(chan uint64, 4)}
	f.setMarks([]Revocation{alice})
	m := NewMarks()
	var mu sync.Mutex
	var got []string
	on := func(c MarkChange) { mu.Lock(); got = append(got, told(c)); mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var rescans atomic.Int32
	go FollowMarks(ctx, f, m, 3, on, func(bool) {}, func() error { rescans.Add(1); return nil }, t.Logf)
	after := func() uint64 {
		select {
		case a := <-f.afters:
			return a
		case <-time.After(5 * time.Second):
			t.Fatal("no watch")
			return 0
		}
	}
	if a := after(); a != 3 {
		t.Fatalf("the first watch is after %d, want 3", a)
	}
	f.events <- markEvent{r: alice, rev: 20}
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: alice.Key, At: time.Unix(99, 0)}, rev: 21}
	// A lift of a mark that does not stand tells nothing; the watch has
	// applied the repeat once this send is taken.
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: "user:zed@example.com"}, lifted: true, rev: 22}
	if all := m.All(); len(all) != 1 || !all[0].At.Equal(alice.At) {
		t.Fatalf("a repeated put: marks %v", all)
	}
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: alice.Key}, lifted: true, rev: 23}
	f.fail <- fmt.Errorf("%w: the watch ended", ErrUnavailable)
	if a := after(); a != 23 {
		t.Fatalf("the watch after a failure is after %d, want 23", a)
	}
	f.compact <- struct{}{} // the load is at 7, below what was delivered
	if a := after(); a != 23 {
		t.Fatalf("the watch after a reload at 7 is after %d, want 23", a)
	}
	if !m.Holds(alice.Kind, alice.Key) || rescans.Load() != 1 {
		t.Fatalf("marks %v, %d rescans", m.All(), rescans.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(got) != "[user:alice@example.com true false user:alice@example.com false false "+
		"user:alice@example.com true true]" {
		t.Fatalf("told %v", got)
	}
}

// A load that fails changes nothing and tells nothing.
func TestALoadThatFailsChangesNoMark(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	m := NewMarks()
	m.Set(alice, true)
	_, err := LoadMarks(context.Background(), failingFeed{}, m, func(MarkChange) { t.Fatal("told") })
	if !errors.Is(err, ErrUnavailable) || !m.Holds(alice.Kind, alice.Key) {
		t.Fatalf("%v; marks %v", err, m.All())
	}
}

type failingFeed struct{}

func (failingFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	return 0, nil, ErrUnavailable
}

func (failingFeed) WatchRevocations(context.Context, uint64, func(Revocation, bool, uint64), func(uint64)) error {
	return ErrUnavailable
}

// All is every mark in force, sorted by kind and key, each with its time.
func TestAllIsEveryMarkSorted(t *testing.T) {
	m := NewMarks()
	m.Set(Revocation{Kind: RevocationPrincipal, Key: "user:b", At: time.Unix(2, 0)}, true)
	m.Set(Revocation{Kind: RevocationPrincipal, Key: "user:a", At: time.Unix(1, 0)}, true)
	m.Set(Revocation{Kind: RevocationCert, Key: "CN=x|0a", At: time.Unix(3, 0)}, true)
	got := ""
	for _, r := range m.All() {
		got += fmt.Sprintf("%s/%s@%d ", r.Kind, r.Key, r.At.Unix())
	}
	if got != "cert/CN=x|0a@3 principal/user:a@1 principal/user:b@2 " {
		t.Fatalf("All %q", got)
	}
	var none *Marks
	if none.All() != nil {
		t.Fatal("a nil Marks has marks")
	}
}

// A mark put in force before its store write has landed (Pend) is never
// lifted by a load the store lacks it in (Ruling T9-b): its write failed,
// or has not committed yet, and a reload is not a lift. Once a load or a
// watch shows the store holds it, or the broker's correction (Put) says
// so, it is the store's like any other, and a load without it lifts it. A
// lift the watch brings, or the broker's own (Set false), lifts it at once.
func TestAReloadKeepsAMarkStillUnwritten(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	ctx := context.Background()
	var got []string
	on := func(c MarkChange) { got = append(got, told(c)) }
	empty, holding := &markFeed{}, &markFeed{marks: []Revocation{alice}}

	m := NewMarks()
	m.Pend(alice)
	if _, err := LoadMarks(ctx, empty, m, on); err != nil || !m.Holds(alice.Kind, alice.Key) || len(got) != 0 {
		t.Fatalf("an unwritten mark after a load without it: %v, holds %v, told %v", err,
			m.Holds(alice.Kind, alice.Key), got)
	}
	LoadMarks(ctx, holding, m, on) // the store has it now
	LoadMarks(ctx, empty, m, on)
	if m.Holds(alice.Kind, alice.Key) || fmt.Sprint(got) != "[user:alice@example.com false true]" {
		t.Fatalf("a mark the store held, then lacked: holds %v, told %v", m.Holds(alice.Kind, alice.Key), got)
	}

	m.Pend(alice)
	m.Put(alice) // the broker's correction: the store holds it
	LoadMarks(ctx, empty, m, nil)
	if m.Holds(alice.Kind, alice.Key) {
		t.Fatal("a mark Put said the store held outlived a load without it")
	}

	m.Pend(alice)
	m.Set(alice, false) // the broker's own lift
	m.Set(alice, true)  // marked again, written
	LoadMarks(ctx, empty, m, nil)
	if m.Holds(alice.Kind, alice.Key) {
		t.Fatal("a lifted unwritten mark stayed unwritten")
	}

	// The watch: a put shows the store holds it; a lift lifts it.
	f := &markFeed{events: make(chan markEvent), compact: make(chan struct{})}
	m.Pend(alice)
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go FollowMarks(fctx, f, m, 7, nil, func(bool) {}, func() error { return nil }, t.Logf)
	f.events <- markEvent{r: alice, rev: 8}
	f.compact <- struct{}{} // the load is empty: the watched put made it the store's
	waitFor(t, func() bool { return !m.Holds(alice.Kind, alice.Key) })
	m.Pend(alice)
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: alice.Key}, lifted: true, rev: 9}
	waitFor(t, func() bool { return !m.Holds(alice.Kind, alice.Key) })
}

// A kept mark (Keep) stands through a load that lacks it, and tells
// nothing; a lift the watch delivers lifts it, and so does a later load
// once a load has seen the store hold it again (plan 7e, Ruling 5). The
// control: the same load lifts a mark not kept.
func TestAKeptMarkStandsThroughAReloadUntilAWatchedLift(t *testing.T) {
	ctx := context.Background()
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	var changes []string
	on := func(c MarkChange) { changes = append(changes, told(c)) }

	unkept := NewMarks()
	unkept.Set(alice, true)
	if _, err := LoadMarks(ctx, &markFeed{}, unkept, nil); err != nil || unkept.Holds(alice.Kind, alice.Key) {
		t.Fatalf("control: a load lacking an unkept mark: %v %v", unkept.All(), err)
	}

	m := NewMarks()
	m.Keep(alice) // not in force: nothing
	if m.Holds(alice.Kind, alice.Key) {
		t.Fatal("Keep put a mark in force")
	}
	m.Set(alice, true)
	m.Keep(alice)
	if _, err := LoadMarks(ctx, &markFeed{}, m, on); err != nil || !m.Holds(alice.Kind, alice.Key) || len(changes) != 0 {
		t.Fatalf("a load lacking a kept mark: %v %v %v", m.All(), changes, err)
	}
	back := &markFeed{}
	back.setMarks([]Revocation{alice}) // the runner put it back
	if _, err := LoadMarks(ctx, back, m, on); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMarks(ctx, &markFeed{}, m, on); err != nil || m.Holds(alice.Kind, alice.Key) {
		t.Fatalf("a mark the store held again was kept past its lift: %v %v", m.All(), err)
	}
	m.Set(alice, true)
	m.Keep(alice)
	m.Set(alice, false) // a lift the watch delivered
	if _, err := LoadMarks(ctx, &markFeed{}, m, on); err != nil || m.Holds(alice.Kind, alice.Key) {
		t.Fatalf("a watched lift: %v %v", m.All(), err)
	}
}

// Keep of a mark not in force leaves nothing behind: a mark put in force
// later, and lacking from a load, is lifted as any unkept mark is.
func TestKeepOfAMarkNotInForceLeavesNothing(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	m := NewMarks()
	m.Keep(alice)
	m.Set(alice, true)
	if _, err := LoadMarks(context.Background(), &markFeed{}, m, nil); err != nil || m.Holds(alice.Kind, alice.Key) {
		t.Fatalf("a Keep before the mark was in force kept it: %v %v", m.All(), err)
	}
}

// Put is a correction only: it moves the time of a mark in force, and
// never puts back one lifted meanwhile (review M2).
func TestPutCorrectsOnlyAMarkInForce(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	m := NewMarks()
	if m.Put(alice) || m.Holds(alice.Kind, alice.Key) {
		t.Fatal("Put put back a mark not in force")
	}
	m.Set(Revocation{Kind: alice.Kind, Key: alice.Key, At: time.Unix(20, 0)}, true)
	if !m.Put(alice) || !m.All()[0].At.Equal(alice.At) {
		t.Fatalf("Put did not correct the time: %v", m.All())
	}
}

// Count is told the marks standing by kind at once and after every change
// that moves them, a lift included, and not for one that moves nothing.
func TestCountFollowsEveryChange(t *testing.T) {
	m := NewMarks()
	m.Set(Revocation{Kind: RevocationCert, Key: "CN=x|0a", At: time.Unix(1, 0)}, true)
	var got []string
	m.Count(func(p, c int) { got = append(got, fmt.Sprintf("%d/%d", p, c)) })
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(2, 0)}
	m.Pend(alice)
	m.Set(alice, true) // already standing: no change
	m.Put(alice)       // a correction: no change
	m.Set(alice, false)
	m.Set(alice, false) // not standing: no change
	if fmt.Sprint(got) != "[0/1 1/1 0/1]" {
		t.Fatalf("counted %v", got)
	}
}

// The unrecorded flag is told once and then cleared: by the store showing
// the mark, by Put's correction, and by a lift. A stale flag would tell
// a later Revoke's own mark while it is in flight, so the feed would close
// that Revoke's connections before it could (review R1).
func TestTheUnrecordedFlagIsCleared(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	holding := &markFeed{marks: []Revocation{alice}}
	ctx := context.Background()
	for name, clear := range map[string]func(m *Marks){
		"the store showing it": func(m *Marks) {
			var got []string
			LoadMarks(ctx, holding, m, func(c MarkChange) { got = append(got, told(c)) })
			if fmt.Sprint(got) != "[user:alice@example.com true true]" {
				t.Fatalf("the first load told %v", got)
			}
		},
		"Put":    func(m *Marks) { m.Put(alice) },
		"a lift": func(m *Marks) { m.Set(alice, false); m.Pend(alice) }, // and a fresh Revoke, in flight
	} {
		m := NewMarks()
		m.Pend(alice)
		if m.Unrecorded(alice) {
			t.Fatalf("%s: a mark the store never showed was taken as stored", name)
		}
		clear(m)
		var got []string
		LoadMarks(ctx, holding, m, func(c MarkChange) { got = append(got, told(c)) })
		if len(got) != 0 {
			t.Fatalf("%s: a load told %v after the flag was cleared", name, got)
		}
	}
}

// A hook that keeps failing says the compaction once per run of failures,
// as the stop is, not once a second (re-review 2 M-11); the next run, after
// the feed is back, says it again.
func TestAFailingRescanHookSaysTheCompactionOnce(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	f := &markFeed{events: make(chan markEvent), compact: make(chan struct{})}
	var hooks atomic.Int32
	var said lines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, NewMarks(), 7, nil, func(bool) {}, func() error {
		if hooks.Add(1) <= 3 {
			return errors.New("circuit open")
		}
		return nil
	}, said.logf)
	compacted := func() int {
		said.mu.Lock()
		defer said.mu.Unlock()
		n := 0
		for _, s := range said.said {
			if strings.Contains(s, "the marks feed's revision was compacted") {
				n++
			}
		}
		return n
	}
	for range 3 { // each a second after the last
		f.compact <- struct{}{}
	}
	f.compact <- struct{}{} // the hook succeeds; the feed reloads
	f.events <- markEvent{r: alice, rev: 8}
	waitFor(t, func() bool { return said.kinds() == "stopped again" })
	if n := compacted(); n != 1 {
		t.Fatalf("the compaction said %d times in one run of failures", n)
	}
	f.compact <- struct{}{}
	waitFor(t, func() bool { return compacted() == 2 })
}

// Get answers the mark in force with its origin, as the store holds it:
// the router's GetRevocation reads it (plan 11a).
func TestMarksGetCarriesTheOrigin(t *testing.T) {
	m := NewMarks()
	at := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	m.Set(Revocation{Kind: RevocationCert, Key: "CN=CA|1f", At: at, Origin: "crl corp"}, true)
	got, ok := m.Get(RevocationCert, "CN=CA|1f")
	if !ok || !got.At.Equal(at) || got.Origin != "crl corp" {
		t.Fatalf("%+v %v", got, ok)
	}
	if all := m.All(); len(all) != 1 || all[0].Origin != "crl corp" {
		t.Fatalf("All: %+v", all)
	}
	m.Set(Revocation{Kind: RevocationCert, Key: "CN=CA|1f"}, false)
	if _, ok := m.Get(RevocationCert, "CN=CA|1f"); ok {
		t.Fatal("a lifted mark is still got")
	}
	var none *Marks
	if _, ok := none.Get(RevocationPrincipal, "user:a"); ok {
		t.Fatal("a nil Marks names a mark")
	}
}

// flakyFeed fails its first loads, then holds marks at revision 7; its
// watch honours after, delivering the events above it, then waits.
type flakyFeed struct {
	mu         sync.Mutex
	fails      int
	marks      []Revocation
	events     map[uint64]Revocation
	loads      int
	watchAfter []uint64
}

func (f *flakyFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	if f.fails > 0 {
		f.fails--
		return 0, nil, ErrUnavailable
	}
	return 7, f.marks, nil
}

func (f *flakyFeed) WatchRevocations(ctx context.Context, after uint64, fn func(Revocation, bool, uint64),
	_ func(uint64)) error {
	f.mu.Lock()
	f.watchAfter = append(f.watchAfter, after)
	revs := make([]uint64, 0, len(f.events))
	for rev := range f.events {
		if rev > after {
			revs = append(revs, rev)
		}
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	for _, rev := range revs {
		fn(f.events[rev], false, rev)
	}
	f.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

// A feed never read (from 0) loads first, trying again each second while
// the store does not answer, and keeps what the process held meanwhile:
// a port49d run after a store gone with the directory cut (plan 11a, R19).
func TestFollowMarksFromZeroLoadsFirst(t *testing.T) {
	m := NewMarks()
	held := Revocation{Kind: RevocationPrincipal, Key: "user:held", At: time.Unix(1, 0)}
	m.Set(held, true)
	m.Keep(held)
	newer := Revocation{Kind: RevocationPrincipal, Key: "user:new", At: time.Unix(2, 0)}
	late := Revocation{Kind: RevocationPrincipal, Key: "user:late", At: time.Unix(3, 0)}
	f := &flakyFeed{fails: 1, marks: []Revocation{newer},
		// 7 is in the load already; 8 came between the load and the watch.
		events: map[uint64]Revocation{7: newer, 8: late}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var mu sync.Mutex
	var logs []string
	told := map[string]int{}
	rescans := 0
	go func() {
		done <- FollowMarks(ctx, f, m, 0, func(c MarkChange) {
			mu.Lock()
			told[c.Key]++
			mu.Unlock()
		}, func(bool) {}, func() error { rescans++; return nil },
			func(format string, args ...any) {
				mu.Lock()
				logs = append(logs, fmt.Sprintf(format, args...))
				mu.Unlock()
			})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !m.Holds(RevocationPrincipal, "user:late") {
		if time.Now().After(deadline) {
			t.Fatal("the marks were never loaded and watched")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !m.Holds(RevocationPrincipal, "user:new") || !m.Holds(RevocationPrincipal, "user:held") {
		t.Fatal("a loaded or kept mark is missing")
	}
	cancel()
	<-done
	if f.loads < 2 || rescans < 1 {
		t.Fatalf("loads %d, rescans %d: want a retried load after its hook", f.loads, rescans)
	}
	// The watch starts at the load's revision: the event at 7 is not
	// delivered again, the one at 8 is seen once.
	if len(f.watchAfter) != 1 || f.watchAfter[0] != 7 {
		t.Fatalf("watch started after %v, want [7]", f.watchAfter)
	}
	mu.Lock()
	defer mu.Unlock()
	if told["user:new"] != 1 || told["user:late"] != 1 {
		t.Fatalf("told %v: want each once", told)
	}
	// The failed load is said once with its cause, and the success at once.
	want := []string{
		"store: the marks feed cannot load the marks (" + ErrUnavailable.Error() + "); trying again every second",
		"store: the marks feed loaded the marks; it follows the store again",
	}
	if len(logs) != 2 || logs[0] != want[0] || logs[1] != want[1] {
		t.Fatalf("log %q, want %q", logs, want)
	}
}

// The floor W is the highest revision up to which the feed has delivered
// every mark event (decision 51, the cache; re-review R-M2): the load's
// revision, then each event applied, then each progress notification. It
// never goes down, and nothing but the feed raises it.
func TestTheFloorIsWhatTheMarksFeedDelivered(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	f := &markFeed{events: make(chan markEvent), progressed: make(chan uint64)}
	m := NewMarks()
	if m.ConfirmedRevision() != 0 {
		t.Fatal("a feed never read has a floor")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, m, 0, nil, func(bool) {}, func() error { return nil }, t.Logf)
	waitFor(t, func() bool { return m.ConfirmedRevision() == 7 }) // the load's
	f.events <- markEvent{r: alice, rev: 12}
	waitFor(t, func() bool { return m.ConfirmedRevision() == 12 && m.Holds(alice.Kind, alice.Key) })
	f.progressed <- 15
	waitFor(t, func() bool { return m.ConfirmedRevision() == 15 })
	f.progressed <- 9 // a late notification never lowers it
	f.events <- markEvent{r: alice, lifted: true, rev: 16}
	waitFor(t, func() bool { return !m.Holds(alice.Kind, alice.Key) })
	if w := m.ConfirmedRevision(); w != 16 {
		t.Fatalf("the floor is %d, want 16", w)
	}
	var none *Marks
	if none.ConfirmedRevision() != 0 {
		t.Fatal("a nil Marks has a floor")
	}
}

// A follow begun at a load's revision starts its floor there.
func TestAFollowFromALoadStartsItsFloorThere(t *testing.T) {
	f := &markFeed{events: make(chan markEvent)}
	m := NewMarks()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, m, 31, nil, func(bool) {}, func() error { return nil }, t.Logf)
	waitFor(t, func() bool { return m.ConfirmedRevision() == 31 })
}

// A write this process saw fail is matched by kind, key and time, the time
// as a JSON round trip leaves it, for LiftTTL, whatever lift came between:
// the writer's own late mark is said as its own, and another process's
// mark of the same key is not (post-11b, C2; R-M1).
func TestAFailedWriteIsMatchedByKindKeyAndTime(t *testing.T) {
	now := time.Now()
	m := NewMarks()
	m.now = func() time.Time { return now }
	mine := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Now(), Origin: "admin_socket uid 0"}
	m.Set(mine, true)
	m.NoteFailedWrite(mine)
	m.Set(mine, false) // a lift the feed brought between the failure and the late put
	var back Revocation
	raw, _ := json.Marshal(mine)
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !m.FailedWrite(back.Kind, back.Key, back.At) {
		t.Fatal("the writer's own mark, after a lift and a JSON round trip, is not its failed write")
	}
	if m.FailedWrite(mine.Kind, mine.Key, mine.At.Add(time.Millisecond)) {
		t.Fatal("another process's mark of the same key, at another time, matched")
	}
	if m.FailedWrite(RevocationCert, mine.Key, mine.At) || m.FailedWrite(mine.Kind, "user:bob@example.com", mine.At) {
		t.Fatal("another kind or key matched")
	}
	now = now.Add(LiftTTL + time.Second)
	if m.FailedWrite(back.Kind, back.Key, back.At) {
		t.Fatal("a failed write is remembered past LiftTTL")
	}
	var none *Marks
	none.NoteFailedWrite(mine)
	if none.FailedWrite(mine.Kind, mine.Key, mine.At) {
		t.Fatal("a nil Marks remembered a write")
	}
}

// The flag rides with the mark: Get, All and Flagged carry it, a lift
// drops it, and a repeat put keeps the first mark's.
func TestTheLandedAfterLiftFlagRidesWithTheMark(t *testing.T) {
	m := NewMarks()
	r := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0), LandedAfterLift: true}
	m.Set(r, true)
	m.Set(Revocation{Kind: r.Kind, Key: "user:bob@example.com", At: time.Unix(11, 0)}, true)
	if got, _ := m.Get(r.Kind, r.Key); !got.LandedAfterLift || m.Flagged() != 1 {
		t.Fatalf("got %+v, %d flagged", got, m.Flagged())
	}
	if all := m.All(); !all[0].LandedAfterLift || all[1].LandedAfterLift {
		t.Fatalf("all: %+v", all)
	}
	m.Set(Revocation{Kind: r.Kind, Key: r.Key, At: time.Unix(12, 0)}, true)
	if got, _ := m.Get(r.Kind, r.Key); !got.LandedAfterLift {
		t.Fatal("a repeat put dropped the first mark's flag")
	}
	m.Set(r, false)
	m.Set(Revocation{Kind: r.Kind, Key: r.Key, At: time.Unix(13, 0)}, true)
	if got, _ := m.Get(r.Kind, r.Key); got.LandedAfterLift || m.Flagged() != 0 {
		t.Fatal("a lift kept the flag for the next mark")
	}
}

// A reload that finds a key standing at another time than the copy's is a
// mark lifted and made again while the feed was away: it is applied, and
// told Standing as an add, so its lines fire (post-11b, C2). One the
// reload finds standing as the copy holds it, flagged or not, is told
// nothing: the line prints once (R-I5), and a restart's load counts it.
func TestAReloadTellsAMarkMadeAgainAndNothingElse(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	bob := Revocation{Kind: RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(11, 0), LandedAfterLift: true}
	f := &markFeed{}
	m := NewMarks()
	m.Set(alice, true)
	m.Set(bob, true)
	again := alice
	again.At, again.Origin, again.LandedAfterLift = time.Unix(20, 0), "admin_socket uid 0", true
	f.setMarks([]Revocation{again, bob})
	var got []MarkChange
	if _, err := LoadMarks(context.Background(), f, m, func(c MarkChange) { got = append(got, c) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Key != alice.Key || !got[0].Standing || !got[0].Reloaded || !got[0].LandedAfterLift ||
		!got[0].At.Equal(again.At) {
		t.Fatalf("told %+v", got)
	}
	if cur, _ := m.Get(alice.Kind, alice.Key); !cur.At.Equal(again.At) || cur.Origin != again.Origin ||
		!cur.LandedAfterLift {
		t.Fatalf("the copy holds %+v", cur)
	}
	got = nil
	if _, err := LoadMarks(context.Background(), f, m, func(c MarkChange) { got = append(got, c) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a reload retold marks already standing: %+v", got)
	}
	fresh := NewMarks() // a restart
	if _, err := LoadMarks(context.Background(), f, fresh, nil); err != nil {
		t.Fatal(err)
	}
	if fresh.Flagged() != 2 {
		t.Fatalf("a restart's load counts %d flagged marks, want 2", fresh.Flagged())
	}
}

// A mark this process put in force before the store held it (Pend) keeps
// its own time through a reload that finds another time: its Revoke is
// still in flight and corrects it (Put), and the reload tells nothing.
func TestAReloadLeavesAnUnwrittenMarksTimeToItsRevoke(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	f := &markFeed{}
	f.setMarks([]Revocation{{Kind: alice.Kind, Key: alice.Key, At: time.Unix(5, 0)}})
	m := NewMarks()
	m.Pend(alice)
	if _, err := LoadMarks(context.Background(), f, m, func(c MarkChange) { t.Fatalf("told %+v", c) }); err != nil {
		t.Fatal(err)
	}
}

// The floor, the failed writes and the flag are read and written from the
// feed's goroutine and from revocations at once (run under -race).
func TestTheLandedStateIsSafeForConcurrentUse(t *testing.T) {
	f := &markFeed{events: make(chan markEvent), progressed: make(chan uint64)}
	m := NewMarks()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, m, 1, func(MarkChange) {}, func(bool) {}, func() error { return nil }, t.Logf)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				r := Revocation{Kind: RevocationPrincipal, Key: fmt.Sprintf("user:%d@example.com", i%7),
					At: time.Unix(int64(i), 0), LandedAfterLift: i%2 == 0}
				m.NoteFailedWrite(r)
				_ = m.FailedWrite(r.Kind, r.Key, r.At)
				_ = m.ConfirmedRevision()
				_ = m.Flagged()
				m.Set(r, g%2 == 0)
				_, _ = m.Get(r.Kind, r.Key)
			}
		}(g)
	}
	for i := 0; i < 200; i++ {
		r := Revocation{Kind: RevocationPrincipal, Key: fmt.Sprintf("user:%d@example.com", i%7), At: time.Unix(int64(i), 0),
			LandedAfterLift: true}
		f.events <- markEvent{r: r, lifted: i%3 == 0, rev: uint64(i + 2)}
		if i%10 == 0 {
			f.progressed <- uint64(i + 2)
		}
	}
	wg.Wait()
	waitFor(t, func() bool { return m.ConfirmedRevision() == 201 })
}

// The feed's put of a mark this process's revoke has pending carries the
// store's flag into Marks, so Flagged and the ds/m/ snapshot see it before
// a reload (task 2 review M5).
func TestTheFeedsPutOfAPendingMarkKeepsItsFlag(t *testing.T) {
	m := NewMarks()
	r := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	m.Pend(r)
	flagged := r
	flagged.LandedAfterLift = true
	m.stored(flagged)
	if got, ok := m.Get(r.Kind, r.Key); !ok || !got.LandedAfterLift || m.Flagged() != 1 {
		t.Fatalf("after the feed's put: %+v %v, flagged %d", got, ok, m.Flagged())
	}
}

// A held, unflagged mark the store now holds flagged at the same time (a
// runner's own put-back over a lift it missed, task 2 re-review RR-I1)
// takes the flag and its origin, and is told Standing once: by a load, and
// by the watch's put.
func TestAHeldMarkThatGainsTheFlagIsToldOnce(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	back := alice
	back.Origin, back.LandedAfterLift = PutBackOrigin(""), true
	f := &markFeed{}
	f.setMarks([]Revocation{back})
	m := NewMarks()
	m.Set(alice, true)
	var got []MarkChange
	on := func(c MarkChange) { got = append(got, c) }
	for range 2 {
		if _, err := LoadMarks(context.Background(), f, m, on); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 1 || !got[0].Standing || !got[0].LandedAfterLift || got[0].Origin != back.Origin {
		t.Fatalf("a load told %+v", got)
	}
	if cur, _ := m.Get(alice.Kind, alice.Key); !cur.LandedAfterLift || cur.Origin != back.Origin || m.Flagged() != 1 {
		t.Fatalf("the copy holds %+v, %d flagged", cur, m.Flagged())
	}

	watched := NewMarks()
	watched.Set(alice, true)
	feed := &markFeed{events: make(chan markEvent)}
	feed.setMarks([]Revocation{alice})
	var mu sync.Mutex
	var tells []MarkChange
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		FollowMarks(ctx, feed, watched, 7, func(c MarkChange) { mu.Lock(); tells = append(tells, c); mu.Unlock() },
			func(bool) {}, func() error { return nil }, t.Logf)
	}()
	defer func() { cancel(); <-done }()
	feed.events <- markEvent{r: back, rev: 8}
	feed.events <- markEvent{r: back, rev: 9}
	for watched.ConfirmedRevision() < 9 {
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(tells) != 1 || !tells[0].Standing || !tells[0].LandedAfterLift || watched.Flagged() != 1 {
		t.Fatalf("the watch told %+v, %d flagged", tells, watched.Flagged())
	}
}
