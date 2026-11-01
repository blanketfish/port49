package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// saidLines is a Broker.Say that keeps every line, for a feed's goroutine.
type saidLines struct {
	mu    sync.Mutex
	lines []string
}

func (s *saidLines) say(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf(format, args...))
}

func (s *saidLines) all() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// cutStore is a store whose revocation writes fail as a cut directory's
// do, floor seen, and whose lift's record is lift (or ErrNotFound).
type cutStore struct {
	store.Store
	mu     sync.Mutex
	floors []uint64
	lift   *store.Lift
	cut    bool
}

func (c *cutStore) PutRevocation(ctx context.Context, r store.Revocation) error {
	c.mu.Lock()
	c.floors = append(c.floors, store.MarkFloor(ctx))
	cut := c.cut
	c.mu.Unlock()
	if cut {
		return fmt.Errorf("%w: the directory store did not answer within 500ms", store.ErrUnavailable)
	}
	return c.Store.PutRevocation(ctx, r)
}

func (c *cutStore) GetLift(context.Context, string, string) (store.Lift, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lift == nil {
		return store.Lift{}, store.ErrNotFound
	}
	return *c.lift, nil
}

// scriptFeed is a marks feed that loads marks at rev 5, then delivers
// events one at a time as the test sends them.
type scriptFeed struct {
	marks  []store.Revocation
	events chan scriptEvent
}

type scriptEvent struct {
	r      store.Revocation
	lifted bool
	rev    uint64
}

func (f *scriptFeed) Revocations(context.Context) (uint64, []store.Revocation, error) {
	return 5, f.marks, nil
}

func (f *scriptFeed) WatchRevocations(ctx context.Context, _ uint64, fn func(store.Revocation, bool, uint64),
	_ func(uint64)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-f.events:
			fn(e.r, e.lifted, e.rev)
		}
	}
}

// follow runs the broker's marks feed over f as port49-broker runs it,
// its tells going to MarkChanged, until the test ends.
func follow(t *testing.T, b *Broker, f *scriptFeed) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.FollowMarks(ctx, f, b.Marks, 5, b.MarkChanged, func(bool) {}, func() error { return nil }, t.Logf)
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// roundTrip is r as the store hands it back: through JSON, its monotonic
// reading gone.
func roundTrip(t *testing.T, r store.Revocation) store.Revocation {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var out store.Revocation
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func waitSaid(t *testing.T, s *saidLines, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if all := s.all(); strings.Contains(all, want) {
			return all
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never said %q; said:\n%s", want, s.all())
	return ""
}

// A revoke whose write fails says it may not have been recorded, that a
// copy already sent can still land and then stand over a lift made
// meanwhile, and to check --list after the heal (L79 k).
func TestARevokeWhoseWriteFailsSaysItMayStillLand(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Proc = "port49-broker"
	f.b.Marks = store.NewMarks()
	f.b.Store = &cutStore{Store: f.st, cut: true}
	_, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice})
	if err == nil || !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	for _, want := range []string{
		"broker: the revocation may not have been recorded: a copy already sent can still land when the directory " +
			"answers again, and then stands everywhere, even over a lift made meanwhile. Until then this " +
			"port49-broker denies what it names, until a lift on this port49-broker or its restart; after the heal " +
			"check `port49 revoke --list` (",
		"stop every port49d (port49-broker serves no device)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not say %q:\n%v", want, err)
		}
	}
}

// A revoke carries this process's floor (Marks.ConfirmedRevision) to its
// put: the store flags the mark against it.
func TestARevokeCarriesItsFeedsFloor(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Marks = store.NewMarks()
	cs := &cutStore{Store: f.st}
	f.b.Store = cs
	follow(t, f.b, &scriptFeed{events: make(chan scriptEvent)})
	deadline := time.Now().Add(5 * time.Second)
	for f.b.Marks.ConfirmedRevision() != 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.floors) != 1 || cs.floors[0] != 5 {
		t.Fatalf("the put's floor: %v, want [5]", cs.floors)
	}
}

// L79 cell k's shape (post-11b, C2): the mark already stands here when this
// broker revokes during a cut, so nothing is Pended or Unrecorded. The feed
// then brings the lift made elsewhere, and the late copy of this broker's
// own write, flagged. The line says the mark landed after the lift, in the
// before-the-lift form, and that it was made here, never "made elsewhere".
// Another process's later mark of the same key is not said as this one's.
func TestTheWritersOwnLateMarkIsSaidAsItsOwnWhenAlreadyHeld(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Proc = "port49-broker"
	said := &saidLines{}
	f.b.Say = said.say
	f.b.Marks = store.NewMarks()
	first := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: f.now.Add(-time.Hour), Origin: "offline uid 0"}
	f.b.Marks.Set(first, true)
	cs := &cutStore{Store: f.st, cut: true}
	f.b.Store = cs
	feed := &scriptFeed{marks: []store.Revocation{first}, events: make(chan scriptEvent)}
	follow(t, f.b, feed)
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice, Origin: "offline uid 0"}); err == nil {
		t.Fatal("the cut revoke succeeded")
	}
	liftAt := f.now.Add(time.Second)
	cs.mu.Lock()
	cs.lift = &store.Lift{At: liftAt, Origin: "offline uid 1000", Revision: 8}
	cs.mu.Unlock()
	late := roundTrip(t, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: f.now,
		Origin: "offline uid 0", LandedAfterLift: true})
	feed.events <- scriptEvent{r: store.Revocation{Kind: late.Kind, Key: late.Key}, lifted: true, rev: 8}
	feed.events <- scriptEvent{r: late, rev: 9}
	all := waitSaid(t, said, "landed after it")
	want := fmt.Sprintf("broker: a revocation of %s made at %s before the lift at %s landed after it: a copy sent "+
		"while its writer was cut off; it stands everywhere; made on this port49-broker, reported unrecorded then",
		alice, f.now.UTC().Format(time.RFC3339), liftAt.UTC().Format(time.RFC3339))
	if !strings.Contains(all, want) || strings.Contains(all, "made elsewhere") {
		t.Fatalf("said:\n%s\nwant a line:\n%s", all, want)
	}
	// Another process's mark of the same key, at its own time, after
	// another lift: not this broker's.
	other := roundTrip(t, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: f.now.Add(2 * time.Second),
		Origin: "offline uid 0", LandedAfterLift: true})
	feed.events <- scriptEvent{r: store.Revocation{Kind: late.Kind, Key: late.Key}, lifted: true, rev: 10}
	feed.events <- scriptEvent{r: other, rev: 11}
	all = waitSaid(t, said, "check with whoever revoked before lifting")
	if strings.Count(all, "made on this port49-broker") != 1 {
		t.Fatalf("another process's mark was said as this broker's:\n%s", all)
	}
}

// The other order (post-11b, C2): no mark stood here, so the revoke Pended
// and was Unrecorded; the feed brings a lift first, which clears both,
// then the late copy. The writer's clause still fires.
func TestTheWritersOwnLateMarkIsSaidAsItsOwnAfterALift(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Proc = "port49-broker"
	said := &saidLines{}
	f.b.Say = said.say
	f.b.Marks = store.NewMarks()
	cs := &cutStore{Store: f.st, cut: true}
	f.b.Store = cs
	feed := &scriptFeed{events: make(chan scriptEvent)}
	follow(t, f.b, feed)
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice, Origin: "offline uid 0"}); err == nil {
		t.Fatal("the cut revoke succeeded")
	}
	feed.events <- scriptEvent{r: store.Revocation{Kind: store.RevocationPrincipal, Key: alice}, lifted: true, rev: 8}
	late := roundTrip(t, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: f.now, Origin: "offline uid 0"})
	feed.events <- scriptEvent{r: late, rev: 9}
	all := waitSaid(t, said, "made on this port49-broker, reported unrecorded then")
	if strings.Contains(all, "made elsewhere") || strings.Contains(all, "landed after") {
		t.Fatalf("said:\n%s", all)
	}
}

// Each form of the flagged line, chosen by the mark's time against the
// lift's (re-review R-I2), and the expired form; none tells anyone to lift
// again. It is said from MarkChanged, on a broker with no listener and
// no runner. An unflagged mark is said no such line.
func TestAFlaggedMarkIsSaidInTheFormItsTimesCall(t *testing.T) {
	liftAt := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	before := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: liftAt.Add(-20 * time.Second),
		Origin: "offline uid 0", LandedAfterLift: true}
	after := before
	after.At, after.Origin = liftAt.Add(2*time.Second), "api user:carol@example.com"
	for _, c := range []struct {
		name string
		mark store.Revocation
		lift *store.Lift
		want string
	}{
		{"before", before, &store.Lift{At: liftAt, Revision: 8},
			"broker: a revocation of user:alice@example.com made at 2026-10-21T02:59:40Z before the lift at " +
				"2026-10-21T03:00:00Z landed after it: a copy sent while its writer was cut off; it stands everywhere"},
		{"after", after, &store.Lift{At: liftAt, Revision: 8},
			"broker: a revocation of user:alice@example.com made at 2026-10-21T03:00:02Z (api user:carol@example.com) " +
				"after the lift at 2026-10-21T03:00:00Z, by a writer whose marks feed had not yet shown the lift; it " +
				"stands everywhere; check with whoever revoked before lifting"},
		{"expired", before, nil,
			"broker: a revocation of user:alice@example.com landed after a lift; the lift's record has expired"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, 8)
			said := &saidLines{}
			f.b.Say, f.b.Marks, f.b.Conns = said.say, store.NewMarks(), nil
			f.b.Store = &cutStore{Store: f.st, lift: c.lift}
			f.b.MarkChanged(store.MarkChange{Revocation: c.mark, Standing: true})
			all := waitSaid(t, said, "broker: ")
			if all != c.want {
				t.Fatalf("said\n%s\nwant\n%s", all, c.want)
			}
			if strings.Contains(all, "lift it again") || strings.Contains(all, "lift again") {
				t.Fatalf("the line invites a lift: %s", all)
			}
		})
	}
	f := newFixture(t, 8)
	said := &saidLines{}
	f.b.Say, f.b.Marks = said.say, store.NewMarks()
	f.b.Store = &cutStore{Store: f.st, lift: &store.Lift{At: liftAt}}
	plain := before
	plain.LandedAfterLift = false
	f.b.MarkChanged(store.MarkChange{Revocation: plain, Standing: true})
	if said.all() != "" {
		t.Fatalf("an unflagged mark was said: %s", said.all())
	}
}

// A revoke the store flagged, made over a lift this process had not yet
// seen, says so in its own report (task 2 review M5).
func TestARevokeTheStoreFlaggedSaysSoInItsReport(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Marks = store.NewMarks()
	f.b.Store = flaggingPuts{f.st}
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice})
	if err != nil {
		t.Fatal(err)
	}
	if text := rep.Text(); !strings.Contains(text, "\nthis revocation landed over a lift of "+alice+" this process's "+
		"marks feed had not yet shown: it stands everywhere, and whoever lifted it may not know; `port49 revoke "+
		"--list` names the lift") {
		t.Fatalf("%s", text)
	}
}

// A revoke that changed nothing, a flagged mark already standing, never
// claims this call landed over a lift: it says the earlier one stands
// flagged (task 2 re-review RR-M1).
func TestARevokeOverAnEarlierFlaggedMarkClaimsNoLanding(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Marks = store.NewMarks()
	earlier := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: f.b.Now().Add(-time.Hour).Round(0),
		Origin: "offline uid 0", LandedAfterLift: true}
	if err := f.st.PutRevocation(context.Background(), earlier); err != nil {
		t.Fatal(err)
	}
	f.b.Marks.Set(earlier, true)
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice})
	if err != nil {
		t.Fatal(err)
	}
	text := rep.Text()
	if strings.Contains(text, "this revocation landed over a lift") || !strings.Contains(text, "\nan earlier "+
		"revocation of "+alice+", flagged landed_after_lift, stands; `port49 revoke --list` names its lift") {
		t.Fatalf("%s", text)
	}
}

// flaggingPuts stores every revocation as the store does one put over a
// lift its writer had not seen.
type flaggingPuts struct{ store.Store }

func (p flaggingPuts) PutRevocation(ctx context.Context, r store.Revocation) error {
	r.LandedAfterLift = true
	return p.Store.PutRevocation(ctx, r)
}

// When the feed's put of a pending mark came before the write's error, the
// writer tells the store's mark, flag and all, never its own unflagged copy
// (task 2 review M5).
func TestTheUnrecordedPathTellsTheStoresFlag(t *testing.T) {
	f := newFixture(t, 8)
	said := &saidLines{}
	f.b.Proc, f.b.Say, f.b.Marks, f.b.Conns = "port49-broker", said.say, store.NewMarks(), nil
	feed := &scriptFeed{events: make(chan scriptEvent)}
	follow(t, f.b, feed)
	liftAt := f.b.Now().Add(time.Minute)
	f.b.Store = &feedFirst{cutStore: cutStore{Store: f.st, lift: &store.Lift{At: liftAt, Revision: 6}}, feed: feed,
		marks: f.b.Marks}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	all := waitSaid(t, said, "landed after it")
	if !strings.Contains(all, "a copy sent while its writer was cut off") ||
		!strings.Contains(all, "made on this port49-broker, reported unrecorded then") {
		t.Fatalf("said:\n%s", all)
	}
	if f.b.Marks.Flagged() != 1 {
		t.Fatalf("flagged %d", f.b.Marks.Flagged())
	}
}

// feedFirst is a store whose revocation write lands flagged and is
// delivered by the marks feed before the write's reply is lost.
type feedFirst struct {
	cutStore
	feed  *scriptFeed
	marks *store.Marks
}

func (s *feedFirst) PutRevocation(ctx context.Context, r store.Revocation) error {
	r.LandedAfterLift = true
	s.feed.events <- scriptEvent{r: r, rev: 9}
	for s.marks.ConfirmedRevision() < 9 {
		time.Sleep(time.Millisecond)
	}
	return fmt.Errorf("%w: the reply was lost", store.ErrUnavailable)
}

// A refused write on a mark this process already holds says it was
// refused and that the mark stands, never "may still land": a refused write
// never lands, and it is not noted as this process's own (task 2 review M2).
func TestARefusedWriteOnAHeldMarkSaysTheMarkStands(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Proc = "port49-broker"
	f.b.Marks = store.NewMarks()
	standing := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: time.Now().Add(-time.Hour)}
	f.b.Marks.Set(standing, true)
	f.b.Store = refusingPuts{f.st}
	_, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice})
	if err == nil || !errors.Is(err, store.ErrRefused) || strings.Contains(err.Error(), "may not have been recorded") ||
		!strings.Contains(err.Error(), "broker: the revocation was refused; the revocation of user:alice@example.com "+
			"this port49-broker already holds stands") {
		t.Fatalf("%v", err)
	}
	if !f.b.Marks.Holds(store.RevocationPrincipal, alice) {
		t.Fatal("the refusal took the standing mark out")
	}
	if f.b.Marks.FailedWrite(store.RevocationPrincipal, alice, f.b.Now()) {
		t.Fatal("a refused write was noted as one that may land")
	}
}

type refusingPuts struct{ store.Store }

func (refusingPuts) PutRevocation(context.Context, store.Revocation) error {
	return fmt.Errorf("%w: etcdserver: permission denied", store.ErrRefused)
}

// A flagged mark a runner put back from its marks copy is said as a
// put-back, never as a copy a cut held back (task 2 review I1): one made
// before the lift re-created a lifted mark, so the line says how to lift
// it again, as sayPutBack does; one made after it was a revoke the store
// had lost, and the line offers no lift.
func TestAPutBackOverALiftIsSaidAsAPutBack(t *testing.T) {
	liftAt := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	before := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: liftAt.Add(-20 * time.Second),
		Origin: store.PutBackOrigin("offline uid 0"), LandedAfterLift: true}
	after := before
	after.At, after.Origin = liftAt.Add(2*time.Second), store.PutBackOrigin("") // the copy keeps no origin
	for _, c := range []struct {
		name, want string
		mark       store.Revocation
		lift       bool
	}{
		{"before", "broker: a revocation of user:alice@example.com made at 2026-10-21T02:59:40Z was put back after " +
			"the lift at 2026-10-21T03:00:00Z by a port49-broker runner from its broker.state_dir/marks.json: its " +
			"watch had not delivered the lift, which it cannot tell from a mark an etcd restore lost; it stands " +
			"everywhere; lift it again with port49 revoke --lift if it was lifted on purpose", before, true},
		{"after", "broker: a revocation of user:alice@example.com made at 2026-10-21T03:00:02Z after the lift at " +
			"2026-10-21T03:00:00Z was put back by a port49-broker runner from its broker.state_dir/marks.json: the " +
			"store had lost it (an etcd restore); it stands everywhere",
			after, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, 8)
			said := &saidLines{}
			f.b.Say, f.b.Marks, f.b.Conns = said.say, store.NewMarks(), nil
			f.b.Store = &cutStore{Store: f.st, lift: &store.Lift{At: liftAt, Revision: 8}}
			f.b.MarkChanged(store.MarkChange{Revocation: c.mark, Standing: true})
			all := waitSaid(t, said, "broker: ")
			if all != c.want {
				t.Fatalf("said\n%s\nwant\n%s", all, c.want)
			}
			if strings.Contains(all, "cut off") || strings.Contains(all, "lift it again") != c.lift {
				t.Fatalf("the line names a cut, or offers a lift where it should not: %s", all)
			}
		})
	}
}

// PutBackOrigin keeps the mark's own origin first, so a CA's mark stays a
// CA's (revokedError), and says a put-back once however often it is put
// back.
func TestPutBackOriginKeepsTheOriginAndSaysItOnce(t *testing.T) {
	once := store.PutBackOrigin("crl corp-ca")
	if !strings.HasPrefix(once, "crl corp-ca") || store.PutBackOrigin(once) != once {
		t.Fatalf("%q, again %q", once, store.PutBackOrigin(once))
	}
	if orig, ok := store.PutBackOf(once); !ok || orig != "crl corp-ca" {
		t.Fatalf("%q %v", orig, ok)
	}
	if _, ok := store.PutBackOf("offline uid 0"); ok {
		t.Fatal("a revoke's own origin read as a put-back")
	}
}

// A slow lift's record never stalls the marks feed: MarkChanged returns
// while the read hangs, and the line is said once it answers (task 2
// review M1).
func TestAFlaggedMarksLineNeverStallsTheFeed(t *testing.T) {
	f := newFixture(t, 8)
	said := &saidLines{}
	f.b.Say, f.b.Marks, f.b.Conns = said.say, store.NewMarks(), nil
	release := make(chan struct{})
	liftAt := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	f.b.Store = slowLift{Store: f.st, release: release, lift: store.Lift{At: liftAt, Revision: 8}}
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		f.b.MarkChanged(store.MarkChange{Revocation: store.Revocation{Kind: store.RevocationPrincipal, Key: alice,
			At: liftAt.Add(-20 * time.Second), LandedAfterLift: true}, Standing: true})
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("MarkChanged waited on the lift's record, stalling the marks feed")
	}
	if all := said.all(); all != "" {
		t.Fatalf("said before the record answered: %s", all)
	}
	close(release)
	waitSaid(t, said, "a copy sent while its writer was cut off")
}

type slowLift struct {
	store.Store
	release chan struct{}
	lift    store.Lift
}

func (s slowLift) GetLift(ctx context.Context, _, _ string) (store.Lift, error) {
	select {
	case <-s.release:
		return s.lift, nil
	case <-ctx.Done():
		return store.Lift{}, ctx.Err()
	}
}

// A lift's record that cannot be read is said so, with the mark: never a
// form the record would have chosen.
func TestAFlaggedMarkWhoseLiftCannotBeReadIsSaidSo(t *testing.T) {
	f := newFixture(t, 8)
	said := &saidLines{}
	f.b.Say, f.b.Marks = said.say, store.NewMarks()
	f.b.Store = liftUnreadable{f.st}
	f.b.MarkChanged(store.MarkChange{Revocation: store.Revocation{Kind: store.RevocationPrincipal, Key: alice,
		At: time.Now(), LandedAfterLift: true}, Standing: true})
	if all := waitSaid(t, said, "broker: "); !strings.Contains(all, "landed after a lift; the lift's record could not be read (") ||
		!strings.Contains(all, "port49 revoke --list") {
		t.Fatalf("said: %s", all)
	}
}

type liftUnreadable struct{ store.Store }

func (liftUnreadable) GetLift(context.Context, string, string) (store.Lift, error) {
	return store.Lift{}, fmt.Errorf("%w: no quorum", store.ErrUnavailable)
}

// The list names a flagged mark's lift, its time and revision from the
// lift's record, or says the record has expired (re-review R-I2).
func TestRevocationsTextNamesAFlaggedMarksLift(t *testing.T) {
	at := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	rs := []store.Revocation{
		{Kind: store.RevocationPrincipal, Key: alice, At: at, Origin: "offline uid 0", LandedAfterLift: true},
		{Kind: store.RevocationPrincipal, Key: "user:bob@example.com", At: at, Origin: "offline uid 0",
			LandedAfterLift: true},
		{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: at, Origin: "offline uid 0"},
	}
	text := RevocationsText(rs, func(kind, key string) (store.Lift, error) {
		switch key {
		case alice:
			return store.Lift{At: at.Add(-time.Minute), Revision: 42}, nil
		case "user:carol@example.com":
			t.Errorf("an unflagged mark's lift was read")
		}
		return store.Lift{}, store.ErrNotFound
	})
	want := "principal user:alice@example.com since 2026-10-21T03:00:00Z (offline uid 0); landed after the lift " +
		"at 2026-10-21T02:59:00Z (revision 42)" +
		"\nprincipal user:bob@example.com since 2026-10-21T03:00:00Z (offline uid 0); landed after a lift; " +
		"the lift's record has expired" +
		"\nprincipal user:carol@example.com since 2026-10-21T03:00:00Z (offline uid 0)"
	if text != want {
		t.Fatalf("got\n%s\nwant\n%s", text, want)
	}
	text = RevocationsText(rs[:1], func(string, string) (store.Lift, error) {
		return store.Lift{}, fmt.Errorf("%w: no quorum", store.ErrUnavailable)
	})
	if !strings.HasSuffix(text, "; landed after a lift; the lift's record could not be read (store: unavailable: no quorum)") {
		t.Fatal(text)
	}
}
