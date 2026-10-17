package placement

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// R26: a logout is written to the directory and read from the set; with the
// directory cut it is accepted, kept pending in the session store, and
// refused here at once.
func TestALogoutIsTheDirectorysAndReadFromTheSet(t *testing.T) {
	ctx := context.Background()
	reach := true
	sess, dir := memory.New(clock), memory.New(clock)
	set := store.NewLogoutSet(clock)
	s := Wrap(Config{Session: sess, Directory: dir, Marks: store.NewMarks(), Logouts: set, LogoutDir: dir,
		Reachable: func() bool { return reach }, CallTimeout: time.Second, BulkTimeout: time.Second})
	l := store.Logout{Key: store.SidKey("https://idp", "s1"), At: t0, Origin: "logout"}
	if err := s.PutLogout(ctx, l, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.GetLogout(ctx, l.Key); err != nil {
		t.Fatalf("the directory lacks the logout: %v", err)
	}
	if _, err := sess.GetLogout(ctx, l.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session store holds a logout: %v", err)
	}
	reach = false
	if got, err := s.GetLogout(ctx, l.Key); err != nil || !got.At.Equal(t0) {
		t.Fatalf("the set's answer with the directory cut: %+v %v", got, err)
	}
	other := store.Logout{Key: store.SidKey("https://idp", "s2"), At: t0}
	if err := s.PutLogout(ctx, other, time.Hour); err != nil {
		t.Fatalf("a logout ingested during the cut: %v, want accepted (pending)", err)
	}
	if _, err := s.GetLogout(ctx, other.Key); err != nil {
		t.Fatalf("a pending logout is not refused here at once: %v", err)
	}
	if _, err := sess.GetLogout(ctx, other.Key); err != nil {
		t.Fatalf("the pending logout is not in the session store: %v", err)
	}
	if _, err := dir.GetLogout(ctx, other.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the cut directory took the logout: %v", err)
	}
}

// pendingFake is a session store's pending logouts, over a memory store's
// records (which lists none itself).
type pendingFake struct {
	st   *memory.Store
	keys []string
}

func (p *pendingFake) Logouts(ctx context.Context) (uint64, []store.LogoutEntry, error) {
	var out []store.LogoutEntry
	for _, k := range p.keys {
		if l, err := p.st.GetLogout(ctx, k); err == nil {
			out = append(out, store.LogoutEntry{Logout: l, Until: time.Now().Add(time.Hour)})
		}
	}
	return 1, out, nil
}

func (p *pendingFake) DeleteLogout(_ context.Context, key string) error {
	p.keys = slices.DeleteFunc(p.keys, func(k string) bool { return k == key })
	return nil
}

// The amendment's whole path: region a cut, a logout accepted there and
// pending; the heal; ForwardPending writes it to the directory and clears it;
// region b, whose set the feed then brings it to, refuses the session.
func TestALogoutDuringACutIsForwardedOnTheHealAndRefusedElsewhere(t *testing.T) {
	ctx := context.Background()
	reach := false
	sa, sb, dir := memory.New(clock), memory.New(clock), memory.New(clock)
	setA, setB := store.NewLogoutSet(clock), store.NewLogoutSet(clock)
	a := Wrap(Config{Session: sa, Directory: dir, Marks: store.NewMarks(), Logouts: setA, LogoutDir: dir,
		Reachable: func() bool { return reach }, CallTimeout: time.Second, BulkTimeout: time.Second})
	b := Wrap(Config{Session: sb, Directory: dir, Marks: store.NewMarks(), Logouts: setB, LogoutDir: dir,
		CallTimeout: time.Second, BulkTimeout: time.Second})
	l := store.Logout{Key: store.SidKey("https://idp", "s1"), At: t0, Origin: "backchannel_logout https://idp"}
	if err := a.PutLogout(ctx, l, time.Hour); err != nil {
		t.Fatal(err)
	}
	pending := &pendingFake{st: sa, keys: []string{l.Key}}
	if n, left, err := ForwardPending(ctx, a, pending); err == nil || n != 0 || left != 1 {
		t.Fatalf("forwarded during the cut: %d, %d left, %v", n, left, err)
	}
	if _, err := b.GetLogout(ctx, l.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("region b saw the logout during the cut: %v", err)
	}
	reach = true
	if n, left, err := ForwardPending(ctx, a, pending); err != nil || n != 1 || left != 0 {
		t.Fatalf("on the heal: forwarded %d, %d left, %v", n, left, err)
	}
	got, err := dir.GetLogout(ctx, l.Key)
	if err != nil {
		t.Fatalf("the directory lacks the forwarded logout: %v", err)
	}
	setB.Put(store.LogoutEntry{Logout: got, Until: time.Now().Add(time.Hour)}) // what b's FollowLogouts does
	if _, err := b.GetLogout(ctx, l.Key); err != nil {
		t.Fatalf("region b does not refuse the session after the heal: %v", err)
	}
	if len(pending.keys) != 0 {
		t.Fatalf("the forwarded logout is still pending: %v", pending.keys)
	}
}

// A forward is exactly once: a second pass finds nothing pending, and the
// directory's record keeps the logout's own time.
func TestAForwardedLogoutIsNotForwardedAgain(t *testing.T) {
	ctx := context.Background()
	reach := false
	sa, dir := memory.New(clock), memory.New(clock)
	set := store.NewLogoutSet(clock)
	a := Wrap(Config{Session: sa, Directory: dir, Marks: store.NewMarks(), Logouts: set, LogoutDir: dir,
		Reachable: func() bool { return reach }, CallTimeout: time.Second, BulkTimeout: time.Second})
	l := store.Logout{Key: store.SidKey("https://idp", "s1"), At: t0, Origin: "backchannel_logout https://idp"}
	if err := a.PutLogout(ctx, l, time.Hour); err != nil {
		t.Fatal(err)
	}
	pending := &pendingFake{st: sa, keys: []string{l.Key}}
	reach = true
	if n, _, err := ForwardPending(ctx, a, pending); err != nil || n != 1 {
		t.Fatalf("first pass: %d %v", n, err)
	}
	if n, left, err := ForwardPending(ctx, a, pending); err != nil || n != 0 || left != 0 {
		t.Fatalf("second pass forwarded %d, %d left, %v", n, left, err)
	}
	if got, err := dir.GetLogout(ctx, l.Key); err != nil || !got.At.Equal(t0) || got.Origin != l.Origin {
		t.Fatalf("the directory's record: %+v %v", got, err)
	}
	if _, err := a.GetLogout(ctx, l.Key); err != nil {
		t.Fatalf("this region stopped refusing after the forward: %v", err)
	}
}
