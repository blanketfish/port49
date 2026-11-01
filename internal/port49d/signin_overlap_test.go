package port49d

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// fakeEnr is an enrollment handle that counts the marks put through it and
// the times it is closed.
type fakeEnr struct {
	store.Enrollments
	puts, closed atomic.Int32
}

func (f *fakeEnr) PutEnrollmentMark(context.Context, store.EnrollmentMark) error {
	f.puts.Add(1)
	return nil
}

func (f *fakeEnr) Close() error { f.closed.Add(1); return nil }

// An open that was slow, started before another caller opened the file and
// wrote through the newer handle, must not replace that handle when it
// finishes: its read is older than the write, and the next write through it
// would put the old mark back on disk. The loser is closed.
func TestAStaleOpenNeverReplacesANewerHandle(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	started := make(chan int32, 4)
	release := make(chan struct{})
	lost := &reopenable{Enrollments: &fakeEnr{}, lost: func() string { return "unreadable" }}
	a, b := &fakeEnr{}, &fakeEnr{}
	well := func(f *fakeEnr) *reopenable { return &reopenable{Enrollments: f, lost: func() string { return "" }} }
	l := &lateEnrollments{now: func() time.Time { return now }}
	l.open = func() (store.Enrollments, error) {
		n := calls.Add(1)
		switch n {
		case 1:
			return lost, nil
		case 2: // the sign-in's retry: slow
			started <- n
			<-release
			return well(a), nil
		}
		return well(b), nil // the operator's forced open
	}
	if in, err := l.get(); err != nil || in != store.Enrollments(lost) {
		t.Fatalf("setup: %v %v", in, err)
	}
	now = now.Add(enrollmentRetryEvery + time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = l.get() }()
	<-started

	l.Refresh() // the operator's --all: opens the fixed file afresh
	if err := l.PutEnrollmentMark(context.Background(), store.EnrollmentMark{}); err != nil || b.puts.Load() != 1 {
		t.Fatalf("the operator's write did not go through the newer handle: %v", err)
	}
	close(release)
	wg.Wait()

	l.mu.Lock()
	got := l.inner
	l.mu.Unlock()
	if r, ok := got.(*reopenable); !ok || r.Enrollments != store.Enrollments(b) {
		t.Fatal("the stale open replaced the newer handle")
	}
	if a.closed.Load() != 1 || b.closed.Load() != 0 {
		t.Fatalf("the loser was closed %d times, the winner %d", a.closed.Load(), b.closed.Load())
	}
}

// Two opens that overlap with no handle yet leave exactly one handle, and the
// loser is closed, not leaked (an own etcd's client keeps reconnecting).
func TestOverlappingOpensLeaveOneHandleAndCloseTheLoser(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var made [2]*fakeEnr
	l := &lateEnrollments{now: time.Now}
	l.open = func() (store.Enrollments, error) {
		n := calls.Add(1)
		f := &fakeEnr{}
		made[n-1] = f
		started <- struct{}{}
		<-release
		return f, nil
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = l.get() }()
	<-started
	go func() { defer wg.Done(); l.Refresh() }()
	<-started
	close(release)
	wg.Wait()

	l.mu.Lock()
	got := l.inner
	l.mu.Unlock()
	win, lose := made[0], made[1]
	if got != store.Enrollments(win) {
		win, lose = lose, win
	}
	if got != store.Enrollments(win) || win.closed.Load() != 0 || lose.closed.Load() != 1 {
		t.Fatalf("winner closed %d times, loser %d", win.closed.Load(), lose.closed.Load())
	}
}
