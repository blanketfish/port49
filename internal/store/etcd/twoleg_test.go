package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// scripted is a legSource the test drives: it hands out one channel per
// opening and records where each opened from.
type scripted struct {
	mu      sync.Mutex
	chans   map[[2]int]chan clientv3.WatchResponse
	from    map[[2]int]int64
	opened  chan [2]int
	probeOK atomic.Bool
	asked   atomic.Int64
}

func newScripted() *scripted {
	s := &scripted{chans: map[[2]int]chan clientv3.WatchResponse{}, from: map[[2]int]int64{}, opened: make(chan [2]int, 32)}
	s.probeOK.Store(true)
	return s
}

func (s *scripted) open(ctx context.Context, i, gen int, from int64) (<-chan clientv3.WatchResponse, context.CancelFunc) {
	s.mu.Lock()
	ch := make(chan clientv3.WatchResponse, 16)
	s.chans[[2]int{i, gen}], s.from[[2]int{i, gen}] = ch, from
	s.mu.Unlock()
	s.opened <- [2]int{i, gen}
	return ch, func() {}
}
func (s *scripted) progress(i int) error { s.asked.Add(1); return nil }
func (s *scripted) probe(context.Context) error {
	if s.probeOK.Load() {
		return nil
	}
	return context.DeadlineExceeded
}
func (s *scripted) send(i, gen int, r clientv3.WatchResponse) {
	s.mu.Lock()
	ch := s.chans[[2]int{i, gen}]
	s.mu.Unlock()
	ch <- r
}
func (s *scripted) end(i, gen int) {
	s.mu.Lock()
	ch := s.chans[[2]int{i, gen}]
	s.mu.Unlock()
	close(ch)
}

func evs(revs ...int64) clientv3.WatchResponse {
	r := clientv3.WatchResponse{Header: pb.ResponseHeader{Revision: revs[len(revs)-1]}}
	for _, v := range revs {
		r.Events = append(r.Events, &clientv3.Event{Type: clientv3.EventTypePut, Kv: &mvccpb.KeyValue{Key: []byte("k"), ModRevision: v}})
	}
	return r
}

func progressAt(rev int64) clientv3.WatchResponse {
	return clientv3.WatchResponse{Header: pb.ResponseHeader{Revision: rev}}
}

func runLegs(t *testing.T, src *scripted, after uint64) (<-chan clientv3.WatchResponse, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := watchLegs(ctx, src, after, nil, func(int64) {}, func(string, ...any) {})
	for i := 0; i < 2; i++ {
		<-src.opened
	}
	return out, cancel
}

// next is the revisions of the next response, or nil after wait.
func next(out <-chan clientv3.WatchResponse, wait time.Duration) ([]int64, bool, bool) {
	select {
	case r, ok := <-out:
		if !ok {
			return nil, false, true
		}
		if r.IsProgressNotify() {
			return []int64{-r.Header.Revision}, true, false
		}
		var revs []int64
		for _, e := range r.Events {
			revs = append(revs, e.Kv.ModRevision)
		}
		return revs, true, false
	case <-time.After(wait):
		return nil, false, false
	}
}

// Both legs bring a revision: it is delivered once.
func TestAnEventBothLegsBringIsDeliveredOnce(t *testing.T) {
	src := newScripted()
	out, _ := runLegs(t, src, 5)
	src.send(0, 1, evs(10))
	src.send(1, 1, evs(10))
	if revs, ok, _ := next(out, time.Second); !ok || len(revs) != 1 || revs[0] != 10 {
		t.Fatalf("first delivery %v %v", revs, ok)
	}
	if revs, ok, _ := next(out, 300*time.Millisecond); ok {
		t.Fatalf("revision 10 was delivered twice: %v", revs)
	}
	src.send(1, 1, evs(11))
	src.send(0, 1, evs(11))
	if revs, ok, _ := next(out, time.Second); !ok || revs[0] != 11 {
		t.Fatalf("second delivery %v %v", revs, ok)
	}
	if revs, ok, _ := next(out, 300*time.Millisecond); ok {
		t.Fatalf("revision 11 was delivered twice: %v", revs)
	}
}

// One leg is behind and delivers late: what the other delivered is dropped,
// a batch partly delivered gives only its new events, and nothing goes back.
func TestALateLegAppliesNothingTwiceAndGoesNowhereBack(t *testing.T) {
	src := newScripted()
	out, _ := runLegs(t, src, 5)
	src.send(0, 1, evs(10))
	src.send(0, 1, evs(11))
	src.send(0, 1, evs(12))
	var got []int64
	for i := 0; i < 3; i++ {
		revs, ok, _ := next(out, time.Second)
		if !ok {
			t.Fatal("a delivery is missing")
		}
		got = append(got, revs...)
	}
	src.send(1, 1, evs(10))
	src.send(1, 1, evs(11, 12, 13)) // 13 is new
	src.send(1, 1, evs(12))
	revs, ok, _ := next(out, time.Second)
	if !ok || len(revs) != 1 || revs[0] != 13 {
		t.Fatalf("the late leg's batch gave %v %v, want only 13", revs, ok)
	}
	got = append(got, revs...)
	if revs, ok, _ := next(out, 300*time.Millisecond); ok {
		t.Fatalf("a stale response was delivered: %v", revs)
	}
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Fatalf("revisions went back or repeated: %v", got)
		}
	}
}

// A progress notification at or below what is delivered is dropped; one above is passed on.
func TestProgressOnlyMovesForward(t *testing.T) {
	src := newScripted()
	out, _ := runLegs(t, src, 5)
	src.send(0, 1, evs(10))
	next(out, time.Second)
	src.send(1, 1, progressAt(9))
	src.send(1, 1, progressAt(10))
	if revs, ok, _ := next(out, 300*time.Millisecond); ok {
		t.Fatalf("a progress notification not above 10 was passed on: %v", revs)
	}
	src.send(1, 1, progressAt(15))
	if revs, ok, _ := next(out, time.Second); !ok || revs[0] != -15 {
		t.Fatalf("progress at 15 was not passed on: %v %v", revs, ok)
	}
	src.send(0, 1, evs(15)) // an event at a revision a progress notification covered
	if revs, ok, _ := next(out, 300*time.Millisecond); ok {
		t.Fatalf("an event the progress notification covered was delivered: %v", revs)
	}
}

// One leg fails alone: the watch does not return, the leg is opened again from
// where the watch is, and the watch ends only when both are down.
func TestALegFailingAloneLeavesTheWatchRunning(t *testing.T) {
	old := legRetry
	legRetry = 100 * time.Millisecond
	defer func() { legRetry = old }()
	src := newScripted()
	out, _ := runLegs(t, src, 5)
	src.end(0, 1)
	src.send(1, 1, evs(10))
	if revs, ok, closed := next(out, time.Second); !ok || closed || revs[0] != 10 {
		t.Fatalf("with one leg down the other's change was not delivered: %v %v %v", revs, ok, closed)
	}
	select {
	case o := <-src.opened:
		if o != [2]int{0, 2} {
			t.Fatalf("opened %v, want leg 0 again", o)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the failed leg was not opened again")
	}
	if f := src.from[[2]int{0, 2}]; f != 11 {
		t.Fatalf("the leg reopened from %d, want 11 (after the delivered 10)", f)
	}
	src.send(0, 2, evs(11))
	if revs, ok, _ := next(out, time.Second); !ok || revs[0] != 11 {
		t.Fatalf("the reopened leg's change: %v %v", revs, ok)
	}
	// Both down at once: the watch ends.
	r := clientv3.WatchResponse{Canceled: true}
	src.send(0, 2, r)
	src.send(1, 1, r)
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-out:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("the watch did not end with both legs down")
		}
	}
}

// A compacted leg ends the watch with its response, so the caller rescans.
func TestACompactedLegEndsTheWatch(t *testing.T) {
	src := newScripted()
	out, _ := runLegs(t, src, 5)
	src.send(1, 1, clientv3.WatchResponse{CompactRevision: 40})
	r, ok := <-out
	if !ok || r.CompactRevision != 40 {
		t.Fatalf("got %+v %v", r, ok)
	}
	if _, ok := <-out; ok {
		t.Fatal("the watch went on after a compaction")
	}
}

// A leg quiet past feedStall while the store answers is opened again; with the
// store silent it is left alone.
func TestAQuietLegIsOpenedAgainOnlyWhileTheStoreAnswers(t *testing.T) {
	oi, os := feedIdle, feedStall
	feedIdle, feedStall = 40*time.Millisecond, 120*time.Millisecond
	defer func() { feedIdle, feedStall = oi, os }()
	src := newScripted()
	src.probeOK.Store(false)
	_, _ = runLegs(t, src, 5)
	select {
	case o := <-src.opened:
		t.Fatalf("a leg was opened again (%v) with the store silent", o)
	case <-time.After(600 * time.Millisecond):
	}
	if src.asked.Load() == 0 {
		t.Fatal("the quiet legs were not asked for their progress")
	}
	src.probeOK.Store(true)
	select {
	case <-src.opened:
	case <-time.After(2 * time.Second):
		t.Fatal("a quiet leg was not opened again with the store answering")
	}
}

// The legs never ask etcd to split a response; the check that says so sees a
// fragmenting op when there is one, so a renamed flag cannot make it pass.
func TestTheLegsAreNotFragmented(t *testing.T) {
	for _, keysOnly := range []bool{false, true} {
		if !notFragmented(legOpts(7, keysOnly)) {
			t.Fatalf("legOpts(keysOnly %v) fragments", keysOnly)
		}
	}
	if notFragmented(append(legOpts(7, false), clientv3.WithFragment())) {
		t.Fatal("notFragmented does not see WithFragment (clientv3 renamed its flag?)")
	}
}
