package inventory

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/fence"
)

// hangMirror makes every read of s's mirror_dir block until the test ends,
// and then fail, and says on entered when one has begun; s waits deadline
// for each.
func hangMirror(t *testing.T, s *Syncer, deadline time.Duration) (entered <-chan struct{}) {
	t.Helper()
	in := make(chan struct{}, 16)
	hang := make(chan struct{})
	s.State.readMirror = func(string, int64, string) ([]byte, error) {
		in <- struct{}{}
		<-hang
		return nil, errors.New("released at the end of the test")
	}
	s.mirrorDeadline = deadline
	t.Cleanup(func() { close(hang) })
	return in
}

// returnsWithin fails the test unless f returns inside d.
func returnsWithin(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return in %s", what, d)
	}
}

// Final review I3: at start, a mirror that hangs beside a good state_dir is
// passed over at its deadline, said, and shows as mirror_behind.
func TestAHungMirrorAtRestoreBesideAGoodStateIsPassedOver(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.out.Reset()
	again := rig.syncer(rig.s.Key)
	hangMirror(t, again, 50*time.Millisecond)
	var err error
	returnsWithin(t, 5*time.Second, "Restore", func() { err = again.Restore(context.Background()) })
	if err != nil || again.Current() == nil || again.Current().Doc.Sequence != 1 {
		t.Fatalf("%v %v", again.Current(), err)
	}
	if !strings.Contains(rig.out.String(), "mirror_dir "+again.State.MirrorDir+" did not answer in 50ms") {
		t.Fatalf("not said: %s", rig.out)
	}
	if testutil.ToFloat64(again.Metrics.MirrorBehind) != 1 {
		t.Fatal("port49_inventory_mirror_behind is not 1 with the mirror hung")
	}
}

// Final review I3: with state_dir empty, a mirror that hangs may hold the
// bundle every port49d holds, so the start fails, saying so, rather than
// starting the sequence again below it.
func TestAHungMirrorWithAnEmptyStateStopsTheStart(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	hangMirror(t, rig.s, 50*time.Millisecond)
	var err error
	returnsWithin(t, 5*time.Second, "Restore", func() { err = rig.s.Restore(context.Background()) })
	if err == nil || !strings.Contains(err.Error(), "did not answer in 50ms") ||
		!strings.Contains(err.Error(), "state_dir "+rig.s.State.Dir+" holds no bundle") {
		t.Fatalf("%v", err)
	}
}

// Final review I3: a Restore waiting on a hung mirror ends with its context,
// as a SIGTERM ends run's.
func TestARestoreWaitingOnAHungMirrorEndsWithItsContext(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	again := rig.syncer(rig.s.Key)
	entered := hangMirror(t, again, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() { errs <- again.Restore(ctx) }()
	<-entered
	cancel()
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("a cancelled Restore returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Restore did not end with its context")
	}
}

// Final review I3: a sync whose mirror write hangs shows it at once as
// mirror_behind, passes it over at the deadline, and holds up no sync after
// it: the read abandoned, the next pass fails at once, said.
func TestAHungMirrorShowsAndHoldsUpNoSync(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 0 {
		t.Fatal("the fixture's mirror is not level")
	}
	entered := hangMirror(t, rig.s, 200*time.Millisecond)
	first := make(chan Result, 1)
	go func() { first <- rig.s.Sync(context.Background(), "schedule") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sync never read the mirror")
	}
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 1 {
		t.Fatal("port49_inventory_mirror_behind does not show the hung read")
	}
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the sync waiting on the mirror did not pass it over at its deadline")
	}
	if !strings.Contains(rig.out.String(), "did not answer in 200ms") {
		t.Fatalf("not said: %s", rig.out)
	}
	returnsWithin(t, 100*time.Millisecond, "a sync after the mirror was abandoned", func() {
		if res := rig.s.Sync(context.Background(), "api"); res.Outcome != OutcomeUnchanged {
			t.Errorf("%+v", res)
		}
	})
	if !strings.Contains(rig.out.String(), "has not answered a read or write started earlier") {
		t.Fatalf("not said: %s", rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 1 {
		t.Fatal("port49_inventory_mirror_behind is not 1 with the mirror hung")
	}
}

// A sync waiting on the mirror — its own read, or another's still inside its
// deadline — ends with its context, as a SIGTERM ends run's.
func TestASyncWaitingOnAHungMirrorEndsWithItsContext(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	entered := hangMirror(t, rig.s, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	first, second := make(chan Result, 1), make(chan Result, 1)
	go func() { first <- rig.s.Sync(ctx, "schedule") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sync never read the mirror")
	}
	go func() { second <- rig.s.Sync(ctx, "api") }()
	cancel()
	for _, c := range []chan Result{first, second} {
		select {
		case <-c:
		case <-time.After(5 * time.Second):
			t.Fatal("a sync waiting on the mirror did not end with its context")
		}
	}
}

// A fresh start reads an empty mirror: nothing is published for it to be
// behind, so mirror_behind, set before the read, is 0 again.
func TestAFreshStartIsNotMirrorBehind(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	if err := rig.s.Restore(context.Background()); err != nil || rig.s.Current() != nil {
		t.Fatalf("%v %v", rig.s.Current(), err)
	}
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 0 {
		t.Fatal("port49_inventory_mirror_behind is 1 with nothing published")
	}
}

// Fix-wave re-review N1: two mirror passes that overlap on a mount that is
// slow but healthy — an API sync landing during the scheduled sync's mirror
// write — are not a hang: the second waits for the first, within its own
// deadline, and nothing is said, counted or left behind.
func TestOverlappingMirrorPassesOnASlowMirrorAreNotAHang(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.out.Reset()
	rig.s.State.readMirror = func(path string, max int64, what string) ([]byte, error) {
		time.Sleep(100 * time.Millisecond)
		return fence.ReadSigned(path, max, what)
	}
	rig.s.mirrorDeadline = 5 * time.Second
	failures := testutil.ToFloat64(rig.s.Metrics.MirrorFailures)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rig.s.mirror(context.Background()) }()
	}
	wg.Wait()
	if strings.Contains(rig.out.String(), "mirror_dir") {
		t.Errorf("a slow, healthy mirror was said: %s", rig.out)
	}
	if n := testutil.ToFloat64(rig.s.Metrics.MirrorFailures) - failures; n != 0 {
		t.Errorf("mirror_write_failures_total rose by %v", n)
	}
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 0 {
		t.Error("port49_inventory_mirror_behind is 1 with the mirror level")
	}
}
