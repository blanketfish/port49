package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
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
// mirror_behind, holds up no other sync, and ends with its context.
func TestAHungMirrorShowsAndHoldsUpNoSync(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 0 {
		t.Fatal("the fixture's mirror is not level")
	}
	entered := hangMirror(t, rig.s, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan Result, 1)
	go func() { first <- rig.s.Sync(ctx, "schedule") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sync never read the mirror")
	}
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 1 {
		t.Fatal("port49_inventory_mirror_behind does not show the hung read")
	}
	returnsWithin(t, 5*time.Second, "a second sync beside the hung mirror", func() {
		if res := rig.s.Sync(context.Background(), "api"); res.Outcome != OutcomeUnchanged {
			t.Errorf("%+v", res)
		}
	})
	if !strings.Contains(rig.out.String(), "has not answered a read or write started ") {
		t.Fatalf("not said: %s", rig.out)
	}
	cancel()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the sync waiting on the mirror did not end with its context")
	}
}
