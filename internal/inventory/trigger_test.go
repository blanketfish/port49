package inventory

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fires struct {
	mu sync.Mutex
	at []time.Time
}

func (f *fires) fire(context.Context, string) {
	f.mu.Lock()
	f.at = append(f.at, time.Now())
	f.mu.Unlock()
}
func (f *fires) n() int              { f.mu.Lock(); defer f.mu.Unlock(); return len(f.at) }
func (f *fires) get(i int) time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.at[i] }

func runDebouncer(t *testing.T, d *Debouncer) func() {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.Run(ctx, &wg)
	return func() { cancel(); wg.Wait() }
}

// Decision 31: a burst is one sync.
func TestABurstOfDeliveriesIsOneSync(t *testing.T) {
	var f fires
	d := NewDebouncer([]string{"nb"}, 50*time.Millisecond, time.Hour, f.fire)
	stop := runDebouncer(t, d)
	for i := 0; i < 5; i++ {
		d.Notify("nb")
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	stop()
	if f.n() != 1 {
		t.Fatalf("%d syncs", f.n())
	}
}

// Decision 31: a flood costs one sync per gap.
func TestAFloodIsOneSyncPerGap(t *testing.T) {
	var f fires
	d := NewDebouncer([]string{"nb"}, 5*time.Millisecond, 100*time.Millisecond, f.fire)
	stop := runDebouncer(t, d)
	for end := time.Now().Add(450 * time.Millisecond); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		d.Notify("nb")
	}
	stop()
	if f.n() < 2 || f.n() > 6 {
		t.Fatalf("%d syncs in 450ms with a 100ms gap", f.n())
	}
	for i := 1; i < len(f.at); i++ {
		if gap := f.at[i].Sub(f.at[i-1]); gap < 90*time.Millisecond {
			t.Fatalf("syncs %s apart", gap)
		}
	}
}

// A delivery during a sync brings exactly one more after it: the change it
// announces may have come after the sync read the source.
func TestADeliveryDuringASyncBringsOneMore(t *testing.T) {
	release, started := make(chan struct{}), make(chan struct{}, 4)
	var f fires
	d := NewDebouncer([]string{"nb"}, time.Millisecond, time.Millisecond, func(ctx context.Context, s string) {
		f.fire(ctx, s)
		started <- struct{}{}
		<-release
	})
	stop := runDebouncer(t, d)
	d.Notify("nb")
	<-started
	d.Notify("nb")
	d.Notify("nb")
	d.Notify("nb")
	release <- struct{}{}
	<-started
	release <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	stop()
	if f.n() != 2 {
		t.Fatalf("%d syncs", f.n())
	}
}

// Decision 31: a delivery inside the gap, then silence, is one more sync, no
// sooner than gap after the last began: a change is never lost to the window.
func TestADeliveryInsideTheGapIsSyncedAfterIt(t *testing.T) {
	var f fires
	fired := make(chan struct{}, 4)
	d := NewDebouncer([]string{"nb"}, time.Millisecond, 200*time.Millisecond, func(ctx context.Context, s string) {
		f.fire(ctx, s)
		fired <- struct{}{}
	})
	stop := runDebouncer(t, d)
	defer stop()
	d.Notify("nb")
	<-fired
	time.Sleep(20 * time.Millisecond)
	d.Notify("nb")
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("a delivery inside the gap was lost")
	}
	if g := f.get(1).Sub(f.get(0)); g < 200*time.Millisecond {
		t.Fatalf("second sync %v after the first", g)
	}
	select {
	case <-fired:
		t.Fatal("a third sync")
	case <-time.After(400 * time.Millisecond):
	}
}

func TestAnUnknownSourceIsIgnored(t *testing.T) {
	var f fires
	d := NewDebouncer([]string{"nb"}, time.Millisecond, time.Millisecond, f.fire)
	stop := runDebouncer(t, d)
	d.Notify("other")
	time.Sleep(20 * time.Millisecond)
	stop()
	if f.n() != 0 {
		t.Fatalf("%d syncs", f.n())
	}
}

// A sync pending when ctx ends is dropped, not fired, and Run's goroutines
// are joined at once.
func TestAPendingSyncEndsWithCtx(t *testing.T) {
	var f fires
	d := NewDebouncer([]string{"nb", "nautobot"}, time.Hour, time.Hour, f.fire)
	stop := runDebouncer(t, d)
	d.Notify("nb")
	d.Notify("nautobot")
	time.Sleep(10 * time.Millisecond)
	joined := make(chan struct{})
	go func() { stop(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("a pending sync held the debouncer past its ctx")
	}
	if f.n() != 0 {
		t.Fatalf("%d syncs", f.n())
	}
}
