package port49d

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// sleepsOf swaps the retry loops' sleep for one that records the wait and passes at once, and fixes the
// jitter at its middle (factor 1). After n sleeps it cancels the context the loop runs on and reports the
// wait ended by it, so a loop that never succeeds ends.
func sleepsOf(t *testing.T, n int, cancel context.CancelFunc) func() []time.Duration {
	t.Helper()
	var mu sync.Mutex
	var got []time.Duration
	was, wasRnd := retrySleep, retryRnd
	t.Cleanup(func() { retrySleep, retryRnd = was, wasRnd })
	retryRnd = func() float64 { return 0.5 }
	retrySleep = func(_ context.Context, d time.Duration) bool {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, d)
		if len(got) >= n {
			cancel()
			return false
		}
		return true
	}
	return func() []time.Duration { mu.Lock(); defer mu.Unlock(); return append([]time.Duration(nil), got...) }
}

// onTheStoreSchedule is the first ten waits about a second and the eleventh about two: the schedule of
// the wait for the store (storeWaitAfter), not a flat 5s.
func onTheStoreSchedule(t *testing.T, waits []time.Duration) {
	t.Helper()
	if len(waits) < 11 {
		t.Fatalf("only %d waits: %v", len(waits), waits)
	}
	for i := 0; i < 10; i++ {
		if waits[i] != time.Second {
			t.Fatalf("wait %d is %v, want 1s: %v", i+1, waits[i], waits)
		}
	}
	if waits[10] != 2*time.Second {
		t.Fatalf("the 11th wait is %v, want 2s: %v", waits[10], waits)
	}
}

func TestTheBrokersStartRetriesOnTheStoreSchedule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := sleepsOf(t, 12, cancel)
	var out bytes.Buffer
	err := startRetry(ctx, &out, func() error { return fmt.Errorf("%w: no quorum", store.ErrUnavailable) })
	if err == nil {
		t.Fatal("a start that never reads returned nil")
	}
	onTheStoreSchedule(t, waits())
	if n := strings.Count(out.String(), "nothing is served yet"); n != 1 {
		t.Fatalf("twelve identical failures printed %d lines:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), storeScheduleText) || strings.Contains(out.String(), "in 5s") {
		t.Fatalf("the line does not state the schedule:\n%s", out.String())
	}
}

func TestRetryCtxSaysAnOutageOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := sleepsOf(t, 12, cancel)
	var out bytes.Buffer
	was := stderr
	stderr = &out
	t.Cleanup(func() { stderr = was })
	if err := retryCtx(ctx, func() error { return fmt.Errorf("%w: no quorum", store.ErrUnavailable) }); err == nil {
		t.Fatal("a retry that never succeeds returned nil")
	}
	onTheStoreSchedule(t, waits())
	if n := strings.Count(out.String(), "trying again"); n != 1 {
		t.Fatalf("twelve identical failures printed %d lines:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), storeScheduleText) {
		t.Fatalf("the line does not state the schedule:\n%s", out.String())
	}
}

func TestTheRunnersHoldRetriesOnTheStoreSchedule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := sleepsOf(t, 12, cancel)
	var out bytes.Buffer
	was := stderr
	stderr = &out
	t.Cleanup(func() { stderr = was })
	var say outageSayer
	for failed := 1; failed <= 12 && waitToHold(ctx, &say, failed, "/port49/", fmt.Errorf("%w: no quorum", store.ErrUnavailable)); failed++ {
	}
	onTheStoreSchedule(t, waits())
	if n := strings.Count(out.String(), "taking keyspace /port49/"); n != 1 {
		t.Fatalf("twelve identical failures printed %d lines:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), storeScheduleText) {
		t.Fatalf("the line does not state the schedule:\n%s", out.String())
	}
}

func TestALateDirectoryOpenRetriesOnTheStoreSchedule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := sleepsOf(t, 12, cancel)
	var out bytes.Buffer
	var say outageSayer
	for failed := 1; failed <= 12 && waitForDirectory(ctx, &out, &say, failed, "port49d", fmt.Errorf("%w: no quorum", store.ErrUnavailable)); failed++ {
	}
	onTheStoreSchedule(t, waits())
	if n := strings.Count(out.String(), "directory store: not followed yet"); n != 1 {
		t.Fatalf("twelve identical failures printed %d lines:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), storeScheduleText) || strings.Contains(out.String(), "every 5s") {
		t.Fatalf("the line does not state the schedule:\n%s", out.String())
	}
}

// fastRetries makes every retry loop's wait a millisecond, for a test about what a loop does and not how
// long it waits.
func fastRetries(t *testing.T) {
	t.Helper()
	was := retrySleep
	t.Cleanup(func() { retrySleep = was })
	retrySleep = func(ctx context.Context, _ time.Duration) bool { return sleepCtx(ctx, time.Millisecond) }
}
