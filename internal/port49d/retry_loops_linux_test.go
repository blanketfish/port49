package port49d

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
)

// The wait after a run of the duties: a run of storeAttemptMax or more starts the schedule over, a shorter
// one (a hold lost again and again) counts as one more failure, so a flapping hold backs off.
func TestNextFailedBacksOffAFlappingHoldAndRestartsAfterALongRun(t *testing.T) {
	for _, c := range []struct {
		failed int
		ran    time.Duration
		want   int
	}{
		{0, time.Second, 1},
		{3, storeAttemptMax - time.Millisecond, 4},
		{3, storeAttemptMax, 1},
		{11, time.Hour, 1},
		{11, 0, 12},
	} {
		if got := nextFailed(c.failed, c.ran); got != c.want {
			t.Errorf("nextFailed(%d, %v) = %d, want %d", c.failed, c.ran, got, c.want)
		}
	}
}

// openDirectoryLater's own count: a directory that does not answer is tried on the store schedule.
func TestALateDirectoryOpenLoopBacksOffWhileTheDirectoryIsSilent(t *testing.T) {
	var out syncBuffer
	f := splitFleet(t)
	f.twoStores(t)
	endpointsAre(t, f.broker, f.dproxy.Addr(), silentEndpoint(t))
	cfg, _ := loadBroker(t, f.broker)
	cfg.Stores.Directory.Etcd.CallTimeout = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := sleepsOf(t, 12, cancel)
	err := openDirectoryLater(ctx, cfg, metrics.New(prometheus.NewRegistry()), &out, &dirHandle{}, "port49-broker", nil)
	if err == nil {
		t.Fatal("a silent directory opened")
	}
	onTheStoreSchedule(t, waits())
	if !strings.Contains(out.String(), "directory store: not followed yet") {
		t.Fatalf("the outage was not said:\n%s", out.String())
	}
}

// run()'s own bookkeeping, on a real keyspace: with the store cut after a take, the hold loop's failure
// count climbs by one each failed attempt (so it waits on the store schedule), an outage is said, and
// after the hold is taken again a second outage with the same words is said again.
func TestTheRunnersHoldLoopCountsEachFailureAndSaysEachOutage(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	var mu sync.Mutex
	var counts []int
	was, wasSleep, wasRnd := holdWaiting, retrySleep, retryRnd
	t.Cleanup(func() { holdWaiting, retrySleep, retryRnd = was, wasSleep, wasRnd })
	holdWaiting = func(failed int) { mu.Lock(); counts = append(counts, failed); mu.Unlock() }
	retryRnd = func() float64 { return 0.5 }
	retrySleep = func(c context.Context, _ time.Duration) bool { return sleepCtx(c, time.Millisecond) }
	_, stop := startBroker(t, f.broker, &out, 1)
	defer func() { f.proxy.Hang(false); _ = stop() }()
	waitWithin(t, &out, "runner: took keyspace /port49/", 30*time.Second)

	f.proxy.Hang(true)
	waitFor90(t, "five counts in the first outage", func() bool { mu.Lock(); defer mu.Unlock(); return len(counts) >= 5 })
	mu.Lock()
	first := append([]int(nil), counts...)
	mu.Unlock()
	for i := 1; i < len(first); i++ {
		if first[i] != first[i-1]+1 {
			t.Fatalf("the hold loop's failure count does not climb by one each attempt: %v", first)
		}
	}
	if strings.Count(out.String(), "runner: taking keyspace /port49/") < 1 {
		t.Fatalf("the outage was not said:\n%s", out.String())
	}
	f.proxy.Hang(false)
	waitFor90(t, "the hold taken again", func() bool { return strings.Count(out.String(), "runner: took keyspace /port49/") >= 2 })
	before := strings.Count(out.String(), "runner: taking keyspace /port49/")
	f.proxy.Hang(true)
	waitFor90(t, "the second outage said again", func() bool {
		return strings.Count(out.String(), "runner: taking keyspace /port49/") > before
	})
}

// waitFor90 waits up to 90 seconds for cond.
func waitFor90(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(90 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s", what)
		}
	}
}
