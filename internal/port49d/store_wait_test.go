package port49d

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

func testWait(every time.Duration, again bool, startTimeout time.Duration) storeWait {
	return storeWait{every: every, again: again, startTimeout: startTimeout, proc: "port49d", what: "stores.session",
		eps: "https://etcd-1:2379", at: "stores.session.etcd", closed: "the listeners stay closed"}
}

func unavailable(why string) error { return fmt.Errorf("%s: %w", why, store.ErrUnavailable) }

// An outage that lasts many attempts is one line, and a different one is
// another: a second's retry does not write a line a second.
func TestAnOutageIsSaidOnceAndAgainOnlyWhenItChanges(t *testing.T) {
	var out bytes.Buffer
	n := 0
	errs := []string{"a", "a", "a", "a", "b", "b", "b"}
	try := func() (*etcdstore.Store, error) {
		if n < len(errs) {
			n++
			return nil, unavailable(errs[n-1])
		}
		return nil, nil
	}
	if _, err := awaitStore(context.Background(), try, testWait(time.Millisecond, true, 0), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), "not answering"); got != 2 {
		t.Fatalf("7 failed attempts with two different errors said %d lines, want 2:\n%s", got, out.String())
	}
}

// A first attempt that fails (etcd had no leader yet) is followed by the next
// within about a second, not five: the listeners are shut, and the devices on
// local auth, for as long as the retry takes.
func TestAFailedAttemptIsRetriedWithinASecond(t *testing.T) {
	var out bytes.Buffer
	n := 0
	try := func() (*etcdstore.Store, error) {
		if n++; n == 1 {
			return nil, unavailable("no leader")
		}
		return nil, nil
	}
	begun := time.Now()
	if _, err := awaitStore(context.Background(), try, testWait(storeAttemptEvery, true, 0), &out); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(begun); took > 1500*time.Millisecond {
		t.Fatalf("the retry after a failed attempt came after %v, want about 1s", took)
	}
}

// A cold start's start_timeout is the same bound at a denser cadence: it ends
// the wait no sooner and not much later, and a configuration fault ends it at
// once, named.
func TestAColdStartsTimeoutStandsWithDenserAttempts(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	try := func() (*etcdstore.Store, error) { calls++; return nil, unavailable("dark") }
	begun := time.Now()
	_, err := awaitStore(context.Background(), try, testWait(10*time.Millisecond, false, 100*time.Millisecond), &out)
	took := time.Since(begun)
	if err == nil || !strings.Contains(err.Error(), "did not answer within stores.session.etcd.start_timeout") {
		t.Fatalf("got %v, want the start_timeout error", err)
	}
	if took < 100*time.Millisecond || took > time.Second || calls < 3 {
		t.Fatalf("ended after %v with %d attempts, want the 100ms deadline with several attempts", took, calls)
	}
	fault := &storeFault{errors.New("stores.session.etcd.ca_file: unreadable")}
	_, err = awaitStore(context.Background(), func() (*etcdstore.Store, error) { return nil, fault }, testWait(10*time.Millisecond, false, time.Minute), &out)
	if !errors.As(err, new(*storeFault)) {
		t.Fatalf("a configuration fault on a cold start: %v, want it returned at once", err)
	}
}

// The wait is the base for the first ten failed attempts, then doubles to ten
// times the base and stays there.
func TestTheStoreWaitStaysAtTheBaseThenBacksOffToTheCap(t *testing.T) {
	b := time.Second
	var got []time.Duration
	for failed := 1; failed <= 16; failed++ {
		got = append(got, storeWaitAfter(b, failed))
	}
	want := []time.Duration{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 4, 8, 10, 10, 10}
	for i := range want {
		if got[i] != want[i]*b {
			t.Fatalf("wait after failed attempt %d is %v, want %v (all: %v)", i+1, got[i], want[i]*b, got)
		}
	}
}

// Jitter stays within a fifth either way, whatever the source gives, and is
// never 0.
func TestTheStoreWaitJitterStaysWithinItsBounds(t *testing.T) {
	d := 10 * time.Second
	for _, r := range []float64{0, 0.000001, 0.25, 0.5, 0.75, 0.999999} {
		j := jittered(d, r)
		if j < 8*time.Second || j > 12*time.Second || j <= 0 {
			t.Fatalf("jittered(%v, %v) = %v, want 8s to 12s and never 0", d, r, j)
		}
	}
	if jittered(d, 0) != 8*time.Second || jittered(d, 0.5) != d {
		t.Fatalf("the ends are %v and %v, want 8s and %v", jittered(d, 0), jittered(d, 0.5), d)
	}
}

// awaitStore waits as the schedule says, jitter applied from the injected
// source: no sleeping, so no flake.
func TestAwaitStoreWaitsAsTheScheduleSays(t *testing.T) {
	var waits []time.Duration
	w := testWait(time.Second, true, 0)
	w.rnd = func() float64 { return 0.5 } // no jitter
	w.after = func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		c := make(chan time.Time, 1)
		c <- time.Time{}
		return c
	}
	n := 0
	try := func() (*etcdstore.Store, error) {
		if n++; n <= 14 {
			return nil, unavailable("dark")
		}
		return nil, nil
	}
	if _, err := awaitStore(context.Background(), try, w, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	s := time.Second
	want := []time.Duration{s, s, s, s, s, s, s, s, s, s, 2 * s, 4 * s, 8 * s, 10 * s}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Fatalf("waits %v, want %v", waits, want)
	}
	w.rnd = func() float64 { return 0 }
	waits, n = nil, 0
	if _, err := awaitStore(context.Background(), try, w, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if waits[0] != 800*time.Millisecond {
		t.Fatalf("first wait with the lowest jitter %v, want 800ms", waits[0])
	}
}
