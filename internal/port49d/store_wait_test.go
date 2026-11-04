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
