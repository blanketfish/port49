package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// fakeClock is a clock whose sleeps advance it and take no time; slept is
// every wait asked for, in order.
type fakeClock struct {
	at    time.Time
	slept []time.Duration
}

func (f *fakeClock) clock() retryClock {
	return retryClock{
		now:   func() time.Time { return f.at },
		sleep: func(d time.Duration) { f.slept = append(f.slept, d); f.at = f.at.Add(d) },
	}
}

func storeDown(after time.Duration) error {
	return &agent.StoreUnavailableError{
		Err:        &agent.BrokerUnavailableError{Err: errors.New("agent: the broker is unavailable just now (store_unavailable): d; retry in 5s")},
		RetryAfter: after,
	}
}

// `port49 token` retries a mint refused store_unavailable, waiting the
// reply's Retry-After (5s when it has none) between tries, and gives the
// token once the broker is ready (spec §5.7; issue #11).
func TestTokenRetriesStoreUnavailableThenSucceeds(t *testing.T) {
	fc := &fakeClock{at: time.Unix(1000, 0)}
	calls := 0
	var errb strings.Builder
	item, err := mintRetrying(func() (api.MintItem, error) {
		calls++
		switch calls {
		case 1:
			return api.MintItem{}, storeDown(7 * time.Second)
		case 2:
			return api.MintItem{}, storeDown(0)
		}
		return permit, nil
	}, fc.clock(), "port49 token", &errb)
	if err != nil || item.Login != "LOGINTOKEN" || calls != 3 {
		t.Fatalf("item %+v err %v after %d calls", item, err, calls)
	}
	if len(fc.slept) != 2 || fc.slept[0] != 7*time.Second || fc.slept[1] != 5*time.Second {
		t.Fatalf("waited %v, want the Retry-After (7s) and then the default (5s)", fc.slept)
	}
	if strings.Contains(errb.String(), "LOGINTOKEN") {
		t.Fatalf("stderr holds the token: %q", errb.String())
	}
}

// A broker that stays unavailable is waited on for 30s in all, then the last
// error stands as it always did.
func TestTokenGivesUpAfterThirtySeconds(t *testing.T) {
	fc := &fakeClock{at: time.Unix(1000, 0)}
	calls := 0
	want := storeDown(5 * time.Second)
	_, err := mintRetrying(func() (api.MintItem, error) { calls++; return api.MintItem{}, want }, fc.clock(),
		"port49 token", &strings.Builder{})
	if err != want {
		t.Fatalf("err %v, want the broker's own", err)
	}
	var total time.Duration
	for _, d := range fc.slept {
		total += d
	}
	if total != 30*time.Second || calls != 7 {
		t.Fatalf("waited %v over %d calls, want 30s over 7", total, calls)
	}
}

// Any other failure ends at once: no wait, no second try.
func TestTokenRetriesNoOtherReason(t *testing.T) {
	for name, e := range map[string]error{
		"another outage": &agent.BrokerUnavailableError{Err: errors.New("agent: the broker is unreachable")},
		"a refusal":      &agent.APIError{Status: 503, Code: "revocation_busy", Detail: "d", RetryAfter: 5 * time.Second},
		"session over":   agent.ErrSessionOver,
		"no agent":       agent.ErrNoAgent,
	} {
		fc := &fakeClock{at: time.Unix(1000, 0)}
		calls := 0
		_, err := mintRetrying(func() (api.MintItem, error) { calls++; return api.MintItem{}, e }, fc.clock(),
			"port49 token", &strings.Builder{})
		if err != e || calls != 1 || len(fc.slept) != 0 {
			t.Errorf("%s: err %v, %d calls, waited %v; want the error at once", name, err, calls, fc.slept)
		}
	}
}

// A Retry-After longer than what is left of the 30s is not waited on: the
// whole call never overshoots 30s.
func TestTokenNeverOvershootsThirtySeconds(t *testing.T) {
	fc := &fakeClock{at: time.Unix(1000, 0)}
	calls := 0
	steps := []time.Duration{20 * time.Second, 20 * time.Second}
	start := fc.at
	_, err := mintRetrying(func() (api.MintItem, error) {
		calls++
		d := 20 * time.Second
		if calls <= len(steps) {
			d = steps[calls-1]
		}
		return api.MintItem{}, storeDown(d)
	}, fc.clock(), "port49 token", &strings.Builder{})
	if err == nil || fc.at.Sub(start) > 30*time.Second || calls != 2 {
		t.Fatalf("err %v after %d calls and %v, want to stop at the second refusal inside 30s", err, calls, fc.at.Sub(start))
	}
	if len(fc.slept) != 1 || fc.slept[0] != 20*time.Second {
		t.Fatalf("waited %v, want one 20s wait", fc.slept)
	}
}

// End to end through the socket: the agent's 503 store_unavailable with its
// Retry-After is waited out, the token is printed once, and the exit is 0.
func TestTokenCommandWaitsOutTheStartGate(t *testing.T) {
	fc := &fakeClock{at: time.Unix(1000, 0)}
	defer func(c retryClock) { tokenRetryClock = c }(tokenRetryClock)
	tokenRetryClock = fc.clock()
	var n atomic.Int32
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r) // the status read for the ceiling warning
			return
		}
		if n.Add(1) <= 2 {
			w.Header().Set("Retry-After", strconv.Itoa(3))
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "store_unavailable", Detail: "the broker is unavailable just now (store_unavailable): wait; retry in 3s"})
			return
		}
		_ = json.NewEncoder(w).Encode(permit)
	}))
	var out, errb lockedBuffer
	code := run([]string{"token", "--socket", sock, "leaf1"}, &out, &errb)
	if code != 0 || out.String() != "LOGINTOKEN\n" || n.Load() != 3 {
		t.Fatalf("code %d out %q err %q after %d calls", code, out.String(), errb.String(), n.Load())
	}
	if len(fc.slept) != 2 || fc.slept[0] != 3*time.Second {
		t.Fatalf("waited %v", fc.slept)
	}
}

// And when it never clears: the same exit code and retry wording as before
// the retry existed, after 30s of waiting, with the broker's detail.
func TestTokenCommandGivesUpWithTheSameWords(t *testing.T) {
	fc := &fakeClock{at: time.Unix(1000, 0)}
	defer func(c retryClock) { tokenRetryClock = c }(tokenRetryClock)
	tokenRetryClock = fc.clock()
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "store_unavailable", Detail: "gate closed; retry in 5s"})
	}))
	var out, errb lockedBuffer
	code := run([]string{"token", "--json", "--socket", sock, "leaf1"}, &out, &errb)
	var f tokenFailure
	if code != 1 || json.Unmarshal([]byte(out.String()), &f) != nil || f.Error != "broker_unavailable" ||
		!strings.Contains(errb.String(), "gate closed; retry in 5s") || fc.at.Sub(time.Unix(1000, 0)) != 30*time.Second {
		t.Fatalf("code %d out %q err %q, waited %v", code, out.String(), errb.String(), fc.slept)
	}
}

// A proof (touch or sign-in) refused store_unavailable is not retried: a retry
// would ask the person to prove again unasked. Only the mint is retried.
func TestTokenDoesNotRetryAProofRefusedStoreUnavailable(t *testing.T) {
	fc := &fakeClock{at: time.Unix(1000, 0)}
	calls := 0
	want := &mfaUnprovedError{Err: storeDown(5 * time.Second)}
	_, err := mintRetrying(func() (api.MintItem, error) { calls++; return api.MintItem{}, want }, fc.clock(),
		"port49 token", &strings.Builder{})
	if err != want || calls != 1 || len(fc.slept) != 0 {
		t.Fatalf("err %v after %d calls, waits %v; want the proof's error at once", err, calls, fc.slept)
	}
}
