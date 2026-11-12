package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
)

// mintResult is one concurrent Mint's answer.
type mintResult struct {
	device string
	item   api.MintItem
	err    error
}

// waitMints waits until the fake broker has been asked n mint requests.
func waitMints(t *testing.T, r *rig, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.fb.mu.Lock()
		got := len(r.fb.batchKeys)
		r.fb.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the broker was asked %d mint requests, want %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// mintAll starts one Mint per device at once and returns the channel its
// answers arrive on.
func mintAll(r *rig, devices []string) <-chan mintResult {
	out := make(chan mintResult, len(devices))
	var wg sync.WaitGroup
	for _, d := range devices {
		wg.Add(1)
		go func() {
			defer wg.Done()
			item, err := r.a.Mint(context.Background(), d, false, 0, "")
			out <- mintResult{d, item, err}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	return out
}

// queueBehindOne sends a first mint, waits until the broker holds it, then
// sends the rest, which queue behind it on the agent's one connection.
func queueBehindOne(t *testing.T, r *rig, first string, rest []string) (<-chan mintResult, <-chan mintResult) {
	t.Helper()
	a := mintAll(r, []string{first})
	waitMints(t, r, 1)
	b := mintAll(r, rest)
	// Let the rest reach the agent's queue before the first answers.
	time.Sleep(100 * time.Millisecond)
	return a, b
}

func devices(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("leaf%02d", i)
	}
	return out
}

// Mints that queue behind a slow one go out as batches of at most batch_max,
// not one exchange each, and each caller gets its own device's token (F2-3).
func TestQueuedMintsCoalesceIntoBatches(t *testing.T) {
	defer func(d time.Duration) { wireWait = d }(wireWait)
	wireWait = 5 * time.Second
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.delay = 300 * time.Millisecond
	r.fb.mu.Unlock()
	devs := devices(24)
	start := time.Now()
	first, rest := queueBehindOne(t, r, devs[0], devs[1:])
	var all []mintResult
	for res := range first {
		all = append(all, res)
	}
	for res := range rest {
		all = append(all, res)
	}
	if len(all) != len(devs) {
		t.Fatalf("%d answers, want %d", len(all), len(devs))
	}
	for _, res := range all {
		if res.err != nil {
			t.Errorf("%s: %v", res.device, res.err)
			continue
		}
		if res.item.Device != res.device || res.item.Address != "addr-"+res.device {
			t.Errorf("%s was answered with another device's item", res.device)
		}
	}
	r.fb.mu.Lock()
	defer r.fb.mu.Unlock()
	if len(r.fb.batches) > 4 {
		t.Errorf("%d exchanges for %d mints, want at most 4 (batch_max 10)", len(r.fb.batches), len(devs))
	}
	for _, b := range r.fb.batches {
		if len(b) > 10 {
			t.Errorf("a batch of %d devices, over batch_max 10", len(b))
		}
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("took %v", took)
	}
}

// One device's refusal fails that device's caller and no other (F2-3).
func TestOneDevicesRefusalDoesNotFailTheOthers(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.delay = 200 * time.Millisecond
	r.fb.itemErrFor = map[string]string{"leaf03": "inventory_error"}
	r.fb.mu.Unlock()
	devs := devices(6)
	first, rest := queueBehindOne(t, r, devs[0], devs[1:])
	var all []mintResult
	for res := range first {
		all = append(all, res)
	}
	for res := range rest {
		all = append(all, res)
	}
	for _, res := range all {
		var ie *ItemError
		if res.device == "leaf03" {
			if !errors.As(res.err, &ie) || ie.Device != "leaf03" {
				t.Errorf("leaf03: %v", res.err)
			}
			continue
		}
		if res.err != nil {
			t.Errorf("%s failed with another device's refusal: %v", res.device, res.err)
		}
	}
	r.fb.mu.Lock()
	defer r.fb.mu.Unlock()
	together := false
	for _, b := range r.fb.batches {
		if len(b) > 1 {
			for _, d := range b {
				together = together || d == "leaf03"
			}
		}
	}
	if !together {
		t.Error("leaf03 was never sent in a batch with another device")
	}
}

// A batch whose answer is lost is sent again under the same key and body, so
// the broker replays each device's record and no device is minted twice.
func TestARetriedBatchMintsNoDeviceTwice(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.delay = 200 * time.Millisecond
	r.fb.mu.Unlock()
	devs := devices(6)
	first, _ := queueBehindOne(t, r, devs[0], nil)
	r.fb.mu.Lock()
	r.fb.dropAfterMint = 1 // the next request, the batch, is minted and its answer lost
	r.fb.mu.Unlock()
	rest := mintAll(r, devs[1:])
	var all []mintResult
	for res := range first {
		all = append(all, res)
	}
	for res := range rest {
		all = append(all, res)
	}
	for _, res := range all {
		if res.err != nil {
			t.Errorf("%s: %v", res.device, res.err)
		}
	}
	r.fb.mu.Lock()
	defer r.fb.mu.Unlock()
	for _, d := range devs {
		if r.fb.minted[d] != 1 {
			t.Errorf("%s was minted %d times", d, r.fb.minted[d])
		}
	}
	retried := false
	for i := range r.fb.batchKeys {
		for j := i + 1; j < len(r.fb.batchKeys); j++ {
			if r.fb.batchKeys[i] == r.fb.batchKeys[j] && len(r.fb.batches[i]) > 1 &&
				fmt.Sprint(r.fb.batches[i]) == fmt.Sprint(r.fb.batches[j]) {
				retried = true
			}
		}
	}
	if !retried {
		t.Error("no batch of several devices was sent twice under one key")
	}
}

// A revocation sent while mints are queued waits for the exchange in flight
// and one batch, not for every queued mint one by one.
func TestARevocationQueuedDuringABatchIsNotDelayed(t *testing.T) {
	r := newRig(t)
	delay := 400 * time.Millisecond
	r.fb.mu.Lock()
	r.fb.delay = delay
	r.fb.answers = map[string]refusal{"/v1/tokens/revoke": revokedSelf}
	r.fb.mu.Unlock()
	devs := devices(11)
	first, rest := queueBehindOne(t, r, devs[0], devs[1:])
	start := time.Now()
	if _, err := r.a.Revoke(context.Background(), api.RevokeRequest{Mine: true}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 3*delay {
		t.Fatalf("the revocation waited %v behind queued mints, want under %v", took, 3*delay)
	}
	for res := range first {
		if res.err != nil {
			t.Errorf("%s: %v", res.device, res.err)
		}
	}
	for res := range rest {
		if res.err != nil {
			t.Errorf("%s: %v", res.device, res.err)
		}
	}
}

// A broker that accepts and stalls: Mint ends on the agent's own deadline,
// named, below the socket client's timeout, so the socket never gives up first.
func TestAStalledMintEndsOnTheAgentsNamedDeadline(t *testing.T) {
	if mintDeadline >= socketTimeout {
		t.Fatalf("mintDeadline %v is not below socketTimeout %v", mintDeadline, socketTimeout)
	}
	defer func(d time.Duration) { mintDeadline = d }(mintDeadline)
	mintDeadline = time.Second
	r := newRig(t)
	r.a.client.Timeout = 3 * time.Second // the transport's own limit, past the deadline
	r.fb.mu.Lock()
	r.fb.stall = true
	r.fb.mu.Unlock()
	start := time.Now()
	_, err := socketFor(t, r.a).Token(context.Background(), TokenRequest{Device: "leaf1"})
	if err == nil || !strings.Contains(err.Error(), "did not finish within") ||
		!strings.Contains(err.Error(), "waiting for the broker's answer") {
		t.Fatalf("a stalled mint said %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("took %v", took)
	}
	var bu *BrokerUnavailableError
	if !errors.As(err, &bu) {
		t.Errorf("not an outage the caller may retry: %T", err)
	}
}

// The deadline also covers the idempotency_in_progress waits, and says so.
func TestAMintStuckInProgressEndsOnTheAgentsNamedDeadline(t *testing.T) {
	defer func(d time.Duration) { mintDeadline = d }(mintDeadline)
	defer func(d, m time.Duration) { inProgressDelay, inProgressDelayMax = d, m }(inProgressDelay, inProgressDelayMax)
	mintDeadline = 500 * time.Millisecond
	inProgressDelay, inProgressDelayMax = 200*time.Millisecond, 200*time.Millisecond
	r := newRig(t)
	// The batch's sender ends on the same deadline, a moment after Mint
	// returns: let it finish before the vars above are put back.
	defer r.a.senders.Wait()
	r.fb.mu.Lock()
	r.fb.inProgress = 1 << 30
	r.fb.mu.Unlock()
	_, err := r.a.Mint(context.Background(), "leaf1", false, 0, "")
	if err == nil || !strings.Contains(err.Error(), "did not finish within") ||
		!strings.Contains(err.Error(), "waiting for an earlier try") {
		t.Fatalf("a mint stuck in progress said %v", err)
	}
}
