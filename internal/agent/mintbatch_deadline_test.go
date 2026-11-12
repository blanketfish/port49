package agent

import (
	"context"
	"testing"
	"time"
)

// A batch claimed late ends at its caller's deadline, counted from when the
// caller asked, not from when the batch was claimed: with the broker
// stalled, leaf-b (asked 200ms after leaf-a, claimed when leaf-a's request
// ends at 1s) is done by 1.2s, not 2s.
func TestALateBatchEndsAtItsCallersDeadline(t *testing.T) {
	defer func(d time.Duration) { mintDeadline = d }(mintDeadline)
	mintDeadline = time.Second
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.stall = true
	r.fb.mu.Unlock()
	start := time.Now()
	asked := make(chan struct{}, 2)
	mint := func(device string) {
		_, _ = r.a.Mint(context.Background(), device, false, 0, "")
		asked <- struct{}{}
	}
	go mint("leaf-a")
	waitMints(t, r, 1)
	time.Sleep(200 * time.Millisecond)
	go mint("leaf-b") // queued behind leaf-a's stalled request
	<-asked
	<-asked
	r.a.senders.Wait()
	if took := time.Since(start); took > 1700*time.Millisecond {
		t.Fatalf("the late batch ran to %v, past its caller's deadline", took)
	}
}
