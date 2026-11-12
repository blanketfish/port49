package agent

import (
	"testing"
	"time"
)

// Callers claimed into a batch do not go back to the wire while it waits on
// an idempotency_in_progress answer: each acquisition of the wire is a
// batch's own, not a caller's spin.
func TestCallersInABatchDoNotSpinOnTheWire(t *testing.T) {
	defer func(d time.Duration) { mintDeadline = d }(mintDeadline)
	defer func(d, m time.Duration) { inProgressDelay, inProgressDelayMax = d, m }(inProgressDelay, inProgressDelayMax)
	mintDeadline = time.Second
	inProgressDelay, inProgressDelayMax = 100*time.Millisecond, 100*time.Millisecond
	r := newRig(t)
	defer r.a.senders.Wait()
	r.fb.mu.Lock()
	r.fb.inProgress = 1 << 30
	r.fb.delay = 50 * time.Millisecond
	r.fb.mu.Unlock()
	res := mintAll(r, devices(8))
	for range devices(8) {
		<-res
	}
	r.a.senders.Wait()
	// Eight callers, at most eight batches of one, each sleeping 100ms for a
	// second: about ten wire takes a batch. A spin is in the thousands.
	if n := r.a.wireTakes.Load(); n > 200 {
		t.Fatalf("%d acquisitions of the wire in a second", n)
	}
}
