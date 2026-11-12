package agent

import (
	"context"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
)

// 31 mints queued ahead of a revocation, batch_max 10: the revocation waits
// for the exchange in flight and the four batches ahead of it, no more.
func TestARevocationWaitsBehindTheQueuedBatchesAndNoMore(t *testing.T) {
	r := newRig(t)
	delay := 200 * time.Millisecond
	r.fb.mu.Lock()
	r.fb.delay = delay
	r.fb.answers = map[string]refusal{"/v1/tokens/revoke": revokedSelf}
	r.fb.mu.Unlock()
	devs := devices(32)
	first, rest := queueBehindOne(t, r, devs[0], devs[1:])
	start := time.Now()
	if _, err := r.a.Revoke(context.Background(), api.RevokeRequest{Mine: true}); err != nil {
		t.Fatal(err)
	}
	// In flight (1) + ceil(31/10) batches (4); the revocation itself is quick.
	if took := time.Since(start); took > 5*delay+400*time.Millisecond {
		t.Fatalf("the revocation waited %v, want at most %v", took, 5*delay+400*time.Millisecond)
	}
	for _, ch := range []<-chan mintResult{first, rest} {
		for res := range ch {
			if res.err != nil {
				t.Errorf("%s: %v", res.device, res.err)
			}
		}
	}
	r.fb.mu.Lock()
	defer r.fb.mu.Unlock()
	if len(r.fb.batches) != 5 {
		t.Errorf("%d mint requests, want 5 (1 + 10, 10, 10, 1)", len(r.fb.batches))
	}
}
