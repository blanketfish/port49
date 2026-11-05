package broker

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/store"
)

// slowBlobs is a store whose PutBlob, the first store call of each device's
// mint, takes delay and counts how many run at once.
type slowBlobs struct {
	store.Store
	delay         time.Duration
	inflight, max atomic.Int32
}

func (s *slowBlobs) PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
	n := s.inflight.Add(1)
	defer s.inflight.Add(-1)
	for {
		m := s.max.Load()
		if n <= m || s.max.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(s.delay)
	return s.Store.PutBlob(ctx, hash, body, ttl)
}

func batchFixture(t *testing.T, n int) (*fixture, *slowBlobs, []string) {
	t.Helper()
	var extra []admission.Device
	var names []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("dev%03d", i)
		names = append(names, name)
		extra = append(extra, admission.Device{Name: name, Platform: "arista_eos",
			Addresses: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("10.9.%d.%d", i/250, i%250+1))}})
	}
	f := newFixtureWithDevices(t, 1000, extra...)
	f.b.BatchMax = n + 2
	s := &slowBlobs{Store: f.st, delay: 50 * time.Millisecond}
	f.b.Store = s
	return f, s, names
}

func batchBody(devices []string) string {
	return `{"devices":["` + strings.Join(devices, `","`) + `"]}`
}

// A batch's devices mint with bounded concurrency (load run 5, Q2): 100
// devices at 50 ms each take a few rounds of eight, not 100 in a row.
func TestABatchMintsItsDevicesConcurrentlyUpToEight(t *testing.T) {
	f, s, names := batchFixture(t, 100)
	start := time.Now()
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), batchBody(names), ""))
	took := time.Since(start)
	if len(resp.Results) != 100 {
		t.Fatalf("%d results", len(resp.Results))
	}
	if took > 2*time.Second { // serial is 5 s; eight at a time is about 0.65 s
		t.Fatalf("100 devices took %v", took)
	}
	if got := s.max.Load(); got < 2 || got > 8 {
		t.Fatalf("%d in flight at once; want 2 to 8", got)
	}
}

// The response is in the request's order, whichever device finishes first.
func TestAConcurrentBatchKeepsTheRequestOrder(t *testing.T) {
	f, _, names := batchFixture(t, 40)
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 { // not sorted
		names[i], names[j] = names[j], names[i]
	}
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), batchBody(names), ""))
	for i, it := range resp.Results {
		if it.Device != names[i] {
			t.Fatalf("result %d is %s; want %s", i, it.Device, names[i])
		}
	}
}

// One device's refusal or fault leaves the others' verdicts as they were.
func TestOneDevicesFailureLeavesTheOthersVerdicts(t *testing.T) {
	f, _, names := batchFixture(t, 20)
	mixed := append(append(append([]string{}, names[:10]...), "ghost", "bare"), names[10:]...)
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), batchBody(mixed), ""))
	if len(resp.Results) != len(mixed) {
		t.Fatalf("%d results", len(resp.Results))
	}
	for i, it := range resp.Results {
		switch it.Device {
		case "ghost":
			if it.Verdict != "deny" || it.Reason != "no_grants_matched" {
				t.Fatalf("ghost: %+v", it)
			}
		case "bare":
			if it.Error != "device_unconfigured" {
				t.Fatalf("bare: %+v", it)
			}
		default:
			if it.Device != mixed[i] || it.Verdict != "permit" {
				t.Fatalf("result %d: %+v", i, it)
			}
		}
	}
}

// A store that refuses a device's blob is that device's store_unavailable
// deny inside a 200, and the batch goes on.
func TestAStoreFailureIsOneDevicesDenyInsideA200(t *testing.T) {
	f, _, names := batchFixture(t, 12)
	f.b.Store = failingBlobs{Store: f.b.Store}
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), batchBody(names), ""))
	if len(resp.Results) != 12 {
		t.Fatalf("%d results", len(resp.Results))
	}
	for _, it := range resp.Results {
		if it.Verdict != "deny" || it.Reason != "store_unavailable" {
			t.Fatalf("%+v", it)
		}
	}
}

type failingBlobs struct{ store.Store }

func (failingBlobs) PutBlob(context.Context, string, []byte, time.Duration) error {
	return fmt.Errorf("%w: no quorum", store.ErrUnavailable)
}
