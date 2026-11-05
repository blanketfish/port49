package etcd

import (
	"runtime"
	"testing"
	"time"
)

// An attempt that fails after Open closes the store (port49d's attempt);
// that leaves nothing running: a thousand opens and closes against an
// endpoint that answers nothing grow no goroutines.
func TestAThousandStoresOpenedAndClosedLeaveNoGoroutines(t *testing.T) {
	cfg := Config{Endpoints: []string{"127.0.0.1:1"}, DialTimeout: 50 * time.Millisecond}
	open := func() {
		s, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ { // warm: the runtime's own goroutines settle
		open()
	}
	settle := func() int {
		for i := 0; i < 20; i++ {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}
	before := settle()
	for i := 0; i < 1000; i++ {
		open()
	}
	if after := settle(); after > before+5 {
		t.Fatalf("goroutines %d before, %d after 1000 opens and closes", before, after)
	}
}
