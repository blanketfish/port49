package etcd

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// A call that is not re-sent (a mint's PutToken) cannot be saved by a hedge,
// so it must not keep landing on a member that has just left it waiting: with
// one of three members dark, only the calls already in flight when it went
// dark may fail, not one in three for as long as its connection stays up.
func TestUnhedgedCallsStopLandingOnAMemberThatJustTimedOut(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	for i := 0; i < 12; i++ { // every connection up before one goes dark
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.Ping(c)
		cancel()
	}
	ps[2].Hang(true)
	var fails, total, n atomic.Int64
	var wg sync.WaitGroup
	end := time.Now().Add(8 * time.Second) // inside keepalive's 10s + 2s
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(end) {
				c, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				id := n.Add(1)
				_, err := s.PutToken(c, store.TokenKey{NAS: "leaf-01", Username: fmt.Sprint("u", id)},
					store.Token{ID: fmt.Sprint("t", id), Secret: []byte("x"), Kind: store.KindLogin, ExpiresAt: time.Now().Add(time.Minute)})
				cancel()
				total.Add(1)
				if err != nil {
					fails.Add(1)
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	t.Logf("%d of %d unhedged writes failed with one member dark", fails.Load(), total.Load())
	if f := fails.Load(); f > 6 {
		t.Fatalf("%d of %d unhedged writes failed with one member dark, want only those in flight when it went dark (6 at most)", f, total.Load())
	}
}
