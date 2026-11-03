package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// With one of three members dark, four goroutines reading at once must see no
// read fail: the copies of one hedged call go to different members, whatever
// the other goroutines' calls do to the client's rotation. (Round-robin
// shared by every call let a call's copies all land on the dark member.)
func TestAHedgedReadsCopiesGoToDifferentMembersUnderConcurrency(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	for i := 0; i < 12; i++ { // every connection up before one goes dark
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.Ping(c)
		cancel()
	}
	ps[2].Hang(true)
	var fails, total atomic.Int64
	var wg sync.WaitGroup
	end := time.Now().Add(8 * time.Second) // inside keepalive's 10s + 2s, which would drop the dark connection
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(end) {
				c, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				err := s.Ping(c)
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
	if fails.Load() != 0 {
		t.Fatalf("%d of %d hedged reads failed with one of three members dark", fails.Load(), total.Load())
	}
}
