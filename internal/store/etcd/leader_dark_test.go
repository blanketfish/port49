package etcd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/storetest"
)

// The leader paused (its client link hangs and its Raft stops, as `docker
// pause` does) leaves the other two to elect one. Logins (a mint, then a
// redemption of it) run on four goroutines through all of it; once the
// election has had its time, no call may fail at once: a failure that takes
// under 20 ms is an error returned without trying a member (the matrix saw
// 9 s of them, leader_dark round 3).
func TestNoCallFailsAtOnceWhileTheLeaderIsDark(t *testing.T) {
	s, c, ps := threeBehindProxies(t)
	for i := 0; i < 12; i++ { // every connection up before the leader goes dark
		cx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.Ping(cx)
		cancel()
	}
	leader := c.Leader(t)
	start := time.Now()
	ps[leader].Hang(true)
	c.Kill(leader)

	type failure struct {
		at, took time.Duration
		op       string
		err      error
	}
	var mu sync.Mutex
	var fails []failure
	var calls int
	note := func(op string, begun time.Time, err error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if err != nil {
			fails = append(fails, failure{begun.Sub(start), time.Since(begun), op, err})
		}
	}
	var wg sync.WaitGroup
	end := start.Add(16 * time.Second)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; time.Now().Before(end); n++ {
				id := fmt.Sprintf("w%d-%d", w, n)
				k := store.TokenKey{NAS: "leaf-01", Username: id}
				rk := store.ReceiptKey{NAS: "leaf-01", Username: id, CredentialSHA256: sha256.Sum256([]byte(id))}
				now := time.Now()
				r := store.Receipt{Status: 1, CtxID: "01J", CredentialSHA256: rk.CredentialSHA256, FirstRedeemedAt: now,
					IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Minute)}
				cx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				b := time.Now()
				_, err := s.PutToken(cx, k, store.Token{ID: id, Secret: []byte(id), Kind: store.KindLogin,
					ExpiresAt: time.Now().Add(time.Minute)})
				cancel()
				note("PutToken", b, err)
				if err != nil {
					time.Sleep(250 * time.Millisecond)
					continue
				}
				cx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				b = time.Now()
				err = s.RedeemAndReceipt(cx, k, id, storetest.Rw(rk, r, "user:alice"))
				cancel()
				note("RedeemAndReceipt", b, err)
				time.Sleep(250 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	instant := 0
	for _, f := range fails {
		t.Logf("+%v %s failed in %v: %v", f.at.Round(time.Millisecond), f.op, f.took.Round(time.Millisecond), f.err)
		if f.at > 3*time.Second && f.took < 20*time.Millisecond {
			instant++
		}
	}
	t.Logf("%d of %d calls failed, %d at once after the first 3 s", len(fails), calls, instant)
	if instant > 0 {
		t.Fatalf("%d calls failed at once while the leader was dark", instant)
	}
}
