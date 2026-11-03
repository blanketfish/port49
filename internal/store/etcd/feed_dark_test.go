package etcd

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// A context watch on a member that goes dark ends and is opened on another,
// so the feed keeps following the store: the fence holds a login behind the
// feed, and a feed left on a paused member (its connection stays up until
// keepalive fails it, 10 to 12 s on) refused logins for that long. Each
// member goes dark in turn, so the watch is on it once; the loop is
// FollowContexts's, which opens a failed watch again every second.
func TestAContextWatchOnADarkMemberMovesToAnother(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	seen := map[string]bool{}
	from := uint64(0)
	go func() {
		for ctx.Err() == nil {
			mu.Lock()
			after := from
			mu.Unlock()
			s.WatchContexts(ctx, after, func(c store.ContextChange) {
				mu.Lock()
				seen[c.Key.Username] = true
				from = max(from, c.Rev)
				mu.Unlock()
			}, func(rev uint64) { mu.Lock(); from = max(from, rev); mu.Unlock() }, nil)
			time.Sleep(time.Second)
		}
	}()
	put := func(name string) {
		k := store.ContextKey{NAS: "leaf-01", Username: name}
		for i := 0; i < 20; i++ { // a write may meet the dark member: try again
			c, cc := context.WithTimeout(ctx, 500*time.Millisecond)
			err := s.PutContext(c, k, store.Context{CtxID: name, Principal: "user:x", Username: name}, time.Hour)
			cc()
			if err == nil {
				return
			}
		}
		t.Fatalf("could not write %s", name)
	}
	delivered := func(name string, within time.Duration) bool {
		for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			mu.Lock()
			ok := seen[name]
			mu.Unlock()
			if ok {
				return true
			}
		}
		return false
	}
	put("warm")
	if !delivered("warm", 5*time.Second) {
		t.Fatal("the watch delivered nothing on a healthy cluster")
	}
	for i, p := range ps {
		name := fmt.Sprintf("dark%d", i)
		p.Hang(true)
		put(name)
		if !delivered(name, 6*time.Second) {
			t.Errorf("member %d dark: the watch had not brought a change written after it went dark in 6s", i)
		}
		p.Hang(false)
		time.Sleep(3 * time.Second) // reconnect settles
	}
}
