package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Members is how many members etcd lists, and how many of those answer a
// status read at their first client URL within per (plan 11a, R21: port49
// store status's "3/3 members"). The answer is this client's view: a
// member whose advertised URL it cannot reach does not answer. An error is
// the member list's, and then nothing is counted.
func (s *Store) Members(ctx context.Context, per time.Duration) (answering, listed int, err error) {
	// Serializable: the list needs no quorum, so with the quorum lost the
	// count still reads 1/3, not an error (R21).
	resp, err := s.ctx.MemberList(ctx, clientv3.WithSerializable())
	if err != nil {
		return 0, 0, unavailable(err)
	}
	var wg sync.WaitGroup
	var n atomic.Int64
	for _, m := range resp.Members {
		if len(m.ClientURLs) == 0 {
			continue // added, and not yet started
		}
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			mctx, cancel := context.WithTimeout(ctx, per)
			defer cancel()
			if _, err := s.ctx.Status(mctx, url); err == nil {
				n.Add(1)
			}
		}(m.ClientURLs[0])
	}
	wg.Wait()
	return int(n.Load()), len(resp.Members), nil
}
