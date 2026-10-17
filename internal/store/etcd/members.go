package etcd

import (
	"context"
	"time"
)

// Members is how many members etcd lists, and how many of those answer a
// status read at their first client URL within per (plan 11a, R21: port49
// store status's "3/3 members"). The answer is this client's view: a
// member whose advertised URL it cannot reach does not answer. An error is
// the member list's, and then nothing is counted.
func (s *Store) Members(ctx context.Context, per time.Duration) (answering, listed int, err error) {
	resp, err := s.ctx.MemberList(ctx)
	if err != nil {
		return 0, 0, unavailable(err)
	}
	for _, m := range resp.Members {
		if len(m.ClientURLs) == 0 {
			continue // added, and not yet started
		}
		mctx, cancel := context.WithTimeout(ctx, per)
		_, err := s.ctx.Status(mctx, m.ClientURLs[0])
		cancel()
		if err == nil {
			answering++
		}
	}
	return answering, len(resp.Members), nil
}
