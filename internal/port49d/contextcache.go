package port49d

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// staleSayer says, once per run of them, that the context cache is
// answering past its ttl because the store fails, and once that the
// store answers again (plan 7f, Ruling 5): the line is the durable
// witness, since the metrics registry restarts with each run after a
// store gone, and a stale run ends in one.
type staleSayer struct {
	mu  sync.Mutex
	on  bool
	out io.Writer
	ttl time.Duration
	// key is the config key of ttl, as the line names it (the session
	// store's path + ".etcd.context_cache.ttl"); empty names etcd.context_cache.ttl.
	key string
}

func (s *staleSayer) serve(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.on {
		return
	}
	s.on = true
	if s.key == "" {
		s.key = "etcd.context_cache.ttl"
	}
	fmt.Fprintf(s.out, "port49d: store: the store does not answer context reads (%v); serving cached login contexts "+
		"past %s (%v) until it does or the listeners close; a revocation made meanwhile "+
		"does not reach them\n", err, s.key, s.ttl)
}

func (s *staleSayer) fresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.on {
		return
	}
	s.on = false
	fmt.Fprintln(s.out, "port49d: store: context reads are answered by the store again; the context cache serves "+
		"within its ttl")
}
