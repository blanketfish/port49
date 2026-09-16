// Package limits implements the per-source listener limits of design §11.
// Limits are per source before they are global, so one device cannot deny
// service to the fleet. Nothing here ever locks an account.
package limits

import (
	"net/netip"
	"sync"
	"time"
)

type Config struct {
	PerNASConnections    int
	IdleTimeout          time.Duration
	MalformedBackoffBase time.Duration
	MalformedBackoffMax  time.Duration
	AuthFailureDelayBase time.Duration
	AuthFailureDelayMax  time.Duration
	AuthFailureWindow    time.Duration
}

type failure struct {
	count int
	last  time.Time
}

type Limiter struct {
	cfg  Config
	now  func() time.Time
	mu   sync.Mutex
	open map[netip.Addr]int
	bad  map[netip.Addr]int
	auth map[string]failure // key: nas + "\x00" + username
}

func New(c Config, now func() time.Time) *Limiter {
	return &Limiter{cfg: c, now: now, open: map[netip.Addr]int{}, bad: map[netip.Addr]int{}, auth: map[string]failure{}}
}

// Acquire takes a connection slot for src. ok is false when the per-NAS cap is
// reached; the caller refuses only that connection.
func (l *Limiter) Acquire(src netip.Addr) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[src] >= l.cfg.PerNASConnections {
		return nil, false
	}
	l.open[src]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.open[src]--
			if l.open[src] == 0 {
				delete(l.open, src)
			}
			l.mu.Unlock()
		})
	}, true
}

// Malformed records a malformed packet from src and returns how long to hold
// the connection before closing it: base * 2^(strikes-1), capped.
func (l *Limiter) Malformed(src netip.Addr) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bad[src]++
	return backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, l.bad[src])
}

// AuthFailure records a failed authentication for (nas, username) and returns
// the delay to apply before the FAIL reply. Counts reset after the window.
func (l *Limiter) AuthFailure(nas, username string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := nas + "\x00" + username
	f := l.auth[k]
	if l.now().Sub(f.last) > l.cfg.AuthFailureWindow {
		f.count = 0
	}
	f.count++
	f.last = l.now()
	l.auth[k] = f
	return backoff(l.cfg.AuthFailureDelayBase, l.cfg.AuthFailureDelayMax, f.count)
}

func backoff(base, max time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		return max
	}
	return d
}
