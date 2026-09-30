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
	MalformedWindow      time.Duration // a source's malformed-strike count resets when no strike has arrived within the window
	AuthFailureDelayBase time.Duration
	AuthFailureDelayMax  time.Duration
	AuthFailureWindow    time.Duration
}

type failure struct {
	count int
	last  time.Time
}

type Limiter struct {
	cfg    Config
	now    func() time.Time
	mu     sync.Mutex
	open   map[netip.Addr]int
	bad    map[netip.Addr]failure // malformed strikes per source
	auth   map[string]failure     // key: nas + "\x00" + username
	writes int                    // incremented on every Malformed/AuthFailure; triggers sweep at sweepEvery
}

func New(c Config, now func() time.Time) *Limiter {
	return &Limiter{cfg: c, now: now, open: map[netip.Addr]int{}, bad: map[netip.Addr]failure{}, auth: map[string]failure{}}
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
// the connection before closing it: base * 2^(strikes-1), capped. Counts reset
// after MalformedWindow elapses with no new strikes.
func (l *Limiter) Malformed(src netip.Addr) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.bad[src]
	now := l.now()
	if l.cfg.MalformedWindow > 0 && now.Sub(f.last) > l.cfg.MalformedWindow {
		f.count = 0
	}
	f.count++
	f.last = now
	l.bad[src] = f
	l.writes++
	if l.writes%1024 == 0 {
		l.sweepLocked(now)
	}
	return backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, f.count)
}

// Holding reports whether src is inside the backoff its last strike earned:
// port49d refuses such a source at Accept, at once, rather than hold one of
// its connections silent (L28 branch H).
func (l *Limiter) Holding(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.bad[src]
	if !ok || f.count == 0 {
		return false
	}
	return l.now().Before(f.last.Add(backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, f.count)))
}

// AuthFailure records a failed authentication for (nas, username) and returns
// the delay to apply before the FAIL reply. Counts reset after the window.
func (l *Limiter) AuthFailure(nas, username string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := nas + "\x00" + username
	f := l.auth[k]
	now := l.now()
	if l.cfg.AuthFailureWindow > 0 && now.Sub(f.last) > l.cfg.AuthFailureWindow {
		f.count = 0
	}
	f.count++
	f.last = now
	l.auth[k] = f
	l.writes++
	if l.writes%1024 == 0 {
		l.sweepLocked(now)
	}
	return backoff(l.cfg.AuthFailureDelayBase, l.cfg.AuthFailureDelayMax, f.count)
}

func (l *Limiter) sweepLocked(now time.Time) {
	// Delete malformed-strike entries older than MalformedWindow.
	if l.cfg.MalformedWindow > 0 {
		for src, f := range l.bad {
			if now.Sub(f.last) > l.cfg.MalformedWindow {
				delete(l.bad, src)
			}
		}
	}

	// Delete auth-failure entries older than AuthFailureWindow.
	if l.cfg.AuthFailureWindow > 0 {
		for k, f := range l.auth {
			if now.Sub(f.last) > l.cfg.AuthFailureWindow {
				delete(l.auth, k)
			}
		}
	}
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
