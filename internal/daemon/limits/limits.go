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
	count  int
	last   time.Time
	status bool // the last decline was DeclineStatus's
}

type Limiter struct {
	cfg      Config
	now      func() time.Time
	mu       sync.Mutex
	open     map[netip.Addr]int
	bad      map[netip.Addr]failure // malformed strikes per source
	declined map[netip.Addr]failure // declines per source (Decline): not strikes, a window of their own
	auth     map[string]failure     // key: nas + "\x00" + username
	writes   int                    // incremented on every Malformed/Decline/AuthFailure; triggers sweep at sweepEvery
}

func New(c Config, now func() time.Time) *Limiter {
	return &Limiter{cfg: c, now: now, open: map[netip.Addr]int{}, bad: map[netip.Addr]failure{},
		declined: map[netip.Addr]failure{}, auth: map[string]failure{}}
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
	return backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, l.countLocked(l.bad, src))
}

// Holding reports whether src is inside the backoff its last strike earned:
// port49d refuses such a source at Accept, at once, rather than hold one of
// its connections silent (L28 branch H).
func (l *Limiter) Holding(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inWindowLocked(l.bad, src)
}

// Decline records that port49d declined a packet from src through no fault
// of the source's: admission refuses its device, the device is quarantined,
// or a reload refused or removed it. It opens a window, on the strike's
// schedule, in which the source's next connections are refused at Accept
// before the device writes (spec §10, "A declined source is refused at
// Accept"; §15 L31). It is not a strike: Holding and Malformed never see it.
func (l *Limiter) Decline(src netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.countLocked(l.declined, src)
	f := l.declined[src]
	f.status = false
	l.declined[src] = f
}

// DeclineStatus is Decline for a device whose certificate status could not
// be established (spec §13 decision 50 ruling 8): the same window on the same
// schedule, marked, so the RFC 9887 listener keeps it in force at the next
// Accept, before any TLS byte, rather than dropping it because the device
// is still admitted. Nothing at Accept can tell the status is back without
// the handshake the window exists to spare, so an outage costs each device
// at most one full handshake per window.
func (l *Limiter) DeclineStatus(src netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.countLocked(l.declined, src)
	f := l.declined[src]
	f.status = true
	l.declined[src] = f
}

// DeclinedForStatus reports whether src is inside a window DeclineStatus
// opened last.
func (l *Limiter) DeclinedForStatus(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inWindowLocked(l.declined, src) && l.declined[src].status
}

// Declined reports whether src is inside the window its last decline opened.
// The caller refuses the connection only while port49d still declines src,
// and otherwise calls Undecline: a window never outlasts its reason.
func (l *Limiter) Declined(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inWindowLocked(l.declined, src)
}

// Undecline drops src's decline window and count, for a source port49d no
// longer declines: a reload admitted it again, or its quarantine ended.
func (l *Limiter) Undecline(src netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.declined, src)
}

// countLocked counts one more event from src in m and returns the count,
// which starts over once MalformedWindow has passed with none.
func (l *Limiter) countLocked(m map[netip.Addr]failure, src netip.Addr) int {
	f := m[src]
	now := l.now()
	if l.cfg.MalformedWindow > 0 && now.Sub(f.last) > l.cfg.MalformedWindow {
		f.count = 0
	}
	f.count++
	f.last = now
	m[src] = f
	l.writes++
	if l.writes%1024 == 0 {
		l.sweepLocked(now)
	}
	return f.count
}

// inWindowLocked reports whether src's last event in m is younger than the
// backoff its count earns.
func (l *Limiter) inWindowLocked(m map[netip.Addr]failure, src netip.Addr) bool {
	f, ok := m[src]
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
	// Delete malformed-strike and decline entries older than MalformedWindow.
	if l.cfg.MalformedWindow > 0 {
		for _, m := range []map[netip.Addr]failure{l.bad, l.declined} {
			for src, f := range m {
				if now.Sub(f.last) > l.cfg.MalformedWindow {
					delete(m, src)
				}
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
