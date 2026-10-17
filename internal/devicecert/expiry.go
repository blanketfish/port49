package devicecert

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
)

// seenWindow is how long a device's last verified certificate counts
// toward the least lifetime left: a device not seen for a day may be gone.
const seenWindow = 24 * time.Hour

// LifetimeLeft is the fraction of c's own lifetime (NotAfter - NotBefore)
// still to run at now: 1 when just issued, 0 at expiry, below 0 after.
func LifetimeLeft(c *x509.Certificate, now time.Time) float64 {
	life := c.NotAfter.Sub(c.NotBefore)
	if life <= 0 {
		return 0
	}
	return float64(c.NotAfter.Sub(now)) / float64(life)
}

// Expiry remembers each device's last verified certificate, for
// tls_listener.expiry_warning_fraction's line and
// port49_tls_device_certificate_lifetime_left_ratio (decision 50 ruling 16).
// It judges by the fraction of a certificate's own lifetime left, never a
// fixed duration: a duration sits forever inside a short-lived
// certificate's life and would name every device every day. Renewal by
// ACME or cert-manager happens at two thirds by default, so a certificate
// in its last third is one whose renewal is late.
type Expiry struct {
	Fraction float64 // warn below this fraction left; 0 is off
	Say      func(format string, args ...any)

	mu   sync.Mutex
	seen map[string]seenCert
}

type seenCert struct {
	cert       *x509.Certificate
	at, warned time.Time
}

// Seen notes leaf as device's at now, and says once a day while it has
// less than Fraction of its lifetime left.
func (e *Expiry) Seen(device string, leaf *x509.Certificate, now time.Time) {
	left := LifetimeLeft(leaf, now)
	e.mu.Lock()
	if e.seen == nil {
		e.seen = map[string]seenCert{}
	}
	s := e.seen[device]
	s.cert, s.at = leaf, now
	warn := e.Fraction > 0 && left < e.Fraction && now.Sub(s.warned) >= seenWindow
	if warn {
		s.warned = now
	}
	e.seen[device] = s
	e.mu.Unlock()
	if warn && e.Say != nil {
		e.Say("tls_listener: %s's certificate (serial %s, issuer %s) expires %s, in %s, with %.0f%% of its "+
			"%s lifetime left: its renewal is late; renew it before then",
			device, leaf.SerialNumber.Text(16), printsafe.Line(leaf.Issuer.String(), 200),
			leaf.NotAfter.UTC().Format(time.RFC3339), leaf.NotAfter.Sub(now).Round(time.Minute), left*100,
			leaf.NotAfter.Sub(leaf.NotBefore).Round(time.Hour))
	}
}

// LeastLeft is the least lifetime fraction left among certificates seen in
// the last 24h, and whether there was one. Older entries are dropped.
func (e *Expiry) LeastLeft(now time.Time) (float64, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var least float64
	found := false
	for name, s := range e.seen {
		if now.Sub(s.at) > seenWindow {
			delete(e.seen, name)
			continue
		}
		if f := LifetimeLeft(s.cert, now); !found || f < least {
			least, found = f, true
		}
	}
	return least, found
}
