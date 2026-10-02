package store

import (
	"sync"
	"time"
)

// Marks is the daemon's copy of the standing revocation marks (plan 7d;
// spec §13, decision 35). The store is the authority: port49d loads every
// mark from it at start, before any listener binds, and the broker adds a
// mark before its write is sent, keeping it unless the store refused the
// write, and removes one once its lift has. The
// authorizer, the enable gate and a receipt's replay read it on every
// request, so a context its principal or certificate names is denied
// whatever the record says: a record put back from before the revocation,
// or a context a revocation never reached (a start that kept it). It has
// no minted-after exception, unlike CarryRevocation: a mint reads the
// marks first and after its last write and deletes what it wrote if one
// appeared (decision 32), so no live token was minted after a standing
// mark. A nil *Marks names nothing. It is safe for concurrent use.
type Marks struct {
	mu sync.RWMutex
	m  map[[2]string]time.Time
}

// NewMarks is an empty set: no mark stands.
func NewMarks() *Marks { return &Marks{m: map[[2]string]time.Time{}} }

// Set puts r in force, or lifts it when on is false. A mark already in
// force keeps its first time, as PutRevocation keeps it.
func (m *Marks) Set(r Revocation, on bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{r.Kind, r.Key}
	if !on {
		delete(m.m, k)
		return
	}
	if _, ok := m.m[k]; !ok {
		m.m[k] = r.At
	}
}

// Put puts r in force at r.At, replacing the time of a mark already in
// force: the broker's correction once the store says which mark stands.
func (m *Marks) Put(r Revocation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[[2]string{r.Kind, r.Key}] = r.At
}

// Holds reports whether a mark for (kind, key) is in force.
func (m *Marks) Holds(kind, key string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.m[[2]string{kind, key}]
	return ok
}

// RevokedAt is when c stands revoked: the later of its own RevokedAt and
// a mark standing for its principal or its certificate (CertKey of its
// credential; a blank key names no certificate). Zero when neither.
func (m *Marks) RevokedAt(c Context) time.Time {
	return later(c.RevokedAt, m.Standing(c.Principal, CertKey(c.Credential.Issuer, c.Credential.Serial)))
}

// Standing is the later of the marks standing for principal and for
// certKey, zero when neither stands. An empty principal or a blank
// certificate key names nothing. A receipt's replay asks it of the
// credential presented, which a context need not name (plan 7d).
func (m *Marks) Standing(principal, certKey string) time.Time {
	var at time.Time
	if m == nil {
		return at
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.m[[2]string{RevocationPrincipal, principal}]; ok && principal != "" {
		at = later(at, t)
	}
	if !BlankCertKey(certKey) {
		if t, ok := m.m[[2]string{RevocationCert, certKey}]; ok {
			at = later(at, t)
		}
	}
	return at
}

// Len is how many marks stand.
func (m *Marks) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.m)
}
