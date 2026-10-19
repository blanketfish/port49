package port49d

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// roleStatus is one store's line of port49 store status (plan 11a, R21).
type roleStatus struct {
	role, backend     string
	shares            bool // the session store is the directory store
	answering, listed int
	membersErr        bool
	reachable         bool
	why               string
	cache, aged       bool // a directory line carries a cache age; aged: it was ever confirmed
	snapshot          bool // the cache is a snapshot this run started from, not yet confirmed live (R19)
	age               time.Duration
	pending           int      // back-channel logouts not yet forwarded to the directory (R26)
	down              []string // the directory feeds not running: the cache is not confirmed meanwhile
}

// line is s as the CLI prints it.
func (s roleStatus) line() string {
	switch {
	case s.shares:
		return fmt.Sprintf("%-9s  shares the directory store", s.role)
	case s.backend == config.BackendMemory:
		return fmt.Sprintf("%-9s  %-6s  in process", s.role, s.backend)
	}
	members := fmt.Sprintf("%d/%d members", s.answering, s.listed)
	if s.membersErr {
		members = "?/? members"
	}
	reach := "reachable"
	if !s.reachable {
		reach = "unreachable"
	}
	l := fmt.Sprintf("%-9s  %-6s  %-11s  %s", s.role, s.backend, members, reach)
	if s.cache {
		age := "none"
		if s.aged {
			age = ageText(s.age)
		}
		if s.snapshot {
			age += " (snapshot)"
		}
		l += "  cache " + age
		if len(s.down) > 0 {
			l += "  feeds down: " + strings.Join(s.down, ", ")
		}
	}
	if s.pending > 0 {
		l += fmt.Sprintf("  %d logouts pending", s.pending)
	}
	if s.why != "" && (!s.reachable || s.membersErr) {
		l += "\n           " + printsafe.Line(s.why, 300)
	}
	return l
}

// storeStatus is what port49 store status reads in a process: the
// directory store's handle and the session store's (nil on memory), and the
// directory cache's freshness.
type storeStatus struct {
	backend                 string
	shared                  bool
	dir                     *dirHandle
	session                 *etcdstore.Store
	fresh                   *store.Freshness
	dirTimeout, sessTimeout time.Duration
	// pending is the count of logouts this region has not yet forwarded
	// (port49-broker's); nil on port49d, which ingests none.
	pending func() int
}

func newStoreStatus(cfg config.Config, dir *dirHandle, session *etcdstore.Store, fresh *store.Freshness) *storeStatus {
	s := &storeStatus{backend: cfg.Stores.Session.Backend, shared: cfg.Stores.Shared, dir: dir, session: session,
		fresh: fresh}
	if e := cfg.Stores.Directory.Etcd; e != nil {
		s.dirTimeout = e.CallTimeout
	}
	if e := cfg.Stores.Session.Etcd; e != nil {
		s.sessTimeout = e.CallTimeout
	}
	return s
}

// answer reads each store now, each read within its call_timeout, and
// answers the lines and whether a store did not answer.
func (s *storeStatus) answer(ctx context.Context) (string, bool, error) {
	if s == nil || s.backend == config.BackendMemory {
		return roleStatus{role: "directory", backend: config.BackendMemory}.line() + "\n" +
			roleStatus{role: "session", shares: true}.line(), false, nil
	}
	// Both stores at once, so a partition that takes out both costs the
	// larger call_timeout's reads, not the sum.
	var ss roleStatus
	var wg sync.WaitGroup
	if !s.shared {
		wg.Add(1)
		go func() { defer wg.Done(); ss = s.read(ctx, "session", s.session, s.sessTimeout) }()
	}
	d := s.read(ctx, "directory", s.dir.get(), s.dirTimeout)
	wg.Wait()
	d.cache = true
	d.age, d.aged = s.fresh.Age()
	d.snapshot = s.fresh.Snapshot()
	d.down = s.fresh.Down()
	if s.pending != nil {
		d.pending = s.pending()
	}
	lines, degraded := []string{d.line()}, !d.reachable
	if s.shared {
		lines = append(lines, roleStatus{role: "session", shares: true}.line())
	} else {
		lines, degraded = append(lines, ss.line()), degraded || !ss.reachable
	}
	return strings.Join(lines, "\n"), degraded, nil
}

// read is role's line from h: a linearizable read for reachability beside
// the members.
func (s *storeStatus) read(ctx context.Context, role string, h *etcdstore.Store, timeout time.Duration) roleStatus {
	r := roleStatus{role: role, backend: config.BackendEtcd}
	if h == nil {
		r.membersErr, r.why = true, errNoDirectory.Error()
		return r
	}
	// The ping and the member count at once: the count is a member list and
	// then a status read, each within timeout.
	var perr, merr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		perr = h.Ping(cctx)
	}()
	mctx, mcancel := context.WithTimeout(ctx, 2*timeout)
	r.answering, r.listed, merr = h.Members(mctx, timeout)
	mcancel()
	wg.Wait()
	r.membersErr = merr != nil
	r.reachable = perr == nil
	switch {
	case perr != nil:
		r.why = perr.Error()
	case merr != nil:
		r.why = merr.Error()
	}
	return r
}
