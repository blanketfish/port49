package directory

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }
func newClock() *fakeClock               { return &fakeClock{now: time.Unix(1_000_000, 0).UTC()} }

// fakeDir is one directory server's data and behaviour, shared by every
// connection dialled to it. It answers a search by its exact filter
// string: what a test registers is the filter port49 must send, so a test
// asserts the filter as well as what is done with the answer. An
// unregistered filter answers no entries. err, keyed by filter, answers
// that error instead. delay holds every answer; slow, keyed by filter,
// holds that filter's alone. A fakeDir is itself a Searcher with no
// deadline, for the tests of Tasks 8 and 9 that search it directly.
type fakeDir struct {
	mu       sync.Mutex
	byFilter map[string][]*ldap.Entry
	byBase   map[[2]string][]*ldap.Entry // {base DN, filter}: answers a base-scope search per DN
	err      map[string]error
	delay    time.Duration
	slow     map[string]time.Duration
	calls    []*ldap.SearchRequest
}

func newFakeDir() *fakeDir {
	return &fakeDir{byFilter: map[string][]*ldap.Entry{}, byBase: map[[2]string][]*ldap.Entry{}, err: map[string]error{}, slow: map[string]time.Duration{}}
}

func (d *fakeDir) on(filter string, entries ...*ldap.Entry) { d.byFilter[filter] = entries }

// onBase answers a search of exactly base with filter; it wins over on.
func (d *fakeDir) onBase(base, filter string, entries ...*ldap.Entry) {
	d.byBase[[2]string{base, filter}] = entries
}

// search answers req after its delay, or at once with ctx's error when ctx
// ends first (its own search abandoned, as SearchAsync does), or with a
// network error when closed is closed (the connection under it went).
func (d *fakeDir) search(ctx context.Context, closed <-chan struct{}, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	d.mu.Lock()
	d.calls = append(d.calls, req)
	delay := d.delay
	if s, ok := d.slow[req.Filter]; ok {
		delay = s
	}
	e, es := d.err[req.Filter], d.byFilter[req.Filter]
	if b, ok := d.byBase[[2]string{req.BaseDN, req.Filter}]; ok {
		es = b
	}
	d.mu.Unlock()
	// A closed connection answers nothing, even with no delay to lose the
	// select's race to.
	select {
	case <-closed:
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed"))
	default:
	}
	select {
	case <-closed:
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed"))
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(delay):
	}
	if e != nil {
		return nil, e
	}
	if req.SizeLimit > 0 && len(es) > req.SizeLimit {
		return &ldap.SearchResult{Entries: es[:req.SizeLimit]}, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit"))
	}
	return &ldap.SearchResult{Entries: es}, nil
}

func (d *fakeDir) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return d.search(context.Background(), nil, req)
}

func (d *fakeDir) SearchWithPaging(req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	return d.Search(req)
}

// fakeConn is one dialled connection to a fakeDir, with its own close, so
// a test sees what closing one connection does to the searches on it.
type fakeConn struct {
	d      *fakeDir
	closed chan struct{}
	once   sync.Once
}

func (c *fakeConn) SearchContext(ctx context.Context, req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	return c.d.search(ctx, c.closed, req)
}

func (c *fakeConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// entry builds an entry from attribute pairs.
func entry(dn string, attrs map[string][]string) *ldap.Entry {
	return ldap.NewEntry(dn, attrs)
}

// fakeServers is a Dialer over per-URI behaviour: down refuses the dial
// with a network error, refuse[uri] refuses the bind with that error,
// dirs[uri] is the server a dial reaches, and each dial is a fresh
// fakeConn to it (pre-flight I-3), kept in conns. dialDelay holds each
// dial, so concurrent queries race to dial.
type fakeServers struct {
	mu        sync.Mutex
	dirs      map[string]*fakeDir
	down      map[string]bool
	refuse    map[string]error
	dials     map[string]int
	conns     map[string][]*fakeConn
	dialDelay time.Duration
}

func newFakeServers(uris ...string) *fakeServers {
	f := &fakeServers{dirs: map[string]*fakeDir{}, down: map[string]bool{}, refuse: map[string]error{},
		dials: map[string]int{}, conns: map[string][]*fakeConn{}}
	for _, u := range uris {
		f.dirs[u] = newFakeDir()
	}
	return f
}

func (f *fakeServers) dial(ctx context.Context, s Server) (Client, error) {
	f.mu.Lock()
	f.dials[s.URI]++
	down, refuse, delay := f.down[s.URI], f.refuse[s.URI], f.dialDelay
	f.mu.Unlock()
	time.Sleep(delay)
	switch {
	case down:
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("dial tcp: connection refused"))
	case refuse != nil:
		return nil, refuse
	}
	c := &fakeConn{d: f.dirs[s.URI], closed: make(chan struct{})}
	f.mu.Lock()
	f.conns[s.URI] = append(f.conns[s.URI], c)
	f.mu.Unlock()
	return c, nil
}

// open is how many of uri's dialled connections are not closed.
func (f *fakeServers) open(uri string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.conns[uri] {
		if !c.isClosed() {
			n++
		}
	}
	return n
}

func (f *fakeServers) setRefuse(uri string, err error) {
	f.mu.Lock()
	f.refuse[uri] = err
	f.mu.Unlock()
}

func (f *fakeServers) setDown(uri string, down bool) { f.mu.Lock(); f.down[uri] = down; f.mu.Unlock() }

// closeAll closes every connection dialled to uri, as a server going away
// or dropping its clients does.
func (f *fakeServers) closeAll(uri string) {
	f.mu.Lock()
	cs := slices.Clone(f.conns[uri])
	f.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}
