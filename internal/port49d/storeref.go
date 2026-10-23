package port49d

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// storeRef is one of port49's two stores as a process opens it (plan 11a;
// decision 51): the config path its lines name, its resolved block, the
// scope its roles are checked against, and whether it is the directory
// store of its own.
type storeRef struct {
	at    string
	cfg   config.StoreConfig
	scope etcdstore.Scope
	dir   bool
}

// sessionRef is the store that serves sessions: the one store when shared.
func sessionRef(cfg config.Config) storeRef {
	scope := etcdstore.ScopeShared
	if !cfg.Stores.Shared {
		scope = etcdstore.ScopeSession
	}
	return storeRef{at: cfg.Stores.SessionPath(), cfg: cfg.Stores.Session, scope: scope}
}

// directoryRef is the directory store of its own, which only a split opens.
func directoryRef(cfg config.Config) storeRef {
	return storeRef{at: "stores.directory", cfg: cfg.Stores.Directory, scope: etcdstore.ScopeDirectory, dir: true}
}

// certLabel is the component label of name's identity on this store in
// port49_store_client_cert_expiry_timestamp_seconds: "daemon" or "broker",
// with "_directory" after it on a directory store of its own.
func (r storeRef) certLabel(name string) string {
	if r.dir {
		return name + "_directory"
	}
	return name
}

// what names the store in a line: "store", or "directory store".
func (r storeRef) what() string {
	if r.dir {
		return "directory store"
	}
	return "store"
}

// where names the store's etcd in a line: its endpoints and its prefix.
func (r storeRef) where() string {
	return "etcd " + strings.Join(r.cfg.Etcd.Endpoints, ", ") + ", prefix " + r.cfg.Etcd.Prefix
}

// recordKey is the absolute name of the store's meta/seal_keys record.
func (r storeRef) recordKey() string {
	return strings.TrimSuffix(r.cfg.Etcd.Prefix, "/") + "/v1/meta/seal_keys"
}

// dirHandle is the directory store's raw handle as a process holds it: the
// session store's in a shared store, and absent until it first answers on a
// port49d run that serves from the marks it holds (R19). As a
// placement.Directory an absent handle does not answer.
type dirHandle struct {
	p atomic.Pointer[etcdstore.Store]
}

func (h *dirHandle) set(s *etcdstore.Store) { h.p.Store(s) }
func (h *dirHandle) get() *etcdstore.Store  { return h.p.Load() }

// close closes the handle it holds. A shared store's handle is the session
// store's, closed with it: never call close on one.
func (h *dirHandle) close() {
	if s := h.p.Swap(nil); s != nil {
		s.Close()
	}
}

// errNoDirectory is a directory store this run has not opened yet.
var errNoDirectory = fmt.Errorf("%w: the directory store has not answered since this run began", store.ErrUnavailable)

func (h *dirHandle) PutRevocation(ctx context.Context, r store.Revocation) error {
	if s := h.get(); s != nil {
		return s.PutRevocation(ctx, r)
	}
	return errNoDirectory
}

func (h *dirHandle) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if s := h.get(); s != nil {
		return s.GetRevocation(ctx, kind, key)
	}
	return store.Revocation{}, errNoDirectory
}

func (h *dirHandle) DeleteRevocation(ctx context.Context, kind, key string, by store.Lift) error {
	if s := h.get(); s != nil {
		return s.DeleteRevocation(ctx, kind, key, by)
	}
	return errNoDirectory
}

func (h *dirHandle) GetLift(ctx context.Context, kind, key string) (store.Lift, error) {
	if s := h.get(); s != nil {
		return s.GetLift(ctx, kind, key)
	}
	return store.Lift{}, errNoDirectory
}

func (h *dirHandle) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
	if s := h.get(); s != nil {
		return s.ListRevocations(ctx)
	}
	return nil, errNoDirectory
}

// PutLogout writes a logout to the directory (placement.Config.LogoutDir).
func (h *dirHandle) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	if s := h.get(); s != nil {
		return s.PutLogout(ctx, l, ttl)
	}
	return errNoDirectory
}

// lazyMembers is the directory's membership half over a handle that may
// open after the start (R19), sealed as the session store's: the sealing
// layer is made at the first call that finds the handle open.
type lazyMembers struct {
	h    *dirHandle
	wrap func(*etcdstore.Store) store.Store
	mu   sync.Mutex
	of   *etcdstore.Store
	m    store.Store
}

func (l *lazyMembers) get() (store.Store, error) {
	s := l.h.get()
	if s == nil {
		return nil, errNoDirectory
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.of != s {
		l.of, l.m = s, l.wrap(s)
	}
	return l.m, nil
}

func (l *lazyMembers) PutPin(ctx context.Context, m store.Membership, expect store.PinExpect) error {
	s, err := l.get()
	if err != nil {
		return err
	}
	return s.PutPin(ctx, m, expect)
}

func (l *lazyMembers) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	s, err := l.get()
	if err != nil {
		return store.Membership{}, err
	}
	return s.GetMembership(ctx, p)
}

func (l *lazyMembers) MembershipByKey(ctx context.Context, k string) (store.Membership, error) {
	s, err := l.get()
	if err != nil {
		return store.Membership{}, err
	}
	return s.MembershipByKey(ctx, k)
}

func (l *lazyMembers) RefuseMapKeys(ctx context.Context, ks []string, at time.Time, ttl time.Duration) error {
	s, err := l.get()
	if err != nil {
		return err
	}
	return s.RefuseMapKeys(ctx, ks, at, ttl)
}

func (l *lazyMembers) DeleteMembership(ctx context.Context, p string) (store.Membership, error) {
	s, err := l.get()
	if err != nil {
		return store.Membership{}, err
	}
	return s.DeleteMembership(ctx, p)
}
