package port49d

import (
	"context"
	"fmt"
	"sync/atomic"

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

func (h *dirHandle) DeleteRevocation(ctx context.Context, kind, key string) error {
	if s := h.get(); s != nil {
		return s.DeleteRevocation(ctx, kind, key)
	}
	return errNoDirectory
}

func (h *dirHandle) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
	if s := h.get(); s != nil {
		return s.ListRevocations(ctx)
	}
	return nil, errNoDirectory
}
