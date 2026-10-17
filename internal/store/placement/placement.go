// Package placement is the fixed placement of records between port49's
// two stores (plan 11a; spec §13 decision 51): a store.Store over the
// session store whose revocation marks are the directory store's, and whose
// read of a mark is the process's copy of them.
//
// It is used where the two stores are two: a shared store keeps decision
// 35's atomic login check, and no router.
package placement

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// Directory is the directory store's revocation half, as the router writes,
// lists, and with no copy reads it.
type Directory interface {
	PutRevocation(ctx context.Context, r store.Revocation) error
	GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error)
	DeleteRevocation(ctx context.Context, kind, key string) error
	ListRevocations(ctx context.Context) ([]store.Revocation, error)
}

// Config is Wrap's.
type Config struct {
	// Session is the session store, sealed and guarded: every method but
	// the revocations'.
	Session store.Store
	// Directory is where the marks are written and listed.
	Directory Directory
	// Marks is the process's copy of the directory's marks, which
	// GetRevocation answers from. Nil reads Directory: the offline
	// revocation, which follows no feed.
	Marks *store.Marks
	// CallTimeout bounds each put, delete and read of Directory, and
	// BulkTimeout its list: a directory that does not answer within one is
	// store.ErrUnavailable. Zero is 500ms and 30s.
	CallTimeout, BulkTimeout time.Duration
}

type placed struct {
	store.Store
	c Config
}

// Wrap is c.Session with the revocation marks placed in c.Directory.
func Wrap(c Config) store.Store {
	if c.CallTimeout <= 0 {
		c.CallTimeout = 500 * time.Millisecond
	}
	if c.BulkTimeout <= 0 {
		c.BulkTimeout = 30 * time.Second
	}
	return &placed{Store: c.Session, c: c}
}

func (p *placed) PutRevocation(ctx context.Context, r store.Revocation) error {
	return bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error { return p.c.Directory.PutRevocation(ctx, r) })
}

func (p *placed) DeleteRevocation(ctx context.Context, kind, key string) error {
	return bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
		return p.c.Directory.DeleteRevocation(ctx, kind, key)
	})
}

func (p *placed) ListRevocations(ctx context.Context) (rs []store.Revocation, err error) {
	err = bounded(ctx, p.c.BulkTimeout, func(ctx context.Context) (x error) {
		rs, x = p.c.Directory.ListRevocations(ctx)
		return
	})
	return rs, err
}

// GetRevocation is the copy's mark, or ErrNotFound: a login's and a mint's
// check never waits on the directory (R4). With no copy it reads the
// directory.
func (p *placed) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if p.c.Marks == nil {
		var r store.Revocation
		err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
			r, x = p.c.Directory.GetRevocation(ctx, kind, key)
			return
		})
		return r, err
	}
	if r, ok := p.c.Marks.Get(kind, key); ok {
		return r, nil
	}
	return store.Revocation{}, store.ErrNotFound
}

// SwapLogin compares no mark: the session store holds none, and the marks a
// login read came from the copy, which it has carried into the context
// already (JoinContext; decision 51). Every request is denied by the copy
// whatever the context says.
func (p *placed) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	w store.LoginWrite) error {
	w.Marks = nil
	return p.Store.SwapLogin(ctx, k, rev, c, ttl, w)
}

// bounded runs f under d, and names a directory that did not answer within
// it store.ErrUnavailable; a caller that gave up keeps its own error.
func bounded(ctx context.Context, d time.Duration, f func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	err := f(cctx)
	if err != nil && ctx.Err() == nil && cctx.Err() != nil && !errors.Is(err, store.ErrUnavailable) {
		return fmt.Errorf("%w: the directory store did not answer within %v", store.ErrUnavailable, d)
	}
	return err
}
