package etcd

import (
	"context"
	"errors"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// errNotBuilt is a method plan 7d builds in a later task. No production
// path reaches this package before Task 12, and this file is gone by
// Task 8.
var errNotBuilt = errors.New("etcd: not built yet (plan 7d)")

func (s *Store) PutContext(context.Context, store.ContextKey, store.Context, time.Duration) error {
	return errNotBuilt
}

func (s *Store) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	return store.Context{}, errNotBuilt
}

func (s *Store) SwapContext(context.Context, store.ContextKey, uint64, store.Context, time.Duration) error {
	return errNotBuilt
}

func (s *Store) SwapLogin(context.Context, store.ContextKey, uint64, store.Context, time.Duration, store.LoginWrite) error {
	return errNotBuilt
}

func (s *Store) RewriteContext(context.Context, store.ContextKey, uint64, store.Context, time.Duration, bool) error {
	return errNotBuilt
}

func (s *Store) TouchContext(context.Context, store.ContextKey, time.Duration) error {
	return errNotBuilt
}

func (s *Store) SetPrivilege(context.Context, store.ContextKey, uint8) error { return errNotBuilt }

func (s *Store) AnnotateContext(context.Context, store.ContextKey, string, string) error {
	return errNotBuilt
}

func (s *Store) RefreshContext(context.Context, store.ContextKey, store.ContextRefresh, time.Duration) error {
	return errNotBuilt
}

func (s *Store) SetRevokedAt(context.Context, store.ContextKey, time.Time) error { return errNotBuilt }

func (s *Store) SetContextPolicy(context.Context, store.ContextKey, uint64, store.ContextPolicy) error {
	return errNotBuilt
}

func (s *Store) DeleteContext(context.Context, store.ContextKey) error { return errNotBuilt }

func (s *Store) DeleteContextIf(context.Context, store.ContextKey, uint64) error { return errNotBuilt }

func (s *Store) PutBlob(context.Context, string, []byte, time.Duration) error { return errNotBuilt }

func (s *Store) GetBlob(context.Context, string) ([]byte, error) { return nil, errNotBuilt }

func (s *Store) BumpBlob(context.Context, string, time.Duration) error { return errNotBuilt }

func (s *Store) IndexContext(context.Context, string, string, string, store.ContextRef, time.Duration) error {
	return errNotBuilt
}

func (s *Store) UnindexContext(context.Context, string, string, string, store.ContextRef) error {
	return errNotBuilt
}

func (s *Store) UnindexRef(context.Context, store.ContextRef) error { return errNotBuilt }

func (s *Store) ContextsByPrincipal(context.Context, string) ([]store.ContextRef, error) {
	return nil, errNotBuilt
}

func (s *Store) ContextsBySid(context.Context, string) ([]store.ContextRef, error) {
	return nil, errNotBuilt
}

func (s *Store) ContextsByCert(context.Context, string) ([]store.ContextRef, error) {
	return nil, errNotBuilt
}

func (s *Store) ReindexSid(context.Context, string, string, store.ContextRef, time.Duration) error {
	return errNotBuilt
}

func (s *Store) ActivePrincipals(context.Context) ([]string, error) { return nil, errNotBuilt }

func (s *Store) ReserveIdempotency(context.Context, string, string, store.Idempotency) (store.Idempotency, bool, error) {
	return store.Idempotency{}, false, errNotBuilt
}

func (s *Store) CompleteIdempotency(context.Context, string, string, string, store.Idempotency) error {
	return errNotBuilt
}

func (s *Store) ReleaseIdempotency(context.Context, string, string, string) error { return errNotBuilt }

var _ store.Store = (*Store)(nil)
