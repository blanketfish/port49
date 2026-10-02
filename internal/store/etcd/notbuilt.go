package etcd

import (
	"context"
	"errors"

	"github.com/rhwendt/port49/internal/store"
)

// errNotBuilt is a method plan 7d builds in a later task. No production
// path reaches this package before Task 12, and this file is gone by
// Task 8.
var errNotBuilt = errors.New("etcd: not built yet (plan 7d)")

func (s *Store) ContextsByPrincipal(context.Context, string) ([]store.ContextRef, error) {
	return nil, errNotBuilt
}

func (s *Store) ContextsBySid(context.Context, string) ([]store.ContextRef, error) {
	return nil, errNotBuilt
}

func (s *Store) ContextsByCert(context.Context, string) ([]store.ContextRef, error) {
	return nil, errNotBuilt
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
