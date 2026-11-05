package broker

import (
	"context"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

func (h hookStore) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	if f := h.before["RefreshContext"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.RefreshContext(ctx, k, r, ttl)
}

func (h hookStore) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	if f := h.before["GetLogout"]; f != nil {
		if err := f(); err != nil {
			return store.Logout{}, err
		}
	}
	return h.Store.GetLogout(ctx, key)
}

func (h hookStore) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
	if f := h.before["SetContextPolicy"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.SetContextPolicy(ctx, k, rev, p)
}
