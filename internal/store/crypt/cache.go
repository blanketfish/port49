package crypt

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/store"
)

// DefaultCacheMax is a cache's Max when none is set (spec §13, decision 37).
const DefaultCacheMax = 65536

// CacheConfig is a context cache's bounds and its witnesses (plan 7f;
// design §12; spec §13, decision 37).
type CacheConfig struct {
	TTL     time.Duration          // a hit is an entry younger than this
	Max     int                    // past it the cache is cleared
	IdleTTL time.Duration          // the context's own idle TTL: no stale serve past LastTouchedAt + it
	Now     func() time.Time       // time.Now when nil
	Lookups *prometheus.CounterVec // outcome: hit, miss, stale; nil counts nothing
	Entries prometheus.Gauge       // nil gauges nothing
	Stale   func(err error)        // told at each stale serve, with the store's error; nil tells no one
	Fresh   func()                 // told at each read the store answered; nil tells no one
}

// Cached is inner, port49d's sealed daemon store, with GetContext answered
// from a per-replica read-through cache (design §12), for command and
// session authorization alone: a login, an enable, accounting and a token
// redemption never read through it.
//
// A hit is an entry younger than TTL, read while the context feed is up,
// whose revision the ledger still knows as the latest at its key. An
// entry is evicted by a write through this cache, by every change the
// feed brings (Ledger.changed), by a rescan (Ledger.rescanned) and by not
// found; a read that raced any eviction is not cached (gen).
//
// A read that fails store.ErrUnavailable is answered from an entry the
// ledger still knows, within the context's idle TTL: counted stale and
// told. Revocation does not reach it then (design §12: documented, not
// discovered), until a read lands or port49d's listeners close. Never when
// the failure is ErrFeedBehind: Fenced waits only for a record whose
// revision differs from the ledger's, so a fence timeout means etcd
// answered with a later record than the entry, perhaps a revocation. That
// is not an outage: the entry is evicted and the read denied.
//
// A hit hands out a copy, so a caller that edits the SessionDiscriminators
// slice cannot corrupt the entry.
func Cached(inner store.Store, l *Ledger, cfg CacheConfig) store.Store {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Max <= 0 {
		cfg.Max = DefaultCacheMax
	}
	c := &cache{Store: inner, l: l, cfg: cfg, m: map[store.ContextKey]cacheEntry{}}
	l.attach(c)
	return c
}

type cacheEntry struct {
	c  store.Context
	at time.Time
}

type cache struct {
	store.Store
	l   *Ledger
	cfg CacheConfig
	mu  sync.Mutex
	m   map[store.ContextKey]cacheEntry
	gen uint64 // moved by every eviction; a read is cached only if it did not move meanwhile
}

func (c *cache) count(outcome string) {
	if c.cfg.Lookups != nil {
		c.cfg.Lookups.WithLabelValues(outcome).Inc()
	}
}

func (c *cache) gauge() { // under c.mu
	if c.cfg.Entries != nil {
		c.cfg.Entries.Set(float64(len(c.m)))
	}
}

func (c *cache) evictKey(k store.ContextKey) {
	c.mu.Lock()
	delete(c.m, k)
	c.gen++
	c.gauge()
	c.mu.Unlock()
}

func (c *cache) clearAll() {
	c.mu.Lock()
	clear(c.m)
	c.gen++
	c.gauge()
	c.mu.Unlock()
}

func (c *cache) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	now := c.cfg.Now()
	c.mu.Lock()
	e, ok := c.m[k]
	gen := c.gen
	c.mu.Unlock()
	if ok && now.Sub(e.at) < c.cfg.TTL && c.l.Fence().Up() && !c.l.Fence().Behind() && c.l.knownAt(k, e.c.Rev) {
		c.count("hit")
		return cloned(e.c), nil
	}
	got, err := c.Store.GetContext(ctx, k)
	if err == nil {
		c.count("miss")
		c.mu.Lock()
		if c.gen == gen && c.l.knownAt(k, got.Rev) {
			if len(c.m) >= c.cfg.Max {
				clear(c.m)
			}
			c.m[k] = cacheEntry{c: cloned(got), at: now}
			c.gauge()
		}
		c.mu.Unlock()
		if c.cfg.Fresh != nil {
			c.cfg.Fresh()
		}
		return got, nil
	}
	// A fence timeout is the store answering with a later record than the
	// entry (plan 7f, I-2): not an outage, so never stale, and the entry is
	// superseded.
	behind := errors.Is(err, ErrFeedBehind)
	if ok && errors.Is(err, store.ErrUnavailable) && !behind && c.cfg.TTL > 0 && !c.l.Fence().Behind() && c.l.knownAt(k, e.c.Rev) && c.withinIdle(e.c, now) {
		c.count("stale")
		if c.cfg.Stale != nil {
			c.cfg.Stale(err)
		}
		return cloned(e.c), nil
	}
	c.count("miss")
	if !errors.Is(err, store.ErrUnavailable) || behind {
		c.evictKey(k) // not found, a record that will not open, or one the feed is behind: never served again
	}
	return got, err
}

// cloned is ct with its SessionDiscriminators slice copied: store.Context is
// handed out by value, but that slice is shared with whoever holds the other
// copy.
func cloned(ct store.Context) store.Context {
	ct.SessionDiscriminators = slices.Clone(ct.SessionDiscriminators)
	return ct
}

// withinIdle reports whether the context's own idle TTL, from its last
// touch, has not passed: the store would have reclaimed it then.
func (c *cache) withinIdle(ct store.Context, now time.Time) bool {
	from := ct.LastTouchedAt
	if from.IsZero() {
		from = ct.CreatedAt
	}
	return now.Before(from.Add(c.cfg.IdleTTL))
}

// Every write at a key evicts it once the write returns, whatever it
// returned: the next read is the store's.

func (c *cache) PutContext(ctx context.Context, k store.ContextKey, ct store.Context, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.PutContext(ctx, k, ct, ttl)
}

func (c *cache) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, ct store.Context, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.SwapContext(ctx, k, rev, ct, ttl)
}

func (c *cache) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, ct store.Context, ttl time.Duration, w store.LoginWrite) error {
	defer c.evictKey(k)
	return c.Store.SwapLogin(ctx, k, rev, ct, ttl, w)
}

func (c *cache) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, ct store.Context, ttl time.Duration, policyMoved bool) error {
	defer c.evictKey(k)
	return c.Store.RewriteContext(ctx, k, rev, ct, ttl, policyMoved)
}

func (c *cache) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.TouchContext(ctx, k, ttl)
}

func (c *cache) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	defer c.evictKey(k)
	return c.Store.SetPrivilege(ctx, k, level)
}

func (c *cache) AnnotateContext(ctx context.Context, k store.ContextKey, discHash string, state string) error {
	defer c.evictKey(k)
	return c.Store.AnnotateContext(ctx, k, discHash, state)
}

func (c *cache) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.RefreshContext(ctx, k, r, ttl)
}

func (c *cache) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	defer c.evictKey(k)
	return c.Store.SetRevokedAt(ctx, k, at)
}

func (c *cache) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	defer c.evictKey(k)
	return c.Store.SetContextPolicy(ctx, k, policyRev, p)
}

func (c *cache) DeleteContext(ctx context.Context, k store.ContextKey) error {
	defer c.evictKey(k)
	return c.Store.DeleteContext(ctx, k)
}

func (c *cache) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	defer c.evictKey(k)
	return c.Store.DeleteContextIf(ctx, k, rev)
}

var _ store.Store = (*cache)(nil)
