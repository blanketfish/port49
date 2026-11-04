package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
)

// contextKeyOf is the ContextKey of a c/ key, false for one that does not
// parse.
func (s *Store) contextKeyOf(key string) (store.ContextKey, bool) {
	nas, user, ok := lastTwo(key)
	k := store.ContextKey{NAS: nas, Username: user}
	return k, ok && s.k.context(k) == key
}

// ScanContexts calls fn for every live context at one revision, read a
// page at a time on the context client (ctxKV, so Seen sees each page),
// every page at the first page's revision, and returns it
// (store.ContextFeed). A key that does not parse, or a record that does
// not decode, is said by its key alone and skipped: it raises nothing, and
// a read of it is unreadable anyway.
func (s *Store) ScanContexts(ctx context.Context, fn func(store.ContextKey, store.Context)) (uint64, error) {
	prefix := s.k.family(famContext)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from, rev := prefix, int64(0)
	now := s.now()
	for {
		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(500)}
		if rev > 0 {
			opts = append(opts, clientv3.WithRev(rev))
		}
		resp, err := s.ctxKV.Get(ctx, from, opts...)
		if errors.Is(err, rpctypes.ErrCompacted) {
			return 0, store.ErrCompacted
		}
		if err != nil {
			return 0, unavailable(err)
		}
		if rev == 0 {
			rev = resp.Header.Revision
		}
		for _, kv := range resp.Kvs {
			k, ok := s.contextKeyOf(string(kv.Key))
			if !ok {
				s.unparseable("context key", kv.Key, "skipped by the scan")
				continue
			}
			var r ctxRec
			if json.Unmarshal(kv.Value, &r) != nil {
				s.logf("etcd: the context at %q does not decode; the scan skipped it", kv.Key)
				continue
			}
			if r.ExpiresAt.After(now) {
				fn(k, r.context(kv.ModRevision))
			}
		}
		if !resp.More || len(resp.Kvs) == 0 {
			return uint64(rev), nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// probeCtx and probeTok are a one-key read on the context and token clients:
// answered while the store has a quorum (twoleg.go).
func (s *Store) probeCtx(ctx context.Context) error {
	_, err := s.ctxKV.Get(ctx, s.k.family(famContext), clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly())
	return err
}

func (s *Store) probeTok(ctx context.Context) error {
	_, err := s.tok.Get(ctx, s.k.family(famMark), clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly())
	return err
}

// WatchContexts calls fn for every change to the context family after
// `after` (store.ContextFeed), on the context client, requiring a leader so
// a member cut off from its quorum ends the watch rather than going quiet.
// It asks for etcd's periodic progress notifications (every 10 minutes by
// default, against the 10m compaction retention design §13 prescribes: a resume
// that lands under a compaction is ErrCompacted and rescans), so a quiet
// family's re-watch usually resumes above one (final review 7e-1 I-1).
// It runs as two legs on two members (twoleg.go), so a member gone dark
// leaves the feed following. A request on asks is sent with RequestProgress on
// each leg's own context, which names its stream: etcd answers it with a progress
// notification once the stream's watchers are synced, and that header
// revision is told to progress. An event batch tells progress its highest
// event's revision, never the batch header's, which a catching-up watcher
// may send ahead of what it has delivered. Every response's header
// revision, and every event's, is seen (Seen; Task 6). A watch that fails
// is ErrUnavailable, or ErrRefused when etcd refuses this identity
// (unavailable).
func (s *Store) WatchContexts(ctx context.Context, after uint64, fn func(store.ContextChange),
	progress func(uint64), asks <-chan struct{}) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := s.followLegs(wctx, s.ctx, s.k.family(famContext), after, false, s.probeCtx, asks)
	if err != nil {
		return err
	}
	for resp := range ch {
		s.saw(resp.Header.Revision)
		if err := resp.Err(); err != nil {
			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
				return store.ErrCompacted
			}
			return unavailable(err)
		}
		if resp.IsProgressNotify() {
			progress(uint64(resp.Header.Revision))
			continue
		}
		var top int64
		for _, ev := range resp.Events {
			top = max(top, ev.Kv.ModRevision)
			s.saw(ev.Kv.ModRevision)
			k, ok := s.contextKeyOf(string(ev.Kv.Key))
			if !ok {
				continue
			}
			c := store.ContextChange{Key: k, Rev: uint64(ev.Kv.ModRevision)}
			if ev.Type == clientv3.EventTypeDelete {
				c.Deleted = true
				fn(c)
				continue
			}
			var r ctxRec
			if json.Unmarshal(ev.Kv.Value, &r) != nil {
				// Still told, with no Context: a cache evicts the key, and the
				// ledger cannot open it, so it raises nothing (plan 7f, review M-2).
				s.logf("etcd: a change to the context at %q does not decode; the feed brings it with no body", ev.Kv.Key)
				fn(c)
				continue
			}
			c.Context = r.context(ev.Kv.ModRevision)
			fn(c)
		}
		if top > 0 {
			progress(uint64(top))
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: the context watch ended", store.ErrUnavailable)
}

// markOf is the (kind, key) of an rv/ key, false for one that does not
// parse.
func (s *Store) markOf(key string) (string, string, bool) {
	kind, k, ok := lastTwo(key)
	return kind, k, ok && s.k.mark(kind, k) == key
}

// Revocations is every mark in force at one revision, which it returns
// (store.MarkFeed): ListRevocations read a page at a time on the token
// client, every page at the first page's revision. A mark that does not
// decode stands by the kind and key its etcd key names, as of now, and is
// said by its key, as the watch stands it: an error would fail every
// reload, and leave the marks feed loading again once a second while it
// stands (Ruling T9-e). A key that does not parse names nothing, and is
// said and skipped.
func (s *Store) Revocations(ctx context.Context) (uint64, []store.Revocation, error) {
	prefix := s.k.family(famMark)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from, rev := prefix, int64(0)
	var out []store.Revocation
	for {
		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(500)}
		if rev > 0 {
			opts = append(opts, clientv3.WithRev(rev))
		}
		resp, err := s.tok.Get(ctx, from, opts...)
		if errors.Is(err, rpctypes.ErrCompacted) {
			return 0, nil, store.ErrCompacted
		}
		if err != nil {
			return 0, nil, unavailable(err)
		}
		if rev == 0 {
			rev = resp.Header.Revision
		}
		for _, kv := range resp.Kvs {
			var r markRec
			if json.Unmarshal(kv.Value, &r) != nil {
				kind, key, ok := s.markOf(string(kv.Key))
				if !ok {
					s.logf("etcd: the mark key %q does not parse; the marks load skipped it", kv.Key)
					continue
				}
				s.logf("etcd: the mark at %q does not decode; the marks load stands it as of now", kv.Key)
				r = markRec{Kind: kind, Key: key, At: s.now()}
			}
			out = append(out, r.revocation())
		}
		if !resp.More || len(resp.Kvs) == 0 {
			break
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return uint64(rev), out, nil
}

// WatchRevocations calls fn for every put and lift of a mark after `after`
// (store.MarkFeed), on the token client, requiring a leader as
// WatchContexts does. A put is its record; a lift is the kind and key its
// etcd key names. A put that does not decode stands the mark its key
// names, at the time it was seen, and says so by its key: a revocation
// left out would be one not enforced. Revocations stands it the same
// way. A key that does not parse names nothing, and is said and skipped.
// It runs as two legs on two members (twoleg.go), so a revocation does not
// wait on a member gone dark. A progress notification's header revision is told to progress, as
// WatchContexts asks for and tells them. A watch that fails is
// ErrUnavailable, or ErrRefused when etcd refuses this identity
// (unavailable).
func (s *Store) WatchRevocations(ctx context.Context, after uint64,
	fn func(r store.Revocation, lifted bool, rev uint64), progress func(uint64)) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := s.followLegs(wctx, s.tok, s.k.family(famMark), after, false, s.probeTok, nil)
	if err != nil {
		return err
	}
	for resp := range ch {
		if err := resp.Err(); err != nil {
			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
				return store.ErrCompacted
			}
			return unavailable(err)
		}
		if resp.IsProgressNotify() {
			progress(uint64(resp.Header.Revision))
			continue
		}
		for _, ev := range resp.Events {
			kind, key, ok := s.markOf(string(ev.Kv.Key))
			if !ok {
				s.logf("etcd: the mark key %q does not parse; the marks feed skipped it", ev.Kv.Key)
				continue
			}
			rev := uint64(ev.Kv.ModRevision)
			if ev.Type == clientv3.EventTypeDelete {
				fn(store.Revocation{Kind: kind, Key: key}, true, rev)
				continue
			}
			var r markRec
			if json.Unmarshal(ev.Kv.Value, &r) != nil {
				s.logf("etcd: the mark at %q does not decode; the marks feed stands it as of now", ev.Kv.Key)
				r = markRec{Kind: kind, Key: key, At: s.now()}
			}
			fn(r.revocation(), false, rev)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: the marks watch ended", store.ErrUnavailable)
}

// Revision is the store's current revision, from a linearizable read's
// header: where a feed that has read nothing begins (placement.FollowPins).
func (s *Store) Revision(ctx context.Context) (uint64, error) {
	resp, err := s.tok.Get(clientv3.WithRequireLeader(ctx), s.k.meta("ping"))
	if err != nil {
		return 0, unavailable(err)
	}
	return uint64(resp.Header.Revision), nil
}

// WatchMemberships calls fn with the principal of every put and delete of
// a membership record after `after` (placement.PinFeed; plan 11a, R13), on
// the token client, requiring a leader as WatchRevocations does; the record
// itself is not read, the cache reads it again. A key that does not parse
// is said and skipped. Progress notifications go to progress. A compacted
// revision is store.ErrCompacted; any other failure ErrUnavailable or
// ErrRefused.
func (s *Store) WatchMemberships(ctx context.Context, after uint64, fn func(principal string, rev uint64),
	progress func(uint64)) error {
	wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
	defer cancel()
	prefix := s.k.family(famMembership)
	ch := s.tok.Watch(wctx, prefix, clientv3.WithPrefix(), clientv3.WithRev(int64(after)+1),
		clientv3.WithProgressNotify(), clientv3.WithKeysOnly())
	for resp := range ch {
		if err := resp.Err(); err != nil {
			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
				return store.ErrCompacted
			}
			return unavailable(err)
		}
		if resp.IsProgressNotify() {
			progress(uint64(resp.Header.Revision))
			continue
		}
		for _, ev := range resp.Events {
			p, err := url.PathUnescape(strings.TrimPrefix(string(ev.Kv.Key), prefix))
			if err != nil {
				s.logf("etcd: the membership key %q does not parse; the pins feed skipped it", ev.Kv.Key)
				continue
			}
			fn(p, uint64(ev.Kv.ModRevision))
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: the pins watch ended", store.ErrUnavailable)
}
