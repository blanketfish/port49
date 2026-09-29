package author

import (
	"context"
	"errors"
	"sync"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/store"
)

// Engine is the daemon's Authorizer: it answers from the compiled blob a
// context names (spec §5.1.2, §5.2, §5.3), with the evaluator
// internal/engine runs for replay and explain too, so what the daemon decided
// is what a replay reproduces (spec §5.7).
//
// Blobs are immutable and named by their hash, so each replica caches them
// compiled, by hash, with no invalidation (spec §5.1.1). A command on a cached
// blob costs no blob read; a blob the store cannot produce is
// blob_unavailable, and a store that does not answer is store_unavailable.
// The handler answers both FAIL (plan 4, owner's ruling): an ERROR here
// would run every command under IOS-XE's `if-authenticated` and hand the N9Kv
// to local RBAC (tests/lab/results/L4-error-*.md). Either way nothing falls
// back: answering a broker-minted session from another authorizer because the
// store hiccuped would be a permit nobody granted.
//
// A context with no blob hash is Fallback's: the lab's seeded tokens are
// minted without one. With no Fallback it is denied.
type Engine struct {
	Store    store.Store
	Metrics  *metrics.Metrics
	Fallback Authorizer

	mu    sync.Mutex
	cache map[string]*engine.Program
}

// blobCacheMax bounds the per-replica cache. Spec §5.1.2 expects a few dozen
// blobs per policy version across a 10,000-device fleet; past the bound one
// entry is dropped, and the next command naming it pays one store read.
const blobCacheMax = 1024

const (
	blobUnavailableMsg  = "port49: the policy for this session could not be read - run `port49 token` and log in again"
	storeUnavailableMsg = "port49: authorization store unavailable"
	platformMismatchMsg = "port49: this session's policy was compiled for another platform - run `port49 token` and log in again"
)

// program returns the compiled blob hash names, from the cache or the store.
// A non-empty reason is why it could not.
func (e *Engine) program(ctx context.Context, hash string) (*engine.Program, decision.Reason) {
	e.mu.Lock()
	p, ok := e.cache[hash]
	e.mu.Unlock()
	if ok {
		e.Metrics.BlobCache.WithLabelValues("hit").Inc()
		return p, ""
	}
	e.Metrics.BlobCache.WithLabelValues("miss").Inc()
	body, err := e.Store.GetBlob(ctx, hash)
	e.Metrics.StoreOps.WithLabelValues("get_blob", storeOutcome(err)).Inc()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, decision.BlobUnavailable
	case err != nil:
		return nil, decision.StoreUnavailable
	}
	b, err := engine.Decode(hash, body)
	if err != nil {
		return nil, decision.BlobUnavailable
	}
	if p, err = engine.Compile(b); err != nil {
		return nil, decision.BlobUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cache == nil {
		e.cache = map[string]*engine.Program{}
	}
	if len(e.cache) >= blobCacheMax {
		for k := range e.cache {
			delete(e.cache, k)
			break
		}
	}
	e.cache[hash] = p
	return p, ""
}

// load is the preamble both points share: the program, checked against the
// device it is being asked about. A blob compiled for another platform than
// the device's carries that platform's dialect and attributes, so it is never
// answered from (roadmap, plan 4, carried from plan 3).
func (e *Engine) load(ctx context.Context, r Request) (*engine.Program, *Decision) {
	hash := r.Context.BlobHash
	p, reason := e.program(ctx, hash)
	switch reason {
	case "":
	case decision.StoreUnavailable:
		return nil, &Decision{Reason: reason, ServerMsg: storeUnavailableMsg, Policy: &decision.Policy{Blob: hash}}
	default:
		return nil, &Decision{Reason: reason, ServerMsg: blobUnavailableMsg, Policy: &decision.Policy{Blob: hash}}
	}
	if p.Blob.Platform != r.Device.Platform {
		return nil, &Decision{Reason: decision.BlobPlatformMismatch, ServerMsg: platformMismatchMsg,
			Policy: &decision.Policy{Bundle: p.Blob.Bundle, Blob: hash}}
	}
	return p, nil
}

// Session answers a session authorization with the blob's attributes, the
// four substitutions filled from the context and the device (spec §5.2, §6).
func (e *Engine) Session(ctx context.Context, r Request) Decision {
	if r.Context.BlobHash == "" {
		return e.fallback().Session(ctx, r)
	}
	p, denied := e.load(ctx, r)
	if denied != nil {
		return *denied
	}
	pol := &decision.Policy{Bundle: p.Blob.Bundle, Blob: r.Context.BlobHash}
	attrs, err := p.Blob.SessionAttributes(engine.Values{Username: r.Context.Username,
		Principal: r.Context.Principal, Device: r.Device.NAS})
	if err != nil {
		// ErrAttributeTooLong or ErrSubstitution. The broker checked these
		// values at mint, so the context no longer holds what the token was
		// minted for. Nothing partial is sent.
		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg, Policy: pol}
	}
	for _, a := range attrs {
		// The device refuses the whole session for a priv-lvl that is not a
		// level and for an attribute its platform does not take (IOS-XE,
		// L18-cisco_iosxe.md), and GrantedPrivLvl skips the first, so the
		// ceiling below never sees it; an idletime or timeout that is not a
		// plain decimal may be refused the same way. The load's joint check
		// quarantines such a composition: refused here, never sent.
		if engine.NotALevel(a) || engine.NotANumber(a) || !p.Blob.Accepts(a) {
			return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg, Policy: pol}
		}
	}
	if level, _, ok := engine.GrantedPrivLvl(attrs); ok {
		// A reply above the ceiling the token was minted with would tell the
		// device a level port49 then holds the session under (spec §7). The
		// load's joint check quarantines such a composition, so the context
		// no longer fits the blob: refused, never sent and clamped.
		if ceiling, ok := r.Context.PrivilegeCeiling(); ok && level > ceiling {
			return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg, Policy: pol}
		}
	}
	return Decision{Permit: true, Reason: p.Blob.SessionReason(), Attributes: attrs, Policy: pol}
}

// Command decides one command vector against the blob (spec §5.3).
func (e *Engine) Command(ctx context.Context, r Request) Decision {
	if r.Context.BlobHash == "" {
		return e.fallback().Command(ctx, r)
	}
	p, denied := e.load(ctx, r)
	if denied != nil {
		return *denied
	}
	o := p.Command(r.Raw)
	return Decision{Permit: o.Permit, Reason: o.Reason, ServerMsg: o.ServerMsg(),
		Policy: o.Policy(p.Blob.Bundle, r.Context.BlobHash), Vector: o.Vector}
}

// fallback is the authorizer for a context with no blob. A nil Fallback
// denies rather than panics: port49 never falls back to permitting everything.
func (e *Engine) fallback() Authorizer {
	if e.Fallback == nil {
		return denyAll{}
	}
	return e.Fallback
}

type denyAll struct{}

func (denyAll) Session(context.Context, Request) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}

func (denyAll) Command(context.Context, Request) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}
