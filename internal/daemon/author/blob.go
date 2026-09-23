package author

import (
	"context"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// Blob answers from the compiled blob a context names (spec §5.1.2): the
// session reply is the blob's attributes, and a command is the blob's rules.
// BORROWED AHEAD from plan 4, whose Authorizer replaces it along with the blob
// format (internal/blob).
//
// A context with no blob hash is Fallback's: the lab's seeded tokens are
// minted without one, and they keep the lab authorizer's answers. A context
// that names a blob the store cannot produce, or produces wrong, is denied
// blob_unavailable — a store fault, never a verdict — and nothing falls back:
// answering a broker-minted session from the lab's permissive list because the
// store hiccuped would be a permit nobody granted.
//
// There is no cache. The store is in-process (plan 3, Decided 1), so a cache
// would be a second copy of the same map; spec §5.1.1's per-replica cache is
// plan 4's, with a store worth caching in front of.
//
// Its GetBlob is not counted in StoreOps, unlike every other store call site:
// it holds no metrics handle, and plan 4's Authorizer, which replaces it,
// counts its reads with its cache (plan 3, pre-flight F18).
type Blob struct {
	Store    store.Store
	Fallback Authorizer
}

const blobUnavailableMsg = "port49: the policy for this session could not be read - run `port49 token` and log in again"

func (b *Blob) load(ctx context.Context, c store.Context) (blob.Blob, bool) {
	body, err := b.Store.GetBlob(ctx, c.BlobHash)
	if err != nil {
		return blob.Blob{}, false
	}
	bl, err := blob.Decode(c.BlobHash, body)
	return bl, err == nil
}

func (b *Blob) Session(ctx context.Context, c store.Context, args []string) Decision {
	if c.BlobHash == "" {
		return b.fallback().Session(ctx, c, args)
	}
	bl, ok := b.load(ctx, c)
	if !ok {
		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg}
	}
	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: append([]string(nil), bl.Attributes...)}
}

func (b *Blob) Command(ctx context.Context, c store.Context, vector []string, args []string) Decision {
	if c.BlobHash == "" {
		return b.fallback().Command(ctx, c, vector, args)
	}
	bl, ok := b.load(ctx, c)
	if !ok {
		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg}
	}
	switch bl.Command(vector) {
	case blob.Permitted:
		return Decision{Permit: true, Reason: decision.PermitDominates}
	case blob.Denied:
		return Decision{Reason: decision.NoPermitDominatesDeny, ServerMsg: "port49: denied by policy; see 'port49 explain'"}
	default:
		return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no rule permits this command; see 'port49 explain'"}
	}
}

// fallback is the authorizer for a context with no blob. A nil Fallback
// denies rather than panics: port49 never falls back to permitting everything.
func (b *Blob) fallback() Authorizer {
	if b.Fallback == nil {
		return denyAll{}
	}
	return b.Fallback
}

type denyAll struct{}

func (denyAll) Session(context.Context, store.Context, []string) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}

func (denyAll) Command(context.Context, store.Context, []string, []string) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}
