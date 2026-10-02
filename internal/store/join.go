package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// MaxJoinAttempts bounds JoinContext's read-merge-swap loop. A swap is refused
// only when another write to the same context landed between the read and the
// swap, so the bound is on concurrent writers to one operator's context on one
// device — a login racing a touch, an annotation, a privilege raise, a refresh,
// a revocation, or another login — not on time. Eight is several times what a
// human operator produces; running out is ERROR on the login, never a guess.
const MaxJoinAttempts = 8

// JoinResult is what JoinContext wrote, and why.
type JoinResult struct {
	// Context is the record as written (the store stamps LastTouchedAt on its
	// own copy). Its CtxID is the one to log: the live context's on a join,
	// the login's own otherwise.
	Context Context
	// Joined is true when the login merged into a live context of the same
	// principal.
	Joined bool
	// Replaced is the ctx_id of a live context this login overwrote rather
	// than joined — another principal's, or one past its session ceiling.
	// Empty on a join and on a first login. It is what the redeem record
	// carries as session.replaced_ctx_id (spec §5.6).
	Replaced string
	// ReplacedUnreadable is true when the live record could not be opened
	// (UnreadableContextError) and the login replaced it. Its ctx_id is
	// sealed, so Replaced stays empty and this is what the redeem record
	// carries instead, as session.replaced_unreadable.
	ReplacedUnreadable bool
	// ClampedFrom is the level the live context held when a join lowered it
	// to the newest login's ceiling; zero when the join lowered nothing. The
	// other windows' next command above the new level is denied
	// privilege_exceeded, and this is what the redeem record carries to say
	// why (spec §5.3).
	ClampedFrom uint8
	// Prior is the live record a readable replace displaced, whole; zero on a
	// join, a first login and an unreadable replace. The login unindexes its
	// credential, or a revocation of the displaced principal's sid or
	// certificate would keep reaching the context that replaced it.
	Prior Context
}

// LoginIndex is what a login indexes its context under (IndexContext's
// arguments): its principal, sid and certificate key, for TTL. JoinContext
// decides what the displaced record's keys lose, and SwapLogin writes it
// with the context (plan 7d).
type LoginIndex struct {
	Principal, Sid, CertKey string
	TTL                     time.Duration
}

// Joinable reports whether a login may join the live context rather than
// replace it (spec §5.6): the same principal, and a context not past its
// session ceiling. A context past session_expires is over, whatever else it
// holds, and a login does not extend it; it starts a new one.
func Joinable(live, login Context, now time.Time) bool {
	if live.Principal != login.Principal {
		return false
	}
	return live.SessionExpires.IsZero() || !now.After(live.SessionExpires)
}

// Join merges a login into the live context it may join, by the field rules of
// spec §5.6. The context is "this principal's authorization on this device",
// not one connection, so a second window adds to it and takes nothing away
// from the first: the ctx_id, the privilege already granted, the session
// discriminators and the accounting state are kept. What the newest broker
// decision says — the policy blob, the ceiling, the enable mechanism, the
// credential — comes from the login. The clock fields take the later of the
// two. mintedAt is the login token's store.Token.MintedAt.
func Join(live, login Context, mintedAt time.Time) Context {
	out := live
	out.Port, out.RemAddr = login.Port, login.RemAddr
	out.BlobHash, out.MaxPrivilege, out.Enable = login.BlobHash, login.MaxPrivilege, login.Enable
	out.Credential = login.Credential
	out.AuthTime = later(live.AuthTime, login.AuthTime)
	out.SessionExpires = laterCeiling(live.SessionExpires, login.SessionExpires)
	out.RefreshedAt = login.RefreshedAt
	out.LastTouchedAt = login.LastTouchedAt
	// The login's level only ever raises what is held, and the result is
	// bounded by the ceiling the newest login carries — the same rule
	// SetPrivilege applies (spec §5.3).
	if login.PrivLvl > out.PrivLvl {
		out.PrivLvl = login.PrivLvl
	}
	if ceiling, ok := out.PrivilegeCeiling(); ok && out.PrivLvl > ceiling {
		out.PrivLvl = ceiling
	}
	out.RevokedAt = CarryRevocation(live.RevokedAt, mintedAt)
	out.SessionDiscriminators = append([]string(nil), live.SessionDiscriminators...)
	out.Rev = 0
	return out
}

// CarryRevocation keeps a revocation unless the token being redeemed was
// minted after it. A token cut before the revocation is exactly what the
// revocation was meant to stop, so it must not lift the mark; a token cut after
// it is the broker having verified the credential again, which is the one thing
// that may (spec §13, decision 15). The login path reads it too, before the
// token is spent, to refuse a login into a context whose revocation it cannot
// lift.
func CarryRevocation(revokedAt, mintedAt time.Time) time.Time {
	if revokedAt.IsZero() || mintedAt.After(revokedAt) {
		return time.Time{}
	}
	return revokedAt
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// laterCeiling is later for session_expires, where zero is "no ceiling" and so
// is later than any time: a join never gives a context a ceiling that neither
// login's policy would impose on its own.
func laterCeiling(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	return later(a, b)
}

// JoinContext writes a login's context at k: a join into the live context
// when Joinable says it may, the login itself otherwise (spec §5.6), with
// its index and its revocation check in the same step (SwapLogin; plan 7d).
// It reads the marks for the login's principal and certificate, then the
// context, decides, and swaps on what it read, retrying from the read when
// the swap is refused, so a write that lands in between — SetRevokedAt, or
// a mark, above all — is merged rather than erased, and two concurrent
// logins both land in one context instead of one overwriting the other.
//
// login is the context this login would create on its own, CtxID
// included. A mark that stands for login's principal or certificate is
// carried into the context as its revocation by CarryRevocation's rule: a
// token minted after the mark is the credential verified again (decision
// 15). A replace of the same principal's context past its ceiling carries
// the revocation by the same rule a join does.
//
// The index change is the one the login path made in three calls before
// plan 7d: another principal's replace, or an unreadable one, clears every
// key the ref was indexed under; the same principal's replace drops only
// the displaced sid and certificate this login does not share; a join
// keeps what is there. Then the login's own keys are added.
//
// A record the sealing layer cannot open (UnreadableContextError) cannot
// be merged, and is replaced by the login: refusing it would lock the
// operator out until the idle TTL reclaims a record nothing can use. The
// replace is a swap on the plaintext revision the error carries, and it
// keeps the plaintext RevokedAt by the same minted-after rule whoever the
// principal was, because the principal is sealed. Any other store error is
// returned as it is.
func JoinContext(ctx context.Context, s Store, k ContextKey, login Context, mintedAt, now time.Time, ttl time.Duration,
	ix LoginIndex) (JoinResult, error) {
	for attempt := 0; attempt < MaxJoinAttempts; attempt++ {
		marks, standing, err := readMarks(ctx, s, login)
		if err != nil {
			return JoinResult{}, err
		}
		mine := login
		mine.RevokedAt = later(mine.RevokedAt, CarryRevocation(standing, mintedAt))
		live, err := s.GetContext(ctx, k)
		var res JoinResult
		var rev uint64
		w := LoginWrite{Principal: ix.Principal, Sid: ix.Sid, CertKey: ix.CertKey, IndexTTL: ix.TTL, Marks: marks}
		var unreadable *UnreadableContextError
		switch {
		case errors.Is(err, ErrNotFound):
			res.Context = mine
		case errors.As(err, &unreadable):
			res = JoinResult{Context: mine, ReplacedUnreadable: true}
			res.Context.RevokedAt = later(mine.RevokedAt, CarryRevocation(unreadable.RevokedAt, mintedAt))
			rev = unreadable.Rev
			w.ClearRef = true
		case err != nil:
			return JoinResult{}, err
		case Joinable(live, mine, now):
			res = JoinResult{Context: Join(live, mine, mintedAt), Joined: true}
			res.Context.RevokedAt = later(res.Context.RevokedAt, mine.RevokedAt)
			if live.PrivLvl > res.Context.PrivLvl {
				res.ClampedFrom = live.PrivLvl
			}
			rev = live.Rev
		default:
			res = JoinResult{Context: mine, Replaced: live.CtxID, Prior: live}
			rev = live.Rev
			if live.Principal == mine.Principal {
				res.Context.RevokedAt = later(mine.RevokedAt, CarryRevocation(live.RevokedAt, mintedAt))
				w.DropSid, w.DropCertKey = displaced(live.Credential, mine.Credential)
			} else {
				w.ClearRef = true
			}
		}
		switch err := s.SwapLogin(ctx, k, rev, res.Context, ttl, w); {
		case err == nil:
			return res, nil
		case !errors.Is(err, ErrConflict):
			return JoinResult{}, err
		}
	}
	return JoinResult{}, fmt.Errorf("store: context still changing after %d attempts: %w", MaxJoinAttempts, ErrConflict)
}

// readMarks reads the marks for the login's principal and certificate, as
// SwapLogin will compare them, and the latest At among those standing.
func readMarks(ctx context.Context, s Store, login Context) ([]MarkRead, time.Time, error) {
	keys := [][2]string{{RevocationPrincipal, login.Principal}}
	if ck := CertKey(login.Credential.Issuer, login.Credential.Serial); !BlankCertKey(ck) {
		keys = append(keys, [2]string{RevocationCert, ck})
	}
	var out []MarkRead
	var standing time.Time
	for _, kk := range keys {
		if kk[1] == "" {
			continue
		}
		r, err := s.GetRevocation(ctx, kk[0], kk[1])
		switch {
		case errors.Is(err, ErrNotFound):
			out = append(out, MarkRead{Kind: kk[0], Key: kk[1]})
		case err != nil:
			return nil, time.Time{}, err
		default:
			out = append(out, MarkRead{Kind: kk[0], Key: kk[1], At: r.At})
			standing = later(standing, r.At)
		}
	}
	return out, standing, nil
}

// displaced is what a same-principal replace unindexes: the displaced
// login's sid and certificate, each only where this login does not share
// it. A key both hold is one this login indexes anyway, and dropping it
// first would leave a moment in which a revocation by it finds nothing —
// which, in one step, it no longer can; the rule is kept so the index ends
// where it did before plan 7d.
func displaced(prior, login Credential) (sid, certKey string) {
	if prior.Sid != login.Sid {
		sid = prior.Sid
	}
	if ck := CertKey(prior.Issuer, prior.Serial); ck != CertKey(login.Issuer, login.Serial) {
		certKey = ck
	}
	return sid, certKey
}
