package etcd

import (
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/rhwendt/port49/internal/store"
)

// keys builds every key under one keyspace. Each part is escaped
// (url.PathEscape), so a "/" in a device name, username, principal, sid or
// certificate key cannot split it, and every family that is scanned by
// prefix ends its scanned parts with "/", so "user:al" never matches
// "user:alice" (Review Focus 3).
type keys struct{ root string }

func newKeys(prefix string) keys {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return keys{root: prefix + "v1/"}
}

func esc(parts ...string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = url.PathEscape(p)
	}
	return strings.Join(out, "/")
}

// The families. Each comment is the key's shape after the root.
const (
	famToken          = "t/"  // t/<nas>/<user>/<id>: a token
	famReceipt        = "r/"  // r/<nas>/<user>/<kind>/<sha256 hex>: a receipt
	famReceiptBy      = "rp/" // rp/<principal>/<nas>/<user>/<kind>/<sha256 hex>: its revocation index
	famContext        = "c/"  // c/<nas>/<user>: a login context
	famIndexed        = "x/"  // x/<nas>/<user>: the ref's index record, authoritative
	famByPrincipal    = "ip/" // ip/<principal>/<nas>/<user>: a lookup entry
	famBySid          = "is/" // is/<sid>/<nas>/<user>
	famByCert         = "ic/" // ic/<cert key>/<nas>/<user>
	famBlob           = "b/"  // b/<hash>
	famTokByPrin      = "tp/" // tp/<principal>/<nas>/<user>: the token index
	famTokByCert      = "tc/" // tc/<cert key>/<nas>/<user>
	famIdem           = "id/" // id/<principal>/<key>: an idempotency record
	famMark           = "rv/" // rv/<kind>/<key>: a revocation mark
	famSuperseded     = "sp/" // sp/<nas>/<user>: when its tokens were last superseded
	famLedger         = "lw/" // lw/<nas>/<user>: the ledger record (plan 7e)
	famMembership     = "mb/" // mb/<principal>: a directory membership (plan 7g), the broker's alone
	famMembershipK    = "mk/" // mk/<map key>: the principal a mapping value resolved to
	famOnce           = "on/" // on/<key>: a once-only record (plan 7h), the broker's alone
	famOIDCOwner      = "oo/" // oo/<OIDCKey>: the principal minting under an OIDC sid or sub
	famLogout         = "lo/" // lo/<OIDCKey>: a back-channel logout's record
	famMFAProof       = "mp/" // mp/<key>: a kept per-login proof (plan 9c), the broker's alone
	famSecondFactor   = "sf/" // sf/<principal>: a person's second factor (plan 9e), the broker's alone
	famSignInAttempts = "sa/" // sa/<key>: a sign-in attempt count (plan 9e), the broker's alone
	famUnlock         = "ul/" // ul/<principal>: a person's latest unlock (plan 11a), the broker's alone
	famMeta           = "meta/"
)

func (k keys) family(f string) string { return k.root + f }

func (k keys) tokens(t store.TokenKey) string {
	return k.root + famToken + esc(t.NAS, t.Username) + "/"
}
func (k keys) token(t store.TokenKey, id string) string { return k.tokens(t) + esc(id) }

func receiptTail(r store.ReceiptKey) string {
	return esc(r.NAS, r.Username, r.Kind, hex.EncodeToString(r.CredentialSHA256[:]))
}
func (k keys) receipt(r store.ReceiptKey) string { return k.root + famReceipt + receiptTail(r) }
func (k keys) receiptsBy(principal string) string {
	return k.root + famReceiptBy + esc(principal) + "/"
}
func (k keys) receiptBy(principal string, r store.ReceiptKey) string {
	return k.receiptsBy(principal) + receiptTail(r)
}

func (k keys) context(c store.ContextKey) string { return k.root + famContext + esc(c.NAS, c.Username) }
func (k keys) indexed(r store.ContextRef) string { return k.root + famIndexed + esc(r.NAS, r.Username) }
func (k keys) lookups(fam, key string) string    { return k.root + fam + esc(key) + "/" }
func (k keys) lookup(fam, key string, r store.ContextRef) string {
	return k.lookups(fam, key) + esc(r.NAS, r.Username)
}

func (k keys) blob(hash string) string { return k.root + famBlob + esc(hash) }

func (k keys) tokenIndex(fam, key string) string { return k.root + fam + esc(key) + "/" }
func (k keys) tokenIndexed(fam, key string, t store.TokenKey) string {
	return k.tokenIndex(fam, key) + esc(t.NAS, t.Username)
}

func (k keys) idem(principal, key string) string  { return k.root + famIdem + esc(principal, key) }
func (k keys) mark(kind, key string) string       { return k.root + famMark + esc(kind, key) }
func (k keys) meta(name string) string            { return k.root + famMeta + name }
func (k keys) ledgerOf(c store.ContextKey) string { return k.root + famLedger + esc(c.NAS, c.Username) }
func (k keys) superseded(t store.TokenKey) string {
	return k.root + famSuperseded + esc(t.NAS, t.Username)
}

func (k keys) membership(principal string) string { return k.root + famMembership + esc(principal) }
func (k keys) membershipKey(mapKey string) string { return k.root + famMembershipK + esc(mapKey) }

func (k keys) once(key string) string      { return k.root + famOnce + esc(key) }
func (k keys) oidcOwner(key string) string { return k.root + famOIDCOwner + esc(key) }
func (k keys) logout(key string) string    { return k.root + famLogout + esc(key) }
func (k keys) mfaProof(key string) string  { return k.root + famMFAProof + esc(key) }

func (k keys) secondFactor(principal string) string { return k.root + famSecondFactor + esc(principal) }
func (k keys) signInAttempts(key string) string     { return k.root + famSignInAttempts + esc(key) }
func (k keys) unlock(principal string) string       { return k.root + famUnlock + esc(principal) }

// enrollmentMark is the enrollment store's creation mark (plan 9e, D7). It
// is not in daemonMetaReads, so the daemon is never granted it.
func (k keys) enrollmentMark() string { return k.meta("enrollments") }

// lastTwo unescapes the last two parts of key: the (NAS, Username) every
// lookup entry and token-index entry ends in.
func lastTwo(key string) (string, string, bool) {
	i := strings.LastIndexByte(key, '/')
	if i <= 0 {
		return "", "", false
	}
	j := strings.LastIndexByte(key[:i], '/')
	if j < 0 {
		return "", "", false
	}
	a, err1 := url.PathUnescape(key[j+1 : i])
	b, err2 := url.PathUnescape(key[i+1:])
	return a, b, err1 == nil && err2 == nil
}
