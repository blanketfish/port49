package etcd

import (
	"encoding/hex"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// The records as stored: JSON with snake_case keys (spec: data is
// snake_case). A store type is never marshalled itself — its fields carry
// no tags — but converted to one of these and back. Each record holds its
// own expiry; the revisions are etcd's.

// credRec is store.Credential with tags: the same fields in the same
// order, so each converts to the other directly.
type credRec struct {
	Method      string   `json:"method,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Iss         string   `json:"iss,omitempty"`
	Sub         string   `json:"sub,omitempty"`
	Sid         string   `json:"sid,omitempty"`
	ACR         string   `json:"acr,omitempty"`
	AMR         []string `json:"amr,omitempty"`
	MFAMethod   string   `json:"mfa_method,omitempty"`
	// omitzero, not omitempty: omitempty never omits a zero time.Time.
	MFAAt          time.Time `json:"mfa_at,omitzero"`
	MFAAgentSHA256 string    `json:"mfa_agent_sha256,omitempty"`
	// Written always, false included; absent reads as false
	// (store.Credential.MFAFresh).
	MFAFresh bool `json:"mfa_fresh"`
}

type tokenRec struct {
	ID            string        `json:"id"`
	Secret        []byte        `json:"secret,omitempty"`
	Kind          string        `json:"kind"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Principal     string        `json:"principal,omitempty"`
	Username      string        `json:"username,omitempty"`
	BlobHash      string        `json:"blob_hash,omitempty"`
	MaxSessionAge time.Duration `json:"max_session_age"`
	Enable        string        `json:"enable,omitempty"`
	MaxPrivilege  uint8         `json:"max_privilege"`
	Credential    credRec       `json:"credential"`
	AuthTime      time.Time     `json:"auth_time"`
	MintedAt      time.Time     `json:"minted_at"`
	VerifiedAt    time.Time     `json:"verified_at"`
	Sealed        []byte        `json:"sealed,omitempty"`
}

func tokenRecOf(t store.Token) tokenRec {
	return tokenRec{ID: t.ID, Secret: t.Secret, Kind: t.Kind, ExpiresAt: t.ExpiresAt, Principal: t.Principal,
		Username: t.Username, BlobHash: t.BlobHash, MaxSessionAge: t.MaxSessionAge, Enable: t.Enable,
		MaxPrivilege: t.MaxPrivilege, Credential: credRec(t.Credential), AuthTime: t.AuthTime, MintedAt: t.MintedAt,
		VerifiedAt: t.VerifiedAt, Sealed: t.Sealed}
}

func (r tokenRec) token() store.Token {
	return store.Token{ID: r.ID, Secret: r.Secret, Kind: r.Kind, ExpiresAt: r.ExpiresAt, Principal: r.Principal,
		Username: r.Username, BlobHash: r.BlobHash, MaxSessionAge: r.MaxSessionAge, Enable: r.Enable,
		MaxPrivilege: r.MaxPrivilege, Credential: store.Credential(r.Credential), AuthTime: r.AuthTime,
		MintedAt: r.MintedAt, VerifiedAt: r.VerifiedAt, Sealed: r.Sealed}
}

type receiptRec struct {
	CredentialSHA256 string    `json:"credential_sha256,omitempty"` // hex; zero when sealed
	Status           uint8     `json:"status"`
	CtxID            string    `json:"ctx_id,omitempty"`
	FirstRedeemedAt  time.Time `json:"first_redeemed_at"`
	IdleExpiresAt    time.Time `json:"idle_expires_at"`
	RetainUntil      time.Time `json:"retain_until"`
	Failed           bool      `json:"failed"`
	// Principal, Sid and CertKey are sealed (store.Receipt): empty under
	// crypt, which reads its own sealed copy (crypt.GetReceipt). They are
	// held here only for the plaintext form, and nothing trusts them.
	Principal string `json:"principal,omitempty"`
	Sid       string `json:"sid,omitempty"`
	CertKey   string `json:"cert_key,omitempty"`
	Sealed    []byte `json:"sealed,omitempty"`
	// Nonce is the redemption request that wrote this receipt (hedge.go).
	Nonce string `json:"nonce,omitempty"`
}

func receiptRecOf(r store.Receipt) receiptRec {
	out := receiptRec{Status: r.Status, CtxID: r.CtxID, FirstRedeemedAt: r.FirstRedeemedAt,
		IdleExpiresAt: r.IdleExpiresAt, RetainUntil: r.RetainUntil, Failed: r.Failed, Principal: r.Principal,
		Sid: r.Sid, CertKey: r.CertKey, Sealed: r.Sealed}
	if r.CredentialSHA256 != ([32]byte{}) {
		out.CredentialSHA256 = hex.EncodeToString(r.CredentialSHA256[:])
	}
	return out
}

func (r receiptRec) receipt() store.Receipt {
	out := store.Receipt{Status: r.Status, CtxID: r.CtxID, FirstRedeemedAt: r.FirstRedeemedAt,
		IdleExpiresAt: r.IdleExpiresAt, RetainUntil: r.RetainUntil, Failed: r.Failed, Principal: r.Principal,
		Sid: r.Sid, CertKey: r.CertKey, Sealed: r.Sealed}
	if b, err := hex.DecodeString(r.CredentialSHA256); err == nil && len(b) == 32 {
		copy(out.CredentialSHA256[:], b)
	}
	return out
}

// expiryRec is an index entry's whole value: when it stops naming its key.
type expiryRec struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type markRec struct {
	Kind            string    `json:"kind"`
	Key             string    `json:"key"`
	At              time.Time `json:"at"`
	Origin          string    `json:"origin,omitempty"`
	LandedAfterLift bool      `json:"landed_after_lift,omitempty"`
}

func markRecOf(r store.Revocation) markRec {
	return markRec{Kind: r.Kind, Key: r.Key, At: r.At, Origin: r.Origin, LandedAfterLift: r.LandedAfterLift}
}

func (r markRec) revocation() store.Revocation {
	return store.Revocation{Kind: r.Kind, Key: r.Key, At: r.At, Origin: r.Origin, LandedAfterLift: r.LandedAfterLift}
}

// liftRec is a lift's record (rl/; decision 51): when the lift was made and
// who asked, and until when the record is live on the store's clock; its
// lease only reclaims it.
type liftRec struct {
	At     time.Time `json:"at"`
	Origin string    `json:"origin,omitempty"`
	Until  time.Time `json:"until"`
}

// ctxRec is a login context as stored. PolicyRev is store.Context's
// PolicyRev drawn from etcd's revision counter: a write that moves what a
// policy refresh decides sets PolicyMoved, and the context's PolicyRev is
// then the key's mod_revision, the revision of that very write; the next
// write that does not move it stores the mod_revision it read as
// policy_rev and clears the flag. So PolicyRev moves exactly on the writes
// memory moves it on, and never repeats a value (store.Context.PolicyRev).
//
// Under crypt every trusted field is inside Sealed and empty here, except
// revoked_at, which crypt also writes in the clear; the revisions, the
// idle clock (last_touched_at) and accounting's annotations are the
// plaintext bookkeeping beside it (Ruling 17).
type ctxRec struct {
	CtxID                 string    `json:"ctx_id,omitempty"`
	Principal             string    `json:"principal,omitempty"`
	Username              string    `json:"username,omitempty"`
	Port                  string    `json:"port,omitempty"`
	RemAddr               string    `json:"rem_addr,omitempty"`
	PrivLvl               uint8     `json:"priv_lvl"`
	BlobHash              string    `json:"blob_hash,omitempty"`
	Credential            credRec   `json:"credential"`
	AuthTime              time.Time `json:"auth_time"`
	SessionExpires        time.Time `json:"session_expires"`
	RefreshedAt           time.Time `json:"refreshed_at"`
	RevokedAt             time.Time `json:"revoked_at"`
	LastTouchedAt         time.Time `json:"last_touched_at"`
	SessionDiscriminators []string  `json:"session_discriminators,omitempty"`
	AccountingState       string    `json:"accounting_state,omitempty"`
	Enable                string    `json:"enable,omitempty"`
	MaxPrivilege          uint8     `json:"max_privilege"`
	CreatedAt             time.Time `json:"created_at"`
	// Logins is the login witness (store.Context.Logins): empty under
	// crypt, which seals it. It is held here only for the plaintext form,
	// so a join on this backend alone keeps the witness memory keeps. The
	// replay check trusts Logins only through crypt, which ignores this
	// field and reads its sealed copy: anyone who can write etcd can write
	// this one, and bare etcd, with no sealing layer over it, is never a
	// production configuration (Task 6 review M-2).
	Logins []string `json:"logins,omitempty"`
	Sealed []byte   `json:"sealed,omitempty"`
	// SwapNonce is the login swap that wrote this record (hedge.go); a later
	// write that rebuilds the record drops it.
	SwapNonce string `json:"swap_nonce,omitempty"`

	ExpiresAt   time.Time `json:"expires_at"`
	PolicyRev   int64     `json:"policy_rev"`
	PolicyMoved bool      `json:"policy_moved"`
}

func ctxRecOf(c store.Context) ctxRec {
	return ctxRec{CtxID: c.CtxID, Principal: c.Principal, Username: c.Username, Port: c.Port, RemAddr: c.RemAddr,
		PrivLvl: c.PrivLvl, BlobHash: c.BlobHash, Credential: credRec(c.Credential), AuthTime: c.AuthTime,
		SessionExpires: c.SessionExpires, RefreshedAt: c.RefreshedAt, RevokedAt: c.RevokedAt,
		LastTouchedAt: c.LastTouchedAt, SessionDiscriminators: append([]string(nil), c.SessionDiscriminators...),
		AccountingState: c.AccountingState, Enable: c.Enable, MaxPrivilege: c.MaxPrivilege, CreatedAt: c.CreatedAt,
		Logins: append([]string(nil), c.Logins...), Sealed: c.Sealed}
}

func (r ctxRec) context(mod int64) store.Context {
	return store.Context{CtxID: r.CtxID, Principal: r.Principal, Username: r.Username, Port: r.Port,
		RemAddr: r.RemAddr, PrivLvl: r.PrivLvl, BlobHash: r.BlobHash, Credential: store.Credential(r.Credential),
		AuthTime: r.AuthTime, SessionExpires: r.SessionExpires, RefreshedAt: r.RefreshedAt, RevokedAt: r.RevokedAt,
		LastTouchedAt: r.LastTouchedAt, SessionDiscriminators: append([]string(nil), r.SessionDiscriminators...),
		AccountingState: r.AccountingState, Enable: r.Enable, MaxPrivilege: r.MaxPrivilege, CreatedAt: r.CreatedAt,
		Logins: append([]string(nil), r.Logins...), Sealed: r.Sealed, Rev: uint64(mod),
		PolicyRev: uint64(r.policyRev(mod))}
}

func (r ctxRec) policyRev(mod int64) int64 {
	if r.PolicyMoved {
		return mod
	}
	return r.PolicyRev
}

type blobRec struct {
	Body      []byte    `json:"body"`
	ExpiresAt time.Time `json:"expires_at"`
}

// idxRec is a ref's index record, x/<nas>/<user>: every principal, sid and
// certificate key the ref answers under, each with its own expiry. It is
// authoritative: a lookup entry answers only while this lists its key
// live (Ruling 6).
type idxRec struct {
	Principals []idxEntry `json:"principals,omitempty"`
	Sids       []idxEntry `json:"sids,omitempty"`
	Certs      []idxEntry `json:"certs,omitempty"`
}

type idxEntry struct {
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (x *idxRec) list(fam string) *[]idxEntry {
	switch fam {
	case famByPrincipal:
		return &x.Principals
	case famBySid:
		return &x.Sids
	}
	return &x.Certs
}

// add lists key under fam until exp, as the memory store's addRef does:
// an entry already there takes exp, whatever it held.
func (x *idxRec) add(fam, key string, exp time.Time) {
	l := x.list(fam)
	for i := range *l {
		if (*l)[i].Key == key {
			(*l)[i].ExpiresAt = exp
			return
		}
	}
	*l = append(*l, idxEntry{Key: key, ExpiresAt: exp})
}

func (x *idxRec) drop(fam, key string) {
	l := x.list(fam)
	out := (*l)[:0]
	for _, e := range *l {
		if e.Key != key {
			out = append(out, e)
		}
	}
	*l = out
}

// restamp pushes every entry out to exp, never shortening one: an
// extension of the context carries its index entries (design §12).
func (x *idxRec) restamp(exp time.Time) {
	for _, l := range []*[]idxEntry{&x.Principals, &x.Sids, &x.Certs} {
		for i := range *l {
			if exp.After((*l)[i].ExpiresAt) {
				(*l)[i].ExpiresAt = exp
			}
		}
	}
}

// lists reports whether key is listed under fam, live at now.
func (x idxRec) lists(fam, key string, now time.Time) bool {
	for _, e := range *x.list(fam) {
		if e.Key == key {
			return e.ExpiresAt.After(now)
		}
	}
	return false
}

func (x idxRec) maxExp() time.Time {
	var m time.Time
	for _, l := range [][]idxEntry{x.Principals, x.Sids, x.Certs} {
		for _, e := range l {
			if e.ExpiresAt.After(m) {
				m = e.ExpiresAt
			}
		}
	}
	return m
}

func (x idxRec) empty() bool { return len(x.Principals)+len(x.Sids)+len(x.Certs) == 0 }

// prune drops every entry expired at now. Every write of the record calls
// it, so the record holds the keys still live and no more: a joined
// context that sees a login per window stays as large as its live logins,
// not its history (pre-flight M20). An expired entry answers no lookup
// already (lists), so dropping it changes no answer. It is not a cap: a
// live entry is never dropped to bound the record, since that would cost
// a revocation its reach (the memory store's indexKeys says why).
func (x *idxRec) prune(now time.Time) {
	for _, l := range []*[]idxEntry{&x.Principals, &x.Sids, &x.Certs} {
		out := (*l)[:0]
		for _, e := range *l {
			if e.ExpiresAt.After(now) {
				out = append(out, e)
			}
		}
		*l = out
	}
}

type idemRec struct {
	BodyHash  string    `json:"body_hash"`
	Response  []byte    `json:"response,omitempty"` // empty once sealed: the sealing layer seals it
	ExpiresAt time.Time `json:"expires_at"`
	Sealed    []byte    `json:"sealed,omitempty"`
	Holder    string    `json:"holder,omitempty"`
	Pending   bool      `json:"pending"`
}

func idemRecOf(r store.Idempotency) idemRec {
	return idemRec{BodyHash: r.BodyHash, Response: r.Response, ExpiresAt: r.ExpiresAt, Sealed: r.Sealed,
		Holder: r.Holder, Pending: r.Pending}
}

func (r idemRec) idempotency() store.Idempotency {
	return store.Idempotency{BodyHash: r.BodyHash, Response: r.Response, ExpiresAt: r.ExpiresAt, Sealed: r.Sealed,
		Holder: r.Holder, Pending: r.Pending}
}
