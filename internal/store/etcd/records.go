package etcd

import (
	"encoding/hex"
	"time"

	"github.com/rhwendt/port49/internal/store"
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
	Sealed        []byte        `json:"sealed,omitempty"`
}

func tokenRecOf(t store.Token) tokenRec {
	return tokenRec{ID: t.ID, Secret: t.Secret, Kind: t.Kind, ExpiresAt: t.ExpiresAt, Principal: t.Principal,
		Username: t.Username, BlobHash: t.BlobHash, MaxSessionAge: t.MaxSessionAge, Enable: t.Enable,
		MaxPrivilege: t.MaxPrivilege, Credential: credRec(t.Credential), AuthTime: t.AuthTime, MintedAt: t.MintedAt,
		Sealed: t.Sealed}
}

func (r tokenRec) token() store.Token {
	return store.Token{ID: r.ID, Secret: r.Secret, Kind: r.Kind, ExpiresAt: r.ExpiresAt, Principal: r.Principal,
		Username: r.Username, BlobHash: r.BlobHash, MaxSessionAge: r.MaxSessionAge, Enable: r.Enable,
		MaxPrivilege: r.MaxPrivilege, Credential: store.Credential(r.Credential), AuthTime: r.AuthTime,
		MintedAt: r.MintedAt, Sealed: r.Sealed}
}

type receiptRec struct {
	CredentialSHA256 string    `json:"credential_sha256,omitempty"` // hex; zero when sealed
	Status           uint8     `json:"status"`
	CtxID            string    `json:"ctx_id,omitempty"`
	FirstRedeemedAt  time.Time `json:"first_redeemed_at"`
	IdleExpiresAt    time.Time `json:"idle_expires_at"`
	RetainUntil      time.Time `json:"retain_until"`
	Failed           bool      `json:"failed"`
	Principal        string    `json:"principal,omitempty"`
	Sid              string    `json:"sid,omitempty"`
	CertKey          string    `json:"cert_key,omitempty"`
	Sealed           []byte    `json:"sealed,omitempty"`
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
	Kind   string    `json:"kind"`
	Key    string    `json:"key"`
	At     time.Time `json:"at"`
	Origin string    `json:"origin,omitempty"`
}

func markRecOf(r store.Revocation) markRec {
	return markRec{Kind: r.Kind, Key: r.Key, At: r.At, Origin: r.Origin}
}

func (r markRec) revocation() store.Revocation {
	return store.Revocation{Kind: r.Kind, Key: r.Key, At: r.At, Origin: r.Origin}
}
