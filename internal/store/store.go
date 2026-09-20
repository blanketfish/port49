// Package store is the narrow interface every shared record passes through
// (design §12). Implementations are pluggable; memory is the reference.
package store

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("store: not found")

type TokenKey struct {
	NAS      string // device name from admission
	Username string // canonical form
}

type Token struct {
	Secret    []byte
	Kind      string // KindLogin | KindEnable
	Reusable  bool
	ExpiresAt time.Time
}

// Token kinds.
const (
	KindLogin  = "login"
	KindEnable = "enable"
)

// ReceiptKey addresses the short-lived proof of a completed redemption. The
// credential hash is part of the key, not merely recorded in the record: that
// is what makes a byte-identical retransmission the only thing that replays,
// while a genuinely new login by the same user finds nothing and redeems
// normally (design §8; spec §13, decision 15).
type ReceiptKey struct {
	NAS              string
	Username         string // canonical form
	CredentialSHA256 [32]byte
}

type Receipt struct {
	// CredentialSHA256 repeats the key's hash. The lookup already selects on
	// it; this copy is what the constant-time compare in package authen checks
	// after the lookup, so a store answering with a record it was not asked
	// for is caught rather than replayed.
	CredentialSHA256 [32]byte
	Status           uint8 // the authentication REPLY status that was sent
	CtxID            string
	ExpiresAt        time.Time
}

// ContextKey addresses the login context. It is (nas, username), and it
// deliberately does not mention the port: measured, `port` is not the same
// value at the authentication that writes the context and the authorization
// that reads it on any platform in the lab (spec §13, decision 15; §15, L1).
// One consequence is accepted rather than fixed: two concurrent logins by one
// username on one device share this key.
type ContextKey struct {
	NAS      string
	Username string // canonical form
}

type Context struct {
	CtxID     string
	Principal string
	Username  string
	// Port and RemAddr are recorded as the device presented them at
	// authentication. They are attributes, never part of any key; RemAddr is
	// compared on the enable exchange (spec §5.6).
	Port      string
	RemAddr   string
	PrivLvl   uint8
	CreatedAt time.Time
}

type Store interface {
	PutToken(ctx context.Context, k TokenKey, t Token) (count int, err error)
	Candidates(ctx context.Context, k TokenKey) ([]Token, error)
	RedeemAndReceipt(ctx context.Context, k TokenKey, secret []byte, rk ReceiptKey, r Receipt) error
	GetReceipt(ctx context.Context, rk ReceiptKey) (Receipt, error)
	PutContext(ctx context.Context, k ContextKey, c Context, ttl time.Duration) error
	GetContext(ctx context.Context, k ContextKey) (Context, error)
	DeleteContext(ctx context.Context, k ContextKey) error
}
