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
	Kind      string // "login" | "enable"
	Reusable  bool
	ExpiresAt time.Time
}

type ReceiptKey struct{ NAS, Port, Username string }

type Receipt struct {
	CredentialSHA256 [32]byte
	Status           uint8 // the authentication REPLY status that was sent
	CtxID            string
	ExpiresAt        time.Time
}

type ContextKey struct{ NAS, Port string }

type Context struct {
	CtxID     string
	Principal string
	Username  string
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
