package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

// RefreshExporterLabel is the TLS exporter label a refresh signature covers
// (RFC 8446 §7.5): the exporter value is the connection's own, so a nonce
// answered on another connection does not verify (spec §5.6; decision 33).
const RefreshExporterLabel = "EXPORTER-port49-refresh"

// RefreshNonceLen is the challenge's length in bytes.
const RefreshNonceLen = 32

const refreshContext = "port49 session refresh v1\x00"

// RefreshMessage is what the agent signs and the broker verifies: a fixed
// context string, so the key's signature means this and nothing else, then
// the nonce, then the connection's exporter value.
func RefreshMessage(nonce, ekm []byte) []byte {
	m := make([]byte, 0, len(refreshContext)+len(nonce)+len(ekm))
	return append(append(append(m, refreshContext...), nonce...), ekm...)
}

// RefreshAlgorithm is the one signature algorithm a key of this type signs
// a refresh with: ECDSA with SHA-256, RSA-PSS with SHA-256, Ed25519.
func RefreshAlgorithm(pub crypto.PublicKey) (x509.SignatureAlgorithm, bool) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA256, true
	case *rsa.PublicKey:
		return x509.SHA256WithRSAPSS, true
	case ed25519.PublicKey:
		return x509.PureEd25519, true
	}
	return 0, false
}

// SignRefresh signs msg with signer as RefreshAlgorithm says for its key.
func SignRefresh(signer crypto.Signer, msg []byte) ([]byte, error) {
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(msg)
		return signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	case *rsa.PublicKey:
		sum := sha256.Sum256(msg)
		return signer.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case ed25519.PublicKey:
		return signer.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	return nil, errors.New("api: a refresh is signed by an ECDSA, RSA or Ed25519 key")
}

// RefreshChallenge is POST /v1/refresh/challenge's answer.
type RefreshChallenge struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

// RefreshRequest is POST /v1/refresh: the nonce and the signature over
// RefreshMessage, both base64url without padding.
type RefreshRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// RefreshedSession is one live context a refresh visited: its outcome
// (extended, revoked, past_grace, not_judged), its ceiling when extended,
// and whether the device's own session is out of the extension's reach.
type RefreshedSession struct {
	Device         string `json:"device"`
	Username       string `json:"username"`
	Outcome        string `json:"outcome"`
	SessionExpires string `json:"session_expires,omitempty"`
	Unreached      bool   `json:"unreached,omitempty"`
}

// RefreshResponse is POST /v1/refresh's 200.
type RefreshResponse struct {
	AuthTime      string             `json:"auth_time"`
	SessionEndsAt string             `json:"session_ends_at"`
	Sessions      []RefreshedSession `json:"sessions"`
}
