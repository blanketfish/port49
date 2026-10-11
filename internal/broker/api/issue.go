package api

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// issuanceNonceLabel prefixes the key a sign-in's nonce names, so the hash
// is one no other use of the key's bytes makes.
const issuanceNonceLabel = "port49 issue v1\x00"

// IssuanceNonce is the nonce a sign-in for a port49-issued certificate sends
// (spec §13 decision 43 ruling 3): the base64url SHA-256 of a label and the
// key's PKIX DER. The broker issues a certificate only for the key the ID
// token's nonce names, so a token taken in flight certifies no other key.
func IssuanceNonce(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(issuanceNonceLabel))
	h.Write(der)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// IssueRequest is POST /v1/certificate's body: the key's PKCS #10 request,
// base64url DER. Its subject is not read; its signature proves the key.
type IssueRequest struct {
	CSR string `json:"csr"`
}

// IssueResponse is POST /v1/certificate's answer (decision 43 ruling 8).
type IssueResponse struct {
	// Certificate is PEM: the certificate, then the issuing CA's.
	Certificate string `json:"certificate"`
	Principal   string `json:"principal"`
	// Serial is as `port49 revoke --cert-serial` takes it.
	Serial   string `json:"serial"`
	NotAfter string `json:"not_after"`
}

// Issuance is /v1/config's word that the broker issues certificates over an
// OIDC sign-in (decision 43 ruling 18).
type Issuance struct {
	CertificateLifetimeSeconds int `json:"certificate_lifetime_seconds"`
}
