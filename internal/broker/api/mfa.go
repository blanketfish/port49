package api

import (
	"crypto/sha256"
	"encoding/base64"
)

// AgentSessionHeader carries the agent's session: 32 random bytes,
// base64url, drawn at the agent's start (decision 45 ruling 15). The broker
// keeps its SHA-256 and never the value.
const AgentSessionHeader = "Port49-Agent-Session"

// MFAExporterLabel is the TLS exporter label a touch proof covers
// (RFC 8446 §7.5): the exporter value is the held connection's own, so a
// signature made over another connection's does not verify (decision 45
// ruling 12).
const MFAExporterLabel = "EXPORTER-port49-per-login-mfa"

// MFAChallengeLen is a challenge's length in bytes.
const MFAChallengeLen = 32

const (
	mfaContext = "port49 per-login mfa v1\x00"
	mfaNonce   = "port49 per-login v1\x00"
)

// MFAMessage is what the touch key signs: a fixed context, so the key's
// signature means this and nothing else, then the challenge, then the held
// connection's exporter value.
func MFAMessage(challenge, ekm []byte) []byte {
	m := make([]byte, 0, len(mfaContext)+len(challenge)+len(ekm))
	return append(append(append(m, mfaContext...), challenge...), ekm...)
}

// MFANonce is the nonce an idp_mfa sign-in carries:
// base64url(SHA-256("port49 per-login v1\0" ‖ challenge)), no padding.
func MFANonce(challenge []byte) string {
	h := sha256.New()
	h.Write([]byte(mfaNonce))
	h.Write(challenge)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// MFALevel is one level of a requirement, as the API and the record say it.
type MFALevel struct {
	Level           string   `json:"level"`
	Accept          []string `json:"accept"`
	ReuseForSeconds int      `json:"reuse_for_seconds"`
}

// PerLoginMFA is a requirement an item or a refresh answers with: the
// device, the challenge to prove, the policy's accept, the methods this
// broker verifies of them, and where each part came from.
type PerLoginMFA struct {
	Device          string     `json:"device,omitempty"`
	Challenge       string     `json:"challenge"`
	ExpiresAt       string     `json:"expires_at"`
	Accept          []string   `json:"accept"`
	Methods         []string   `json:"methods"`
	ReuseForSeconds int        `json:"reuse_for_seconds"`
	ReuseFrom       string     `json:"reuse_from"`
	Levels          []MFALevel `json:"levels"`
}

// MFAConfig is GET /v1/config's per_login_mfa: what this broker verifies
// now, and the acr_values an idp_mfa sign-in sends.
type MFAConfig struct {
	Methods   []string `json:"methods"`
	ACRValues string   `json:"acr_values,omitempty"`
}

// MFAProofRequest is POST /v1/mfa's body.
type MFAProofRequest struct {
	Challenge   string   `json:"challenge"`
	Method      string   `json:"method"`                // hardware_key_touch | idp_mfa
	Signature   string   `json:"signature,omitempty"`   // touch: base64url over MFAMessage
	Attestation []string `json:"attestation,omitempty"` // touch: base64url DER: [touch slot, f9 device, session slot]
}

// MFAProofResponse is POST /v1/mfa's 200.
type MFAProofResponse struct {
	Method   string `json:"method"`
	ProvedAt string `json:"proved_at"`
}
