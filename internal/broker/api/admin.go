package api

import (
	"crypto/sha256"
	"time"
)

// An admin-level call proves a touch bound to its own request (spec §5.1.6;
// §13 decision 54 ruling 15). These are the two sides' shared definitions:
// the exporter label, the header, the request binding and the signed message.

// AdminExporterLabel is the TLS exporter label an admin proof covers
// (RFC 8446 §7.5). It is not the per-login label, so a per-login proof is
// never an admin proof.
const AdminExporterLabel = "EXPORTER-port49-admin"

// AdminProofHeader carries the proof of a retried admin call: base64url of
// an AdminProof's JSON.
const AdminProofHeader = "Port49-Admin-Proof"

const (
	adminRequestContext = "port49 admin request v1\x00"
	adminContext        = "port49 admin v1\x00"
)

// AdminRequestSHA256 is the request an admin proof is made for:
// SHA-256("port49 admin request v1\0" ‖ method ‖ 0 ‖ path ‖ 0 ‖ body), over
// the exact body bytes. path is the request's URL.RequestURI(), path and
// query, on both sides.
func AdminRequestSHA256(method, path string, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(adminRequestContext))
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(body)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// AdminMessage is what the touch key signs for an admin call: a fixed
// context of its own, the challenge, the request's hash and the held
// connection's exporter value under AdminExporterLabel.
func AdminMessage(challenge []byte, request [32]byte, ekm []byte) []byte {
	m := make([]byte, 0, len(adminContext)+len(challenge)+len(request)+len(ekm))
	m = append(m, adminContext...)
	m = append(m, challenge...)
	m = append(m, request[:]...)
	return append(m, ekm...)
}

// AdminChallenge is the answer to an admin-level call that carried no proof:
// what the call is, so the person is shown the intent, and the challenge to
// sign.
type AdminChallenge struct {
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AdminProof is the header's value, JSON then base64url: the challenge, the
// touch key's signature over AdminMessage, and the attestations [touch slot,
// f9 device, session slot], each base64url DER.
type AdminProof struct {
	Challenge   string   `json:"challenge"`
	Signature   string   `json:"signature"`
	Attestation []string `json:"attestation"`
}
