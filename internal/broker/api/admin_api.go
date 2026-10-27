package api

import "time"

// The admin endpoints (spec §2, §5.1.4, §5.1.6; plan 12b): each write needs
// its right and a touch bound to the request (AdminProofHeader), and answers
// the text the admin socket used to print.

// MaxImportBytes bounds POST /v1/directory/import's body.
const MaxImportBytes = 16 << 20

// ImportReadTimeout is the read deadline POST /v1/directory/import sets for
// itself: the server's own timeout, sized for a mint, would bound a 16 MiB
// body to about 4.5 Mbit/s.
const ImportReadTimeout = 120 * time.Second

// LiftRequest is POST /v1/revocations/lift: a principal, or a certificate by
// its issuer and serial, exactly one.
type LiftRequest struct {
	Principal  string `json:"principal,omitempty"`
	CertIssuer string `json:"cert_issuer,omitempty"`
	CertSerial string `json:"cert_serial,omitempty"`
}

// PrincipalRequest is POST /v1/directory/forget, /unlock and, with one
// principal, /reset-second-factor.
type PrincipalRequest struct {
	Principal string `json:"principal"`
}

// ResetSecondFactorRequest is POST /v1/directory/reset-second-factor: one
// principal, or all.
type ResetSecondFactorRequest struct {
	Principal string `json:"principal,omitempty"`
	All       bool   `json:"all,omitempty"`
}

// AdminResult is what a proved admin call answers: Text is what the CLI
// prints, unchanged; Partial is set when a step did not finish and the call
// is to be run again.
type AdminResult struct {
	Text    string `json:"text"`
	Partial bool   `json:"partial,omitempty"`
}

// Revocation is one mark in force, as `port49 revoke --list` prints it: Kind
// is principal or cert; Since is RFC 3339. A mark that landed after a lift
// says so, with the lift's time and store revision when its record is still
// held.
type Revocation struct {
	Kind            string `json:"kind"`
	Principal       string `json:"principal,omitempty"`
	CertIssuer      string `json:"cert_issuer,omitempty"`
	CertSerial      string `json:"cert_serial,omitempty"`
	Since           string `json:"since"`
	Origin          string `json:"origin"`
	LandedAfterLift bool   `json:"landed_after_lift,omitempty"`
	LiftAt          string `json:"lift_at,omitempty"`
	LiftRevision    uint64 `json:"lift_revision,omitempty"`
}

// RevocationList is GET /v1/revocations. Text is what --list prints.
type RevocationList struct {
	Marks []Revocation `json:"marks"`
	Text  string       `json:"text"`
}
