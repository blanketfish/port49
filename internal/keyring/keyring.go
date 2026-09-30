// Package keyring resolves which shared-key version, if any, obfuscated a packet.
// RFC 8907 carries no key identifier, so the daemon tries candidates and accepts
// the one under which the body is self-consistent (spec §10).
package keyring

import (
	"errors"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Version struct {
	Number  int
	Secret  []byte
	Retired bool // kept for diagnosis; never admits, never builds a reply
	// RetireAt is the first instant this version is refused: past it, it
	// identifies a device and never admits one, as a retired version does
	// (spec §10, "Retirement is enforced"). Zero is never.
	RetireAt time.Time
}

// Set is one key_ref's versions, ordered current, accepted..., retired...
type Set struct {
	Ref      string
	Versions []Version
}

type Diagnosis string

const (
	DiagValidated      Diagnosis = "validated"
	DiagMatchesRetired Diagnosis = "matches_retired"
	DiagNoKnownKey     Diagnosis = "no_known_key_matches"
	DiagUnencrypted    Diagnosis = "unencrypted_refused"
	DiagNotTACACS      Diagnosis = "not_tacacs"
	// Emitted by the connection layer for packets the keyring never sees; Resolve never returns them.
	DiagUnadmittedSource         Diagnosis = "unadmitted_source"          // source address not in the inventory
	DiagMalformedAfterValidation Diagnosis = "malformed_after_validation" // key validated, body did not decode
	DiagDeviceQuarantined        Diagnosis = "device_quarantined"         // admitted, but quarantined by policy (spec §10)
	DiagAdmissionRefused         Diagnosis = "admission_refused"          // in inventory, and admission refused it (spec §10)
)

type Result struct {
	Diagnosis Diagnosis
	Version   int
	Body      []byte // de-obfuscated; nil unless Diagnosis == DiagValidated
}

// Resolve tries every version in order and returns the first that validates.
// Header validation happens first so an unencrypted or non-TACACS packet never
// costs a pad computation or reaches a decoder.
func (s Set) Resolve(h wire.Header, obfuscated []byte, now time.Time) Result {
	if err := h.Validate(); err != nil {
		if errors.Is(err, wire.ErrUnencrypted) {
			return Result{Diagnosis: DiagUnencrypted}
		}
		return Result{Diagnosis: DiagNotTACACS}
	}
	for i, v := range s.Versions {
		body := wire.Obfuscate(h, v.Secret, obfuscated)
		if !Validates(h, body) {
			continue
		}
		if s.State(i, now) == "retired" {
			return Result{Diagnosis: DiagMatchesRetired, Version: v.Number}
		}
		return Result{Diagnosis: DiagValidated, Version: v.Number, Body: body}
	}
	return Result{Diagnosis: DiagNoKnownKey}
}

// State is version i's role at now: "current" (the first), "retired"
// (listed retired, or past its RetireAt), or "accept".
func (s Set) State(i int, now time.Time) string {
	v := s.Versions[i]
	switch {
	case v.Retired || (!v.RetireAt.IsZero() && !now.Before(v.RetireAt)):
		return "retired"
	case i == 0:
		return "current"
	}
	return "accept"
}

// Secret returns the secret for a version number, or nil if it is absent or retired.
func (s Set) Secret(version int) []byte {
	for _, v := range s.Versions {
		if v.Number == version && !v.Retired {
			return v.Secret
		}
	}
	return nil
}

// Validates reports whether body is self-consistent for the packet type the
// header announces. Every decoder enforces its length identity strictly, so a
// wrong key's pseudorandom bytes fail here with overwhelming probability.
func Validates(h wire.Header, body []byte) bool {
	var err error
	switch h.Type {
	case wire.TypeAuthen:
		if h.SeqNo == 1 {
			_, err = wire.DecodeAuthenStart(body)
		} else {
			_, err = wire.DecodeAuthenContinue(body)
		}
	case wire.TypeAuthor:
		_, err = wire.DecodeAuthorRequest(body)
	case wire.TypeAcct:
		_, err = wire.DecodeAcctRequest(body)
	default:
		return false
	}
	return err == nil
}
