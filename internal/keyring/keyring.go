// Package keyring resolves which shared-key version, if any, obfuscated a packet.
// RFC 8907 carries no key identifier, so the daemon tries candidates and accepts
// the one under which the body is self-consistent (spec §10).
package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/secretref"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Version struct {
	Number  int
	Secret  secretref.Secret
	Retired bool // kept for diagnosis; never admits, never builds a reply
	// RetireAt is the first instant this version is refused: past it, it
	// identifies a device and never admits one, as a retired version does
	// (spec §10, "Retirement is enforced"). Zero is never.
	RetireAt time.Time
}

// String is the version as it prints: everything but the secret, which no
// verb and no encoding of a Version carries.
func (v Version) String() string {
	return fmt.Sprintf("keyring.Version{Number: %d, Secret: <redacted>, Retired: %t, RetireAt: %s}", v.Number, v.Retired,
		v.RetireAt.Format(time.RFC3339))
}

// GoString is String, for %#v.
func (v Version) GoString() string { return v.String() }

// Format prints String under every verb, so %x and %s cannot reach Secret.
func (v Version) Format(f fmt.State, _ rune) { fmt.Fprint(f, v.String()) }

// MarshalJSON withholds the secret.
func (v Version) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Number   int
		Secret   string
		Retired  bool
		RetireAt time.Time
	}{v.Number, "<redacted>", v.Retired, v.RetireAt})
}

// MarshalYAML withholds the secret.
func (v Version) MarshalYAML() (any, error) {
	return struct {
		Number   int       `yaml:"number"`
		Secret   string    `yaml:"secret"`
		Retired  bool      `yaml:"retired"`
		RetireAt time.Time `yaml:"retire_at"`
	}{v.Number, "<redacted>", v.Retired, v.RetireAt}, nil
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
	DiagAdmissionWithdrawn       Diagnosis = "admission_withdrawn"        // an open connection's device renamed, re-keyed or re-platformed by a reload (spec §10)
	DiagTransportMismatch        Diagnosis = "transport_mismatch"         // an admitted device on the listener it does not speak (spec §10)
	DiagTLSRefused               Diagnosis = "tls_refused"                // the RFC 9887 listener refused or ended it; tls_outcome says why
	DiagObfuscatedOverTLS        Diagnosis = "obfuscated_over_tls"        // a packet over TLS with the unencrypted flag clear (RFC 9887 §4)
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
		body := wire.Obfuscate(h, v.Secret.Bytes(), obfuscated)
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
			return v.Secret.Bytes()
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
