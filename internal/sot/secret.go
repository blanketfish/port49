// Package sot reads a source of truth, NetBox or Nautobot, into port49's
// inventory facts (spec §10, "Connectors and sync cadence"; §13, decision
// 31). It is the contributable surface the inventory service isolates: it
// holds the source's token, never writes, and returns facts only — no key
// assignment (spec §13, decision 30). It imports nothing from
// internal/inventory, which builds one Source per configured source.
package sot

import (
	"fmt"
	"io"
)

// Secret is a credential named by a secret_ref (env: or file:): a source's API token,
// or its webhook secret. It prints as <redacted> under every fmt verb and in
// JSON, so a configuration printed whole — by a test, a panic, a %+v — never
// carries it. fmt calls Format only on a value it can reach through
// exported fields; reached through an unexported one (a Source's cfg, a
// client's auth) a Secret is printed field by field, so the value sits
// behind a pointer and prints as an address there (pre-flight M1). Reveal is
// the one way to the value, at the one place that sends or checks it.
type Secret struct{ p *string }

// NewSecret holds v.
func NewSecret(v string) Secret { return Secret{&v} }

// Reveal is the value: for the Authorization header, or the HMAC key.
func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return *s.p
}

// Empty is whether there is no value.
func (s Secret) Empty() bool { return s.Reveal() == "" }

func (Secret) Format(f fmt.State, _ rune)   { io.WriteString(f, "<redacted>") }
func (Secret) String() string               { return "<redacted>" }
func (Secret) GoString() string             { return "<redacted>" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"<redacted>"`), nil }
