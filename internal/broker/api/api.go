// Package api is the broker's wire format (design §17), shared by the broker
// and every client of it — the agent first — so the two cannot drift. Every
// key is snake_case.
package api

import "fmt"

// Config is GET /v1/config: discovery data, never fleet information.
type Config struct {
	Methods              []string `json:"methods"`
	MaxSessionAgeSeconds int      `json:"max_session_age_seconds"`
	BatchMax             int      `json:"batch_max"`
	// CeilingWarningSeconds is session.ceiling_warning: how near a device's
	// ceiling `port49 token` warns (plan 7b).
	CeilingWarningSeconds int `json:"ceiling_warning_seconds,omitempty"`
}

// MintRequest is POST /v1/tokens. TTLSeconds is a request, not an
// instruction: the broker clamps it to the subject's token_ttl.
type MintRequest struct {
	Devices    []string `json:"devices"`
	Enable     bool     `json:"enable"`
	TTLSeconds int      `json:"ttl_seconds"`
	Purpose    string   `json:"purpose"`
}

// MintItem is one device's answer. Verdict and Reason use the decision log's
// closed vocabulary (spec §5.7), so the response and the audit record agree.
// An item the broker could not decide — a fault on the broker's side, not a
// refusal of the caller — carries Error and Detail instead of a Verdict, and
// has no decision record.
type MintItem struct {
	Device    string `json:"device"`
	Verdict   string `json:"verdict,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Address   string `json:"address,omitempty"`
	Platform  string `json:"platform,omitempty"`
	Username  string `json:"username,omitempty"`
	Login     string `json:"login,omitempty"`
	Enable    string `json:"enable,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
	Detail    string `json:"detail,omitempty"`
	// SessionExpiresAt is when a login with this token stops being
	// authorized: the connection's authentication plus the device's
	// max_session_age (spec §5.6). Empty when the roles say never.
	SessionExpiresAt string `json:"session_expires_at,omitempty"`
	// Replayed is the broker's own, never on the wire: this permit is an
	// idempotent replay, which recorded no permit of its own.
	Replayed bool `json:"-"`
}

// String is the item with its tokens withheld, so that a %v anywhere — a
// test's failure message, a debug line — never prints one (plan 7b final
// review M-1). The wire form is JSON and is untouched.
func (it MintItem) String() string {
	type plain MintItem
	p := plain(it)
	p.Login, p.Enable = withheld(p.Login), withheld(p.Enable)
	return fmt.Sprintf("%+v", p)
}

// GoString is String, for %#v.
func (it MintItem) GoString() string { return it.String() }

// withheld stands in for a credential in printed output: whether there was
// one, never what it was.
func withheld(s string) string {
	if s == "" {
		return ""
	}
	return "<withheld>"
}

// MintResponse is POST /v1/tokens' 200: partial failure is per item, never at
// the top level (design §17).
type MintResponse struct {
	Principal string     `json:"principal"`
	Subject   string     `json:"subject,omitempty"`
	Results   []MintItem `json:"results"`
}

// Error is every non-200 body.
type Error struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}
