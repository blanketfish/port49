package decision

import "slices"

// Reason is the closed vocabulary of spec §5.7. Handlers use these constants
// and nothing else; the log and the metrics share them.
type Reason string

const (
	// mint (broker; plan 7) — listed so the vocabulary is complete in one place.
	GrantsMatched         Reason = "grants_matched"
	NoGrantsMatched       Reason = "no_grants_matched"
	UsernameCollision     Reason = "username_collision"
	TrustDomainUnresolved Reason = "trust_domain_unresolved"
	// CandidateCapReached: token.candidate_cap unspent tokens already stand
	// for this (device, username). The mint is refused, never a redemption
	// (design §8).
	CandidateCapReached Reason = "candidate_cap_reached"

	// redeem
	TokenRedeemed Reason = "token_redeemed"
	TokenNotFound Reason = "token_not_found"
	// TokenSpent: the credential matched a receipt whose sliding window
	// (receipt_idle_ttl) or absolute cap (receipt_max_age) had passed. FAIL on
	// the wire, exactly as a wrong password is; the log is the only place the
	// two differ (spec §5.7; §13, decision 15).
	TokenSpent         Reason = "token_spent"
	DeviceMismatch     Reason = "device_mismatch"
	CredentialMismatch Reason = "credential_mismatch"
	ReceiptReplayed    Reason = "receipt_replayed"
	TokenKindMismatch  Reason = "token_kind_mismatch"
	StoreUnavailable   Reason = "store_unavailable"

	// authorize_session / authorize_command / escalate
	ContextMatched        Reason = "context_matched"
	EscalationGranted     Reason = "escalation_granted"
	PermitDominates       Reason = "permit_dominates"
	PipeStageDenied       Reason = "pipe_stage_denied"
	ServiceUnsupported    Reason = "service_unsupported"
	EnableRefused         Reason = "enable_refused"
	CeilingExceeded       Reason = "ceiling_exceeded"
	NoRuleMatched         Reason = "no_rule_matched"
	NoPermitDominatesDeny Reason = "no_permit_dominates_deny"
	ContextMissing        Reason = "context_missing"
	UsernameMismatch      Reason = "username_mismatch"
	RemAddrMismatch       Reason = "rem_addr_mismatch"
	PrivilegeExceeded     Reason = "privilege_exceeded"
	SessionExpired        Reason = "session_expired"
	ContextStale          Reason = "context_stale"
	CredentialRevoked     Reason = "credential_revoked"
	DeviceUnknown         Reason = "device_unknown"
	PlatformUnknown       Reason = "platform_unknown"
	BlobUnavailable       Reason = "blob_unavailable"
	// BlobPlatformMismatch: the context's blob was compiled for a platform
	// other than the one the daemon's inventory gives this device. Its
	// attributes and dialect are another platform's, so it is never answered
	// from; operational, like blob_unavailable (spec §5.7).
	BlobPlatformMismatch Reason = "blob_platform_mismatch"
	DeviceQuarantined    Reason = "device_quarantined"
)

// Events.
const (
	EventMint             = "mint"
	EventRedeem           = "redeem"
	EventAuthorizeSession = "authorize_session"
	EventAuthorizeCommand = "authorize_command"
	EventEscalate         = "escalate"
	EventBlob             = "blob"
	EventAccount          = "account"
	EventUnvalidated      = "unvalidated" // not a decision; header-only diagnosis record (spec §10)
	// EventAccountGap is not a decision: accounting records port49 received
	// and could not write, by stage, so a reader of the log knows the stream
	// has a hole there (spec §5.7, §9).
	EventAccountGap = "account_gap"
)

// EventRefresh is the broker carrying the policy in force into a live login
// context (spec §5.1.3): the policy written into it, or the context revoked.
// It is a decision, so it has a verdict and a reason from the table above.
const EventRefresh = "refresh"

const (
	VerdictPermit = "permit"
	VerdictDeny   = "deny"
)

// reasons is every Reason above; reasons_test.go keeps it complete.
var reasons = []Reason{
	GrantsMatched, NoGrantsMatched, UsernameCollision, TrustDomainUnresolved, CandidateCapReached,
	TokenRedeemed, TokenNotFound, TokenSpent, DeviceMismatch, CredentialMismatch, ReceiptReplayed,
	TokenKindMismatch, StoreUnavailable,
	ContextMatched, EscalationGranted, PermitDominates, PipeStageDenied, ServiceUnsupported, EnableRefused,
	CeilingExceeded, NoRuleMatched, NoPermitDominatesDeny, ContextMissing, UsernameMismatch, RemAddrMismatch,
	PrivilegeExceeded, SessionExpired, ContextStale, CredentialRevoked, DeviceUnknown, PlatformUnknown,
	BlobUnavailable, BlobPlatformMismatch, DeviceQuarantined,
}

// Known reports whether r is in spec §5.7's vocabulary. A policy test's
// expected reason is checked against it, so a typo fails at load rather than
// as a test that can never pass.
func Known(r Reason) bool { return slices.Contains(reasons, r) }
