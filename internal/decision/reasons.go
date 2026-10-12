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
	// IdentityUnmapped: the client certificate maps to no usable
	// directory entry (spec §5.7; decision 38). IdentityAmbiguous: to two
	// or more, never the first (design §7). DirectoryUnavailable: no
	// directory server answered and no membership verified within
	// directory.grace is held. CompositionRefused: the principal's
	// subjects compose on the device to a reply a joint check refuses.
	IdentityUnmapped     Reason = "identity_unmapped"
	IdentityAmbiguous    Reason = "identity_ambiguous"
	DirectoryUnavailable Reason = "directory_unavailable"
	CompositionRefused   Reason = "composition_refused"

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
	// RevocationLifted: a revoke record for an operator lifting a revocation
	// (spec §5.1.4, §5.7). A permit.
	RevocationLifted Reason = "revocation_lifted"
	// APIRightMissing: an API call asked to act on another principal's
	// tokens, sessions or decisions, and the caller's subject declares no
	// api: right that unlocks it (spec §2, §5.7; design §17). A denial; the
	// API answers 403 and does nothing.
	APIRightMissing Reason = "api_right_missing"
	DeviceUnknown   Reason = "device_unknown"
	PlatformUnknown Reason = "platform_unknown"
	BlobUnavailable Reason = "blob_unavailable"
	// BlobPlatformMismatch: the context's blob was compiled for a platform
	// other than the one the daemon's inventory gives this device. Its
	// attributes and dialect are another platform's, so it is never answered
	// from; operational, like blob_unavailable (spec §5.7).
	BlobPlatformMismatch Reason = "blob_platform_mismatch"
	DeviceQuarantined    Reason = "device_quarantined"
	// ProjectionFailClosed: a session on a projected platform answered with
	// its composition's fail-closed reply, deny every command but what the
	// projection proved, because the composition cannot be told to the
	// device faithfully (spec §8; §13 decision 26). A permit: the session
	// opens, told less than port49 would permit. `policy test` fails on it.
	ProjectionFailClosed Reason = "projection_fail_closed"

	// CertificateIssued: the broker issued a short-lived client certificate
	// for the key a person's sign-in names (spec §5.7; §13 decision 43
	// ruling 8). A permit on the issue event.
	CertificateIssued Reason = "certificate_issued"

	// The per-login proof (spec §5.1.5; §5.7; §13 decision 45).
	// PerLoginMFARequired: a mint or refresh under a requirement no proof
	// covers. PerLoginMFAProved and PerLoginMFARefused: a proof posted to
	// POST /v1/mfa verified, or did not. PerLoginMFAUnavailable: the
	// requirement accepts no method this broker can verify now.
	PerLoginMFARequired    Reason = "per_login_mfa_required"
	PerLoginMFAProved      Reason = "per_login_mfa_proved"
	PerLoginMFARefused     Reason = "per_login_mfa_refused"
	PerLoginMFAUnavailable Reason = "per_login_mfa_unavailable"
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
	// EventInventoryChange is not a decision: a security-relevant change a
	// bundle swap made, written by the component that swapped (spec §5.7,
	// §10).
	EventInventoryChange = "inventory_change"
	// EventDirectoryForget is not a decision: an operator removed a
	// principal's directory membership, and with it the entry the principal
	// was pinned to (spec §5.7; plan 7g, Ruling 3's escape).
	EventDirectoryForget = "directory_forget"
)

// EventRefresh is the broker carrying the policy in force into a live login
// context (spec §5.1.3): the policy written into it, or the context revoked.
// It is a decision, so it has a verdict and a reason from the table above.
const EventRefresh = "refresh"

// EventRevoke is a revocation by principal or by certificate, or one lifted
// (spec §5.1.4, §5.7): deny credential_revoked, or permit revocation_lifted.
const EventRevoke = "revoke"

// EventIdentity is GET /v1/identity: what the broker resolved the caller to
// (design §17; spec §5.7): permit grants_matched, or deny
// no_grants_matched.
const EventIdentity = "identity"

// EventExplain is POST /v1/explain: a hypothetical decision the broker
// answered, about the caller or, under explain_others, another principal.
// It authorizes nothing; its verdict and reason are the answer given, or
// deny api_right_missing. It never carries the command asked (spec §5.7).
const EventExplain = "explain"

// EventIssue is POST /v1/certificate: whether a person's OIDC sign-in is
// exchanged for a certificate the broker issues (spec §5.7; §13 decision
// 43): permit certificate_issued, or a deny with the refusal's reason.
const EventIssue = "issue"

// EventPerLoginMFA is POST /v1/mfa: whether a per-login proof is accepted
// (spec §5.7; §13 decision 45): permit per_login_mfa_proved, or deny
// per_login_mfa_refused (store_unavailable when the broker could not judge).
const EventPerLoginMFA = "per_login_mfa"

const (
	VerdictPermit = "permit"
	VerdictDeny   = "deny"
)

// reasons is every Reason above; reasons_test.go keeps it complete.
var reasons = []Reason{
	GrantsMatched, NoGrantsMatched, UsernameCollision, TrustDomainUnresolved, CandidateCapReached,
	IdentityUnmapped, IdentityAmbiguous, DirectoryUnavailable, CompositionRefused,
	TokenRedeemed, TokenNotFound, TokenSpent, DeviceMismatch, CredentialMismatch, ReceiptReplayed,
	TokenKindMismatch, StoreUnavailable,
	ContextMatched, EscalationGranted, PermitDominates, PipeStageDenied, ServiceUnsupported, EnableRefused,
	CeilingExceeded, NoRuleMatched, NoPermitDominatesDeny, ContextMissing, UsernameMismatch, RemAddrMismatch,
	PrivilegeExceeded, SessionExpired, ContextStale, CredentialRevoked, DeviceUnknown, PlatformUnknown,
	BlobUnavailable, BlobPlatformMismatch, DeviceQuarantined, ProjectionFailClosed, RevocationLifted,
	APIRightMissing, CertificateIssued,
	PerLoginMFARequired, PerLoginMFAProved, PerLoginMFARefused, PerLoginMFAUnavailable,
}

// Known reports whether r is in spec §5.7's vocabulary. A policy test's
// expected reason is checked against it, so a typo fails at load rather than
// as a test that can never pass.
func Known(r Reason) bool { return slices.Contains(reasons, r) }
