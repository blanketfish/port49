package decision

// Reason is the closed vocabulary of spec §5.7. Handlers use these constants
// and nothing else; the log and the metrics share them.
type Reason string

const (
	// mint (broker; plan 7) — listed so the vocabulary is complete in one place.
	GrantsMatched         Reason = "grants_matched"
	NoGrantsMatched       Reason = "no_grants_matched"
	UsernameCollision     Reason = "username_collision"
	TrustDomainUnresolved Reason = "trust_domain_unresolved"

	// redeem
	TokenRedeemed      Reason = "token_redeemed"
	TokenNotFound      Reason = "token_not_found"
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
	DeviceQuarantined     Reason = "device_quarantined"
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
)

const (
	VerdictPermit = "permit"
	VerdictDeny   = "deny"
)
