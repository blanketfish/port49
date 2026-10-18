// Package decision is the single emitter for port49's own record stream:
// decisions, accounting, blobs, and header-only diagnosis records (spec §5.7).
package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

type Record struct {
	TS          time.Time    `json:"ts"`
	Event       string       `json:"event"`
	Verdict     string       `json:"verdict,omitempty"`
	Reason      Reason       `json:"reason,omitempty"`
	Principal   string       `json:"principal,omitempty"`
	Auth        *Auth        `json:"auth,omitempty"`
	Device      *Device      `json:"device,omitempty"`
	Session     *Session     `json:"session,omitempty"`
	Request     *Request     `json:"request,omitempty"`
	Reply       *Reply       `json:"reply,omitempty"`
	Flags       string       `json:"flags,omitempty"`
	Attribution string       `json:"attribution,omitempty"`
	TaskID      string       `json:"task_id,omitempty"`
	AcctRecord  *AcctRecord  `json:"record,omitempty"`
	Mint        *Mint        `json:"mint,omitempty"`
	Policy      *Policy      `json:"policy,omitempty"`
	Blob        *Blob        `json:"blob,omitempty"`
	Unvalidated *Unvalidated `json:"unvalidated,omitempty"`
	ServerMsg   string       `json:"server_msg,omitempty"`
	Gap         *Gap         `json:"gap,omitempty"`
	// Change is the inventory_change record's body (spec §5.7, §10).
	Change *Change `json:"change,omitempty"`
	// Forget is the directory_forget record's body (spec §5.7).
	Forget *Forget `json:"forget,omitempty"`
	// Sweep names the sweep a mint record's device came from, when the
	// request was by scope (spec §13 decision 42 ruling 4).
	Sweep *Sweep `json:"sweep,omitempty"`
	// Revocation is the revoke record's body (spec §5.7).
	Revocation *Revocation `json:"revocation,omitempty"`
	// Explain is an explain record's own (spec §5.7): who asked, and whether
	// a command was asked. The command itself is never recorded. An explain
	// record carries no Auth: its Principal is whom it was about, and the
	// caller's credential is in AskedByFingerprint (decision 34).
	Explain *Explain `json:"explain,omitempty"`
	// Certificate is an issue record's certificate (spec §5.7; §13 decision
	// 43 ruling 22).
	Certificate *Certificate `json:"certificate,omitempty"`
	// PerLoginMFA is the per-login requirement a mint or refresh record was
	// judged under, or a proof record's method and challenge hash (spec
	// §5.7; §13 decision 45 ruling 19).
	PerLoginMFA *PerLoginMFA `json:"per_login_mfa,omitempty"`
	// SignIn is a directory-password sign-in's source and, on a refusal, what
	// failed (spec §5.7; §13 decision 47).
	SignIn *SignIn `json:"sign_in,omitempty"`
	// SecondFactorReset is the second_factor_reset record's body (spec §5.7).
	SecondFactorReset *SecondFactorReset `json:"second_factor_reset,omitempty"`
	// SignInUnlock is the sign_in_unlock record's body (spec §5.7).
	SignInUnlock *SignInUnlock `json:"sign_in_unlock,omitempty"`
	// EnrollmentsImport is the enrollments_import record's body (spec §5.7).
	EnrollmentsImport *EnrollmentsImport `json:"enrollments_import,omitempty"`
	// IndexError names what a failed index write cost, on the record for the
	// session that lost it. Revocation must report the contexts it could not
	// reach (spec §5.6), and this is the only place that says which they are.
	IndexError string `json:"index_error,omitempty"`
}

// SignIn is what a directory-password sign-in record says of the attempt:
// the source network it came from, which check failed and, for a clock too
// far off, by how much. Never the name typed, the password, the code or the
// secret.
type SignIn struct {
	Source          string `json:"source"`
	Failed          string `json:"failed,omitempty"`
	SkewSeconds     int    `json:"skew_seconds,omitempty"`
	DirectoryResult int    `json:"directory_result,omitempty"`
	DirectoryData   string `json:"directory_data,omitempty"`
}

// SecondFactorReset is an operator's reset of a person's second factor, or
// init-enrollments creating the store (Created). It names the enrollment
// that was cleared, never its secret.
type SecondFactorReset struct {
	EnrolledAt   string `json:"enrolled_at,omitempty"`
	EnrolledFrom string `json:"enrolled_from,omitempty"`
	ReopenUntil  string `json:"reopen_until,omitempty"` // absent on created
	All          bool   `json:"all,omitempty"`          // reset-second-factor --all
	Created      bool   `json:"created,omitempty"`      // init-enrollments (D7)
	Origin       string `json:"origin"`
}

// SignInUnlock is an operator clearing a principal's failed-attempt count.
type SignInUnlock struct {
	// Failures is the count the answering broker held; nil, and so absent,
	// when its session store did not answer the clear: the unlock is in
	// force but the count is unknown, which is not zero.
	Failures *int   `json:"failures,omitempty"`
	Origin   string `json:"origin"`
}

// EnrollmentsImport is `port49 directory import` filling or replacing the
// enrollment store (decision 47 D13).
type EnrollmentsImport struct {
	Records    int    `json:"records"`
	ExportedAt string `json:"exported_at"`
	Replaced   bool   `json:"replaced,omitempty"`
	Origin     string `json:"origin"`
}

// PerLoginMFA is a record's per-login part. A mint or refresh record under a
// requirement carries accept, reuse_for_seconds, levels and, where a proof
// covered it, method, proved_at and reused; a per_login_mfa record carries
// method and challenge_sha256 alone. The challenge itself is never logged.
type PerLoginMFA struct {
	Accept          []string `json:"accept,omitempty"`
	ReuseForSeconds *int     `json:"reuse_for_seconds,omitempty"`
	Levels          []string `json:"levels,omitempty"`
	Method          string   `json:"method,omitempty"`
	ProvedAt        string   `json:"proved_at,omitempty"`
	Reused          bool     `json:"reused,omitempty"`
	ChallengeSHA256 string   `json:"challenge_sha256,omitempty"`
}

// Certificate is the certificate an issue record names: its serial, as
// `port49 revoke --cert-serial` takes it, the issuing CA's DN, its
// fingerprint and its end. Identity, not a secret (spec §5.1.4).
type Certificate struct {
	Serial      string `json:"serial"`
	Issuer      string `json:"issuer"`
	Fingerprint string `json:"fingerprint"`
	NotAfter    string `json:"not_after"`
}

type Auth struct {
	Method string `json:"method"`
	// CredentialSHA256 is omitempty because a mint record has no value for it.
	// §5.7 makes it "the same hash the receipt binds" — the hash of what was
	// presented on the wire — and says a mint record carries token_sha256 per
	// minted token *instead*, since no context and no presentation exist yet.
	// The minter is handed store.Credential, which is identity and not a
	// secret, so any hash it could compute would join to nothing. A blank join
	// key is worse than an absent one: it is present on every mint record in
	// the fleet and therefore joins everything to everything.
	CredentialSHA256 string `json:"credential_sha256,omitempty"`
	// Fingerprint is the sha256 of a client certificate the trust anchor
	// verified and the broker then refused (expired since, no clientAuth, no
	// one email SAN): on a `mint deny trust_domain_unresolved` it says whose
	// certificate it was. Identity, not a secret (spec §5.1.4).
	Fingerprint string `json:"fingerprint,omitempty"`
	// Directory is where the membership this decision used came from. It
	// names no group: Policy.Subjects says which subjects matched (spec
	// §5.7; decision 38).
	Directory *Directory `json:"directory,omitempty"`
	// OIDC is the verified token's identity on a broker event whose caller
	// presented one (plan 7h). A bearer that did not verify has none.
	OIDC *OIDC `json:"oidc,omitempty"`
	// K8s is a verified service account token's identity on a broker event
	// whose caller presented one (plan 10); never set with OIDC.
	K8s *K8s `json:"k8s,omitempty"`
	// DirectoryPassword is how a directory-password sign-in authenticated,
	// recorded because it cannot be established afterwards (spec §5.7; §13
	// decision 47): the methods used, when, and a hash of the directory
	// entry. Never the password or the code.
	DirectoryPassword *DirectoryPassword `json:"directory_password,omitempty"`
}

// DirectoryPassword is a directory-password sign-in's authentication.
type DirectoryPassword struct {
	AMR         []string `json:"amr"`
	AuthTime    string   `json:"auth_time"`
	EntrySHA256 string   `json:"entry_sha256"`
}

// OIDC is what an OIDC caller's verified token said of how it
// authenticated (spec §5.1.4, §5.7; decision 39): the issuer, the subject,
// the provider's own session id, and amr and acr, recorded because how
// someone authenticated cannot be established afterwards, and consulted by
// nothing (decision 13). Only a verified token's claims are ever here.
type OIDC struct {
	Issuer   string   `json:"issuer"`
	Sub      string   `json:"sub"`
	Sid      string   `json:"sid,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AuthTime string   `json:"auth_time,omitempty"`
}

// K8s is a verified service account token's identity on a broker event (plan
// 10; spec §5.7 auth.k8s): which cluster and pod minted, unrecoverable
// afterwards. Cluster is the accepting verifier's configured name: several
// clusters may vouch for one namespace (decision 49 ruling 4).
type K8s struct {
	Cluster           string `json:"cluster"`
	Issuer            string `json:"issuer"`
	Sub               string `json:"sub"`
	ServiceAccountUID string `json:"serviceaccount_uid"`
	Pod               string `json:"pod"`
	PodUID            string `json:"pod_uid"`
	Node              string `json:"node,omitempty"`
	JTI               string `json:"jti,omitempty"`
}

// Directory says where a broker event's directory membership was read:
// fresh from a server for this request, or the store's (grace), verified at
// VerifiedAt. Server and Site are where it was read.
type Directory struct {
	Source     string `json:"source"`      // "fresh" | "grace"
	VerifiedAt string `json:"verified_at"` // FormatTime
	Server     string `json:"server,omitempty"`
	Site       string `json:"site,omitempty"`
}

type Device struct {
	NAS      string `json:"nas"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	// KeyRef and KeyVersion name the key that validated the exchange: set on
	// every record of a validated exchange, and on none other (spec §5.7,
	// §10). `port49 keys status` reads a rotation's phase-out from them.
	KeyRef     string `json:"key_ref,omitempty"`
	KeyVersion int    `json:"key_version,omitempty"`
	// Transport is "tls" on a record of an exchange on the RFC 9887
	// listener, absent on the RFC 8907 listener's; CertSHA256 is then the
	// device's verified leaf certificate (spec §5.7; §13 decision 50 ruling
	// 16). Such a record has no KeyRef.
	Transport  string `json:"transport,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
}

type Session struct {
	CtxID    string `json:"ctx_id"`
	Username string `json:"username,omitempty"`
	// ReplacedCtxID is set on a redeem that replaced an existing context for
	// the same (nas, username) rather than joining it: another principal under
	// the same username, or the same principal's context past its session
	// ceiling. It names the displaced ctx_id so the records before and after
	// can still be joined (spec §5.6). A second login by the same principal
	// joins and sets nothing here.
	ReplacedCtxID string `json:"replaced_ctx_id,omitempty"`
	// ReplacedUnreadable is set on a redeem that replaced a context the
	// sealing layer could not open — sealed under a key that has left the
	// two-key window, or failing authentication. Its ctx_id is sealed, so
	// ReplacedCtxID cannot name it, and this says a context was displaced all
	// the same (spec §5.6).
	ReplacedUnreadable bool `json:"replaced_unreadable,omitempty"`
	// RevokedAt is set on a redeem refused `credential_revoked`: the login
	// would have joined a context whose revocation its token, minted before
	// it, cannot lift. It is the revocation that refused it, rendered as ts
	// is (FormatTime), so the refusal explains itself (spec §5.6).
	RevokedAt string `json:"revoked_at,omitempty"`
	// PrivilegeClamped is set on a redeem that joined a context and lowered
	// the level it held to the newest login's ceiling. The other windows'
	// next command above To is denied privilege_exceeded, and this is the
	// line that says why (spec §5.3). Privilege above is the START level,
	// not the context's.
	PrivilegeClamped *PrivilegeClamp `json:"privilege_clamped,omitempty"`
	// AuthTime and SessionExpires are on a refresh record that moved them:
	// a session refresh's new authentication and ceiling, or a policy
	// refresh's shortened ceiling (spec §5.6, §5.7). SessionExpires is also
	// on a redeem refused `session_expired`: the ceiling that refused it.
	// Rendered as ts is.
	AuthTime       string `json:"auth_time,omitempty"`
	SessionExpires string `json:"session_expires,omitempty"`
	// Unreached is a refresh record's context on a platform that never asks
	// about a command, or on a device the inventory gives no platform: the
	// live session keeps what it had (spec §13, decision 21).
	Unreached bool `json:"unreached,omitempty"`
	// Port and RemAddr are as seen on this exchange, which is not necessarily
	// what the context recorded: they are part of no key (spec §13,
	// decision 15).
	Port    string `json:"port"`
	RemAddr string `json:"rem_addr"`
	// Privilege is, on an authorize_session or authorize_command record, the
	// priv_lvl of the request's header: the level the device asked at. On
	// other events it is what they say (a refresh's is the context's level, a
	// redeem's the login START's).
	Privilege uint8 `json:"privilege"`
	// HeldPrivilege is the context's level when the request arrived, before
	// any raise this request makes, on every authorize_session and
	// authorize_command record whose context was read and is this user's,
	// denials included. It
	// is the number privilege_exceeded turns on, so comparing it with
	// Privilege shows what the device asked for against what port49 held.
	// Recorded only. A pointer so 0 (a valid level) is present when held and
	// the field is absent where no context was read or the one read is not this
	// user's (context_missing, store_unavailable, username_mismatch).
	HeldPrivilege *uint8 `json:"held_privilege,omitempty"`
}

// PrivilegeClamp is the context's held level before and after a join.
type PrivilegeClamp struct {
	From uint8 `json:"from"`
	To   uint8 `json:"to"`
}

type Request struct {
	// Service is the `service` AV pair lifted out of Raw, on every
	// authorize_session and authorize_command record including the denials.
	// It is recorded so "which service is this fleet's devices asking under"
	// is a field to group by rather than a string to parse out of an array —
	// the question after renaming `tacplus-options service-name` on half an
	// SRX fleet, and the one a service_unsupported denial has to answer. It is
	// checked against the platform's session_services list and consulted for
	// nothing else: the service never selects policy (spec §5.2, §5.7).
	Service string   `json:"service,omitempty"`
	Raw     []string `json:"raw"`
	Vector  []string `json:"vector"`
	// Redacted says words were replaced with «redacted» before the record
	// was written (spec §5.8) — of Raw and Vector, or of a rule the record
	// echoes in its policy block: a secret is never logged, and a replay
	// cannot see what was decided.
	Redacted bool `json:"redacted,omitempty"`
}

// Reply is what a permitted authorization returned to the device, as sent: a
// session's attributes with every placeholder filled. Replay re-derives them
// from the blob and compares (spec §5.7).
type Reply struct {
	Attributes []string `json:"attributes"`
}

type AcctRecord struct {
	Raw    []string `json:"raw"`
	Vector []string `json:"vector"`
	// Redacted is Request.Redacted's twin: words were replaced before the
	// record reached the spool, so no secret is ever on disk (spec §5.8).
	Redacted    bool  `json:"redacted,omitempty"`
	PrivLvl     uint8 `json:"priv_lvl"`
	StartTime   int64 `json:"start_time,omitempty"`
	StopTime    int64 `json:"stop_time,omitempty"`
	ElapsedTime int64 `json:"elapsed_time,omitempty"`
}

// Mint is the audit trail for authority (spec §5.7): which tokens were issued,
// identified by hash only. The token itself never appears in the log.
type Mint struct {
	TokenSHA256 []string `json:"token_sha256"`
	TTLSeconds  int      `json:"ttl_seconds"`
	BlobHash    string   `json:"blob,omitempty"`
}

// Sweep is a mint record's sweep: the scope and the page's cursor.
type Sweep struct {
	Scope string `json:"scope"`
	After string `json:"after,omitempty"`
}

// Policy is the record's policy identity and what it matched (spec §5.7).
// Bundle and Blob are mandatory on every record that consulted policy: they
// are what makes the record replayable, and a replay that disagrees with the
// logged verdict is itself a finding. A mint record adds the subject and the
// grants that selected the device; an authorization record adds the rules
// that matched.
type Policy struct {
	// Bundle names the policy the blob was compiled from. Until plan 6
	// publishes versioned bundles it is the sha256 of the policy file.
	Bundle string `json:"bundle,omitempty"`
	// Blob is the hash of the compiled blob the decision was made against.
	Blob    string `json:"blob,omitempty"`
	Subject string `json:"subject,omitempty"`
	// Subjects is every subject matched, sorted, when the principal matches
	// more than one; Subject is then absent (spec §5.7).
	Subjects []string      `json:"subjects,omitempty"`
	Grants   []PolicyGrant `json:"grants,omitempty"`
	// MatchedDeny is the deny that decided a no_permit_dominates_deny, or the
	// most specific deny a permit overrode.
	MatchedDeny *PolicyRule `json:"matched_deny,omitempty"`
	// MatchedPermits is every permit that matched the command, most specific
	// first; the first is the one that decided a permit.
	MatchedPermits []PolicyRule `json:"matched_permits,omitempty"`
	// Stage is the 1-based pipeline stage a pipe_stage_denied refused. The
	// stage's words are on the record already, in request.raw.
	Stage int `json:"stage,omitempty"`
}

// PolicyGrant is one grant that selected the device.
type PolicyGrant struct {
	Scope string   `json:"scope"`
	Roles []string `json:"roles,omitempty"`
	// Expires is when the grant stops matching, rendered as ts is; empty is
	// never.
	Expires string `json:"expires,omitempty"`
}

// PolicyRule is one rule that matched a command: its terms as written, the
// specificity tuple it scored against this command (spec §5.4), and the role
// that carries it.
type PolicyRule struct {
	Rule        []string `json:"rule"`
	Specificity []int    `json:"specificity"`
	Role        string   `json:"role"`
}

// Blob is the `blob` event's body: the compiled blob whole, emitted once per
// hash, so replay depends on the log alone and the store owes the auditor
// nothing (spec §5.1.1; §13, decision 19). Body is the exact bytes the hash
// names.
type Blob struct {
	Hash string          `json:"hash"`
	Body json.RawMessage `json:"body"`
	// Redacted says rule text in Body was redacted before it was logged
	// (spec §5.8), so Body is not the blob Hash names and replay reports
	// every record naming it unverifiable. The store keeps the blob verbatim.
	Redacted bool `json:"redacted,omitempty"`
}

// Gap is the `account_gap` record's body: how many accounting records port49
// received and did not write to this log, at which stage, since when (spec
// §5.7, §9). offer_refused was answered ERROR, and the device may send the
// record again; drain_unparseable and drain_set_aside were answered SUCCESS
// and are not in the log (a set-aside one is in the spool's .unencodable
// file). Reconciliation reads it: a window with a gap cannot say a device
// did not ask.
type Gap struct {
	Stage   string `json:"stage"`
	Records int    `json:"records"`
	Since   string `json:"since"`
}

// Change is one security-relevant change a bundle swap made (spec §10): an
// address added to a device already in inventory, or a device joining or
// leaving a scope with security_log: true. The record's device block names
// the device.
type Change struct {
	Kind    string `json:"kind"`
	Scope   string `json:"scope,omitempty"`
	Address string `json:"address,omitempty"`
	// From and To are a key_ref change's two key_refs, and an admission
	// change's two states.
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	FromBundle string `json:"from_bundle"`
	ToBundle   string `json:"to_bundle"`
}

// Forget is what a directory_forget record says: the entry the principal
// was pinned to, its last verification or refusal, and who asked. It names
// no group and no mapping value.
type Forget struct {
	EntryID    string `json:"entry_id,omitempty"`
	DN         string `json:"dn,omitempty"`
	VerifiedAt string `json:"verified_at"`
	Refused    bool   `json:"refused,omitempty"`
	Origin     string `json:"origin"`
}

// Revocation is what a revocation reached (spec §5.7): identity, never a
// credential. A count of zero is absent.
type Revocation struct {
	By     string `json:"by"`
	Issuer string `json:"issuer,omitempty"`
	Serial string `json:"serial,omitempty"`
	// OIDCIssuer and Sid or Sub name an OIDC session or subject a
	// back-channel logout or a revocation by sid ended (by "sid" or "sub").
	OIDCIssuer string `json:"oidc_issuer,omitempty"`
	Sid        string `json:"sid,omitempty"`
	Sub        string `json:"sub,omitempty"`
	// Principals is every principal a logout reached when its owner record
	// named more than one (a rename under one sub; Ruling 24); the record's
	// Principal is then the first.
	Principals  []string     `json:"principals,omitempty"`
	Device      string       `json:"device,omitempty"`
	Username    string       `json:"username,omitempty"`
	At          string       `json:"at"`
	Origin      string       `json:"origin,omitempty"`
	Contexts    int          `json:"contexts,omitempty"`
	TokenKeys   int          `json:"token_keys,omitempty"`
	Connections int          `json:"connections,omitempty"`
	Unreached   []ContextRef `json:"unreached,omitempty"`
	// Saved is whether broker.revocations_file was written: a standing
	// mark's alone, absent for a self or key revocation, which writes none.
	Saved *bool  `json:"saved,omitempty"`
	Error string `json:"error,omitempty"`
}

// ContextRef names a live context without its ctx_id, which is sealed.
type ContextRef struct {
	Device   string `json:"device"`
	Username string `json:"username"`
}

// Explain is what an explain record says of the call beside its answer.
// AskedBy and AskedByFingerprint are the caller's principal and
// certificate, kept out of Auth so a record's auth and principal always
// describe one credential (decision 34). MintError is the mint item error
// the broker would answer instead of a token; the record then has no
// verdict.
type Explain struct {
	AskedBy            string `json:"asked_by"`
	AskedByFingerprint string `json:"asked_by_fingerprint,omitempty"`
	Command            bool   `json:"command,omitempty"`
	MintError          string `json:"mint_error,omitempty"`
}

// Unvalidated is what is recorded for a packet no key validated: cleartext header
// fields, the source, and a hash of the body — never the body.
type Unvalidated struct {
	Source     string `json:"source"`
	Diagnosis  string `json:"diagnosis"`
	KeyRef     string `json:"key_ref,omitempty"`
	Version    int    `json:"version,omitempty"`
	Type       uint8  `json:"type"`
	SeqNo      uint8  `json:"seq_no"`
	SessionID  uint32 `json:"session_id"`
	Length     uint32 `json:"length"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	// Transport is "tls" on a record from the RFC 9887 listener. TLSOutcome,
	// Detail and CertSHA256 are a tls_refused record's (spec §10): Detail is
	// bounded and printable, never a body.
	Transport  string `json:"transport,omitempty"`
	TLSOutcome string `json:"tls_outcome,omitempty"`
	Detail     string `json:"detail,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
}

type Emitter interface {
	Emit(Record)
}

// Sink is an Emitter that says whether the record reached its destination.
// Emit is for the decision paths, which answer the device either way and
// count a refusal; Write is for a caller that must not forget a record the
// sink refused — the accounting spool, whose at-least-once contract ends
// here, and the broker's blob emission, which has to emit a refused blob
// again (roadmap, plan 4).
type Sink interface {
	Emitter
	Write(Record) error
}

// ErrUnencodable is a record the log can never write, whatever the retry: it
// does not encode. A caller that keeps records for another attempt (the
// accounting spool) sets such a record aside rather than retry it forever.
var ErrUnencodable = errors.New("decision: record does not encode")

type jsonLines struct {
	mu        sync.Mutex
	w         io.Writer
	onFailure func()
}

func NewJSONLines(w io.Writer) Sink { return &jsonLines{w: w} }

// NewJSONLinesWithFailureHook is NewJSONLines plus a callback run once for
// every refused write. From Emit a refused write is a record that does not
// exist while the device was still answered, so something has to count it;
// from Write it may be a record its caller still holds and writes again (the
// accounting spool), which counts once per attempt, so the count is refused
// writes, not lost records;
// the callback rather than a metric keeps this package's dependencies to the
// standard library, so the record shape and the metric registry stay
// independent of each other.
func NewJSONLinesWithFailureHook(w io.Writer, onFailure func()) Sink {
	return &jsonLines{w: w, onFailure: onFailure}
}

// failed reports one record that did not reach the sink.
func (j *jsonLines) failed() {
	if j.onFailure != nil {
		j.onFailure()
	}
}

func (j *jsonLines) Emit(r Record) { _ = j.Write(r) }

// Write is Emit that returns the refusal. Either way the refused write is
// logged and counted, here, once per call: a caller that retries a record
// counts once per refused write, and should pace its retries.
func (j *jsonLines) Write(r Record) error {
	r.TS = r.TS.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		// Not "dropping": a caller of Write (the accounting spool) keeps the
		// record and offers it again; only an Emit caller loses it.
		log.Printf("decision: refused a record that failed to marshal (lost unless its caller keeps it): %v", err)
		j.failed()
		return fmt.Errorf("%w: %v", ErrUnencodable, err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.w.Write(append(b, '\n'))
	if err != nil {
		log.Printf("decision: write failed: %v", err)
		j.failed()
	}
	return err
}

// CredentialHash identifies a presented credential in the log without revealing it.
func CredentialHash(presented []byte) string {
	sum := sha256.Sum256(presented)
	return hex.EncodeToString(sum[:])
}

// timeLayout is how every time on a record is rendered: millisecond precision,
// matching the spec examples.
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// FormatTime renders a time carried in a record field the way ts is rendered,
// so a reader compares the two as strings.
func FormatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// MarshalJSON renders ts with millisecond precision in UTC, matching the spec examples.
func (r Record) MarshalJSON() ([]byte, error) {
	type alias Record
	return json.Marshal(struct {
		TS string `json:"ts"`
		*alias
	}{TS: r.TS.Format(timeLayout), alias: (*alias)(&r)})
}

// UnmarshalJSON is MarshalJSON's counterpart, parsing ts back into a
// time.Time. It exists so a Record round-trips through the accounting
// spool's on-disk overflow file (package acct).
func (r *Record) UnmarshalJSON(b []byte) error {
	type alias Record
	var a struct {
		TS string `json:"ts"`
		*alias
	}
	a.alias = (*alias)(r)
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	ts, err := time.Parse(timeLayout, a.TS)
	if err != nil {
		return err
	}
	r.TS = ts
	return nil
}
