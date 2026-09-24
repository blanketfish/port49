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
	// IndexError names what a failed index write cost, on the record for the
	// session that lost it. Revocation must report the contexts it could not
	// reach (spec §5.6), and this is the only place that says which they are.
	IndexError string `json:"index_error,omitempty"`
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
}

type Device struct {
	NAS      string `json:"nas"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
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
	// Port and RemAddr are as seen on this exchange, which is not necessarily
	// what the context recorded: they are part of no key (spec §13,
	// decision 15).
	Port      string `json:"port"`
	RemAddr   string `json:"rem_addr"`
	Privilege uint8  `json:"privilege"`
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
	Blob    string        `json:"blob,omitempty"`
	Subject string        `json:"subject,omitempty"`
	Grants  []PolicyGrant `json:"grants,omitempty"`
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
