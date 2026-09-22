// Package decision is the single emitter for port49's own record stream:
// decisions, accounting, blobs, and header-only diagnosis records (spec §5.7).
package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	Flags       string       `json:"flags,omitempty"`
	Attribution string       `json:"attribution,omitempty"`
	TaskID      string       `json:"task_id,omitempty"`
	AcctRecord  *AcctRecord  `json:"record,omitempty"`
	Unvalidated *Unvalidated `json:"unvalidated,omitempty"`
	ServerMsg   string       `json:"server_msg,omitempty"`
}

type Auth struct {
	Method           string `json:"method"`
	CredentialSHA256 string `json:"credential_sha256"`
}

type Device struct {
	NAS      string `json:"nas"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

type Session struct {
	CtxID    string `json:"ctx_id"`
	Username string `json:"username,omitempty"`
	// ReplacedCtxID is set on a redeem that overwrote an existing context for
	// the same (nas, username) — the same operator logging into the same
	// device twice. It names the displaced ctx_id so the two shells' records
	// can still be joined (spec §5.6).
	ReplacedCtxID string `json:"replaced_ctx_id,omitempty"`
	// Port and RemAddr are as seen on this exchange, which is not necessarily
	// what the context recorded: they are part of no key (spec §13,
	// decision 15).
	Port      string `json:"port"`
	RemAddr   string `json:"rem_addr"`
	Privilege uint8  `json:"privilege"`
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
}

type AcctRecord struct {
	Raw         []string `json:"raw"`
	Vector      []string `json:"vector"`
	PrivLvl     uint8    `json:"priv_lvl"`
	StartTime   int64    `json:"start_time,omitempty"`
	StopTime    int64    `json:"stop_time,omitempty"`
	ElapsedTime int64    `json:"elapsed_time,omitempty"`
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

type jsonLines struct {
	mu        sync.Mutex
	w         io.Writer
	onFailure func()
}

func NewJSONLines(w io.Writer) Emitter { return &jsonLines{w: w} }

// NewJSONLinesWithFailureHook is NewJSONLines plus a callback run once for
// every record the sink refuses. A refused record is a record that does not
// exist while the device was still answered, so something has to count it;
// the callback rather than a metric keeps this package's dependencies to the
// standard library, so the record shape and the metric registry stay
// independent of each other.
func NewJSONLinesWithFailureHook(w io.Writer, onFailure func()) Emitter {
	return &jsonLines{w: w, onFailure: onFailure}
}

// failed reports one record that did not reach the sink.
func (j *jsonLines) failed() {
	if j.onFailure != nil {
		j.onFailure()
	}
}

func (j *jsonLines) Emit(r Record) {
	r.TS = r.TS.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		log.Printf("decision: dropping record that failed to marshal: %v", err)
		j.failed()
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.w.Write(append(b, '\n'))
	if err != nil {
		log.Printf("decision: write failed: %v", err)
		j.failed()
	}
}

// CredentialHash identifies a presented credential in the log without revealing it.
func CredentialHash(presented []byte) string {
	sum := sha256.Sum256(presented)
	return hex.EncodeToString(sum[:])
}

// MarshalJSON renders ts with millisecond precision in UTC, matching the spec examples.
func (r Record) MarshalJSON() ([]byte, error) {
	type alias Record
	return json.Marshal(struct {
		TS string `json:"ts"`
		*alias
	}{TS: r.TS.Format("2006-01-02T15:04:05.000Z07:00"), alias: (*alias)(&r)})
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
	ts, err := time.Parse("2006-01-02T15:04:05.000Z07:00", a.TS)
	if err != nil {
		return err
	}
	r.TS = ts
	return nil
}
