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
	CtxID     string `json:"ctx_id"`
	Username  string `json:"username,omitempty"`
	Port      string `json:"port"`
	RemAddr   string `json:"rem_addr"`
	Privilege uint8  `json:"privilege"`
}

type Request struct {
	Raw    []string `json:"raw"`
	Vector []string `json:"vector"`
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
	BodySHA256 string `json:"body_sha256"`
}

type Emitter interface {
	Emit(Record)
}

type jsonLines struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONLines(w io.Writer) Emitter { return &jsonLines{w: w} }

func (j *jsonLines) Emit(r Record) {
	r.TS = r.TS.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		log.Printf("decision: dropping record that failed to marshal: %v", err)
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.w.Write(append(b, '\n'))
	if err != nil {
		log.Printf("decision: write failed: %v", err)
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
