// Package replay re-evaluates decision records against the blobs they name
// (spec §5.7, "Replay"; §12, `port49 policy replay`). It reads the log alone —
// the blob a record names is in the same stream as a `blob` event (spec
// §13, decision 19) — and runs internal/engine, the evaluator the daemon
// runs, so a divergence is real: an intended fix, a regression, or a log or
// blob store that was altered.
package replay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
)

// Status is what one record's replay found.
type Status string

const (
	// Agree: the blob reproduces the logged verdict, reason and matched rules.
	Agree Status = "agree"
	// Diverge: it does not, or the blob in the log is not the one its hash
	// names.
	Diverge Status = "diverge"
	// Unverifiable: the log does not carry the blob the record names.
	Unverifiable Status = "unverifiable"
)

// Result is one replayed record, by its 1-based line in the log.
type Result struct {
	Line   int
	Event  string
	Status Status
	Detail string
}

// replayable are the reasons a blob decides. A denial for an operational
// reason — the store or the blob was unavailable — was decided before any
// policy ran, and has nothing to reproduce.
var replayable = map[decision.Reason]bool{
	decision.PermitDominates: true, decision.NoRuleMatched: true, decision.NoPermitDominatesDeny: true,
	decision.PipeStageDenied: true, decision.ContextMatched: true, decision.BlobPlatformMismatch: true,
}

// Replay reads a decision log and replays every authorization record that
// consulted a blob. only, when non-zero, restricts it to the record on that
// line. A line that is not a record is an error: a decision log is JSON lines
// and nothing else.
func Replay(r io.Reader, only int) ([]Result, error) {
	var records []numbered
	blobs := map[string][]byte{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec decision.Record
		if err := rec.UnmarshalJSON(sc.Bytes()); err != nil {
			return nil, fmt.Errorf("line %d is not a decision record: %w", n, err)
		}
		switch {
		case rec.Event == decision.EventBlob && rec.Blob != nil:
			blobs[rec.Blob.Hash] = append([]byte(nil), rec.Blob.Body...)
		case rec.Event == decision.EventAuthorizeCommand || rec.Event == decision.EventAuthorizeSession:
			if rec.Policy != nil && rec.Policy.Blob != "" && replayable[rec.Reason] && (only == 0 || only == n) {
				records = append(records, numbered{n, rec})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(records))
	for _, nr := range records {
		status, detail := one(nr.rec, blobs)
		out = append(out, Result{Line: nr.line, Event: nr.rec.Event, Status: status, Detail: detail})
	}
	return out, nil
}

type numbered struct {
	line int
	rec  decision.Record
}

// one replays a single record.
func one(rec decision.Record, blobs map[string][]byte) (Status, string) {
	hash := rec.Policy.Blob
	body, ok := blobs[hash]
	if !ok {
		return Unverifiable, "the log carries no blob event for " + hash
	}
	b, err := engine.Decode(hash, body)
	if errors.Is(err, engine.ErrHashMismatch) {
		return Diverge, "the blob event for " + hash + " does not hash to its name: the log was altered"
	}
	if err != nil {
		return Diverge, "the blob event for " + hash + " does not decode: " + err.Error()
	}
	if rec.Policy.Bundle != b.Bundle {
		return Diverge, fmt.Sprintf("the record names bundle %s; its blob was compiled from %s", rec.Policy.Bundle, b.Bundle)
	}
	prog, err := engine.Compile(b)
	if err != nil {
		return Diverge, "the blob does not compile: " + err.Error()
	}
	verdict, reason := decision.VerdictPermit, decision.ContextMatched
	var pol *decision.Policy
	var attrs []string
	session := false
	switch {
	case rec.Device != nil && rec.Device.Platform != b.Platform:
		verdict, reason = decision.VerdictDeny, decision.BlobPlatformMismatch
	case rec.Event == decision.EventAuthorizeSession:
		// A session is decided by its attributes as much as by its verdict
		// (spec §5.7): re-derive them from the blob and the record's own
		// values, as the daemon filled them.
		v := engine.Values{Principal: rec.Principal}
		if rec.Session != nil {
			v.Username = rec.Session.Username
		}
		if rec.Device != nil {
			v.Device = rec.Device.Name
		}
		if attrs, err = b.SessionAttributes(v); err != nil {
			return Diverge, "the blob's session attributes do not fit this record's values: " + err.Error()
		}
		session = true
	case rec.Event == decision.EventAuthorizeCommand:
		if rec.Request == nil {
			return Diverge, "the record has no request to replay"
		}
		o := prog.Command(rec.Request.Raw)
		reason = o.Reason
		if !o.Permit {
			verdict = decision.VerdictDeny
		}
		pol = o.Policy(b.Bundle, hash)
	}
	if verdict != rec.Verdict || reason != rec.Reason {
		return Diverge, fmt.Sprintf("logged %s %s, replayed %s %s", rec.Verdict, rec.Reason, verdict, reason)
	}
	if session {
		var logged []string
		if rec.Reply != nil {
			logged = rec.Reply.Attributes
		}
		if !slices.Equal(logged, attrs) {
			return Diverge, fmt.Sprintf("the verdict agrees but the session attributes do not: logged %q, replayed %q",
				logged, attrs)
		}
	}
	if pol != nil {
		logged, _ := json.Marshal(rec.Policy)
		replayed, _ := json.Marshal(pol)
		if string(logged) != string(replayed) {
			return Diverge, fmt.Sprintf("the verdict agrees but the matched rules do not: logged %s, replayed %s",
				logged, replayed)
		}
	}
	return Agree, ""
}
