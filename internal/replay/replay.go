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
	"strings"
	"time"
	"unicode"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/engine"
)

// Status is what one record's replay found.
type Status string

const (
	// Agree: the blob reproduces the logged verdict, reason and matched rules.
	Agree Status = "agree"
	// Diverge: it does not, or the blob in the log is not the one its hash
	// names.
	Diverge Status = "diverge"
	// Unverifiable: the log does not carry the blob the record names, or the
	// record was redacted before it was written (spec §5.8).
	Unverifiable Status = "unverifiable"
	// Skipped: an authorization denied for a reason decided before any policy
	// ran. It is counted, so a record cannot leave the replay unseen.
	Skipped Status = "not_replayed"
)

// Result is one record, by its 1-based line in the log. Reason is the
// reason the record logged; a blob event's own result has none.
type Result struct {
	Line   int
	Event  string
	Status Status
	Reason decision.Reason
	Detail string
}

// replayable are the reasons a blob decides. A denial for an operational
// reason — the store or the blob was unavailable — was decided before any
// policy ran, and has nothing to reproduce.
var replayable = map[decision.Reason]bool{
	decision.PermitDominates: true, decision.NoRuleMatched: true, decision.NoPermitDominatesDeny: true,
	decision.PipeStageDenied: true, decision.ContextMatched: true, decision.BlobPlatformMismatch: true,
	decision.ProjectionFailClosed: true,
}

// Source supplies a blob verbatim from outside the log (spec §5.7, §5.8):
// for a record naming a blob whose event was redacted, and the time that
// blob was compiled (its event's ts), the exact bytes, or false. Replay uses
// them only when they hash to the name the record carries.
type Source func(rec decision.Record, compiledAt time.Time) ([]byte, bool)

// Replay reads a decision log and replays every authorization record that
// consulted a blob, and reports every other authorization record as Skipped.
// only, when non-zero, restricts it to the record on that line. A line that
// is not a record diverges, and the replay goes on past it.
//
// It streams: a record is replayed as it is read, against a program compiled
// once per blob, and only a record read before its blob event is held back —
// decision 19 writes the blob first, so those are rare. Results come back in
// line order.
func Replay(r io.Reader, only int) ([]Result, error) {
	return ReplayWith(r, only, nil)
}

// ReplayWith is Replay, and a record naming a blob whose event was redacted
// is replayed against the blob src gives for it, where src is set and that
// blob hashes to the name the record carries.
func ReplayWith(r io.Reader, only int, src Source) ([]Result, error) {
	rp := replayer{only: only, programs: map[string]*program{}, pending: map[string][]numbered{},
		source: src, verbatim: map[string]*program{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	n := 1
	for ; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec decision.Record
		if err := rec.UnmarshalJSON(sc.Bytes()); err != nil {
			// A write torn by a full disk leaves such a line, and the log
			// writes the record again whole after it; an edit may too.
			// Either way it is this line's divergence, not the log's end.
			if only == 0 || only == n {
				rp.emit(numbered{line: n, rec: decision.Record{Event: "unreadable"}}, Diverge, "not a decision record: truncated or altered ("+err.Error()+")")
			}
			if only != 0 && n >= only && len(rp.pending) == 0 {
				break
			}
			continue
		}
		rp.read(n, rec)
		if only != 0 && n >= only && len(rp.pending) == 0 {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", n, err)
	}
	for hash, recs := range rp.pending {
		for _, nr := range recs {
			rp.emit(nr, Unverifiable, "the log carries no blob event for "+hash)
		}
	}
	slices.SortStableFunc(rp.out, func(a, b Result) int { return a.Line - b.Line })
	return rp.out, nil
}

type replayer struct {
	only int
	// programs caches every blob event by hash, a bad one as its failure, so
	// each blob is decoded and compiled once however many records name it.
	programs map[string]*program
	// pending holds the records read before their blob event, by hash.
	pending map[string][]numbered
	out     []Result
	// source gives a redacted blob verbatim; verbatim caches each one it
	// gave that hashed to its name, by that hash.
	source   Source
	verbatim map[string]*program
}

type numbered struct {
	line int
	rec  decision.Record
}

// program is one blob event, compiled; or, when failure is set, why it could
// not be.
type program struct {
	blob    engine.Blob
	prog    *engine.Program
	failure string
	// redacted is set for a blob event logged with its rule text redacted
	// (spec §5.8): not the blob its hash names, and no divergence either.
	redacted bool
	// at is when the blob was compiled: its event's ts.
	at time.Time
	// verbatim is set for a program a Source gave for a redacted event. Its
	// rules carry what the log redacted, so a divergence prints the log's
	// side of the difference and never the program's.
	verbatim bool
}

// rank orders two copies of one blob event: a verbatim one that compiles,
// then a redacted one, then one that failed.
func (p *program) rank() int {
	switch {
	case p.failure != "":
		return 2
	case p.redacted:
		return 1
	}
	return 0
}

func (rp *replayer) read(n int, rec decision.Record) {
	switch {
	case rec.Event == decision.EventBlob && rec.Blob != nil:
		rp.blob(n, rec.Blob.Hash, rec.Blob.Body, rec.Blob.Redacted, rec.TS)
	case rec.Event == decision.EventAuthorizeCommand || rec.Event == decision.EventAuthorizeSession:
		if rp.only != 0 && rp.only != n {
			return
		}
		nr := numbered{n, rec}
		switch {
		case !replayable[rec.Reason] && rec.Verdict != decision.VerdictDeny:
			// Every reason replay skips is a denial. A permit carrying one is
			// a record edited so that replay would pass over it.
			rp.emit(nr, Diverge, fmt.Sprintf("logged %s %s, and %s is only ever a denial decided before policy ran",
				rec.Verdict, rec.Reason, rec.Reason))
		case !replayable[rec.Reason]:
			rp.emit(nr, Skipped, fmt.Sprintf("%s is decided before policy runs", rec.Reason))
		case rec.Policy == nil || rec.Policy.Blob == "":
			// Bundle and Blob are mandatory on every record that consulted
			// policy (decision.Policy).
			rp.emit(nr, Diverge, fmt.Sprintf("logged %s %s, a decision a blob makes, and the record names no blob",
				rec.Verdict, rec.Reason))
		default:
			p, ok := rp.programs[rec.Policy.Blob]
			if !ok {
				rp.pending[rec.Policy.Blob] = append(rp.pending[rec.Policy.Blob], nr)
				return
			}
			rp.judge(nr, p)
		}
	}
}

// blob compiles a blob event and replays the records that were waiting for
// it. Every blob event is checked against its name whether or not a record
// names it: a bad one is a divergence on its own line, and does not displace
// a good copy read earlier.
func (rp *replayer) blob(n int, hash string, body []byte, redacted bool, at time.Time) {
	p := &program{redacted: redacted, at: at}
	b, err := engine.Decode(hash, body)
	switch {
	case redacted:
		// Its body does not hash to its name, by design: the rules it
		// carries are not the ones that decided, so nothing is compiled from
		// them. Flipping the flag on a verbatim event only makes its
		// records unverifiable, never agree.
	case errors.Is(err, engine.ErrHashMismatch):
		p.failure = "the blob event for " + hash + " does not hash to its name: the log was altered"
	case err != nil:
		p.failure = "the blob event for " + hash + " does not decode: " + err.Error()
	default:
		p.blob = b
		if p.prog, err = engine.Compile(b); err != nil {
			p.failure = "the blob " + hash + " does not compile: " + err.Error()
		}
	}
	if p.failure != "" && (rp.only == 0 || rp.only == n) {
		rp.emit(numbered{n, decision.Record{Event: decision.EventBlob}}, Diverge, p.failure)
	}
	if prev, ok := rp.programs[hash]; ok && prev.rank() <= p.rank() {
		return
	}
	rp.programs[hash] = p
	for _, nr := range rp.pending[hash] {
		rp.judge(nr, p)
	}
	delete(rp.pending, hash)
}

func (rp *replayer) emit(nr numbered, status Status, detail string) {
	rp.out = append(rp.out, Result{Line: nr.line, Event: nr.rec.Event, Status: status,
		Reason: decision.Reason(printable(string(nr.rec.Reason))), Detail: printable(detail)})
}

// printable replaces every rune a terminal could act on. A detail carries
// strings from the log, and an edited log must not write control sequences
// on the auditor's console.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}

// judge replays one record against its blob's program.
func (rp *replayer) judge(nr numbered, p *program) {
	v := rp.withVerbatim(nr.rec, p)
	status, detail := one(nr.rec, v)
	if v.redacted && rp.source != nil {
		detail += "; the policy and inventory files give no blob that hashes to it"
	}
	rp.emit(nr, status, detail)
}

// withVerbatim is p, or, where p's blob event was redacted and a Source is
// set, the program compiled from the verbatim blob the Source gives for this
// record, checked against the hash the record names. A Source that cannot
// give it, or gives other bytes, leaves p, and the record stays unverifiable.
func (rp *replayer) withVerbatim(rec decision.Record, p *program) *program {
	if !p.redacted || rp.source == nil || rec.Policy == nil {
		return p
	}
	hash := rec.Policy.Blob
	if v, ok := rp.verbatim[hash]; ok {
		return v
	}
	body, ok := rp.source(rec, p.at)
	if !ok {
		return p
	}
	b, err := engine.Decode(hash, body)
	if err != nil {
		return p
	}
	prog, err := engine.Compile(b)
	if err != nil {
		return p
	}
	v := &program{blob: b, prog: prog, at: p.at, verbatim: true}
	rp.verbatim[hash] = v
	return v
}

// unshown ends a divergence against a verbatim program: what it replayed is
// rule text the log redacted, and is not printed (spec §5.8).
const unshown = "; the replayed side is from the blob the policy and inventory files give, whose rule text the " +
	"log redacts, and is not shown (spec §5.8)"

// one replays a single record.
func one(rec decision.Record, p *program) (Status, string) {
	if p.failure != "" {
		return Diverge, p.failure
	}
	if p.redacted {
		return Unverifiable, "the blob event for " + rec.Policy.Blob + " was redacted before it was written (spec " +
			"§5.8): the log does not carry the blob the hash names"
	}
	hash, b, prog := rec.Policy.Blob, p.blob, p.prog
	if rec.Policy.Bundle != b.Bundle {
		return Diverge, fmt.Sprintf("the record names bundle %s; its blob was compiled from %s", rec.Policy.Bundle, b.Bundle)
	}
	verdict, reason := decision.VerdictPermit, decision.ContextMatched
	var pol *decision.Policy
	var attrs []string
	var err error
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
			if p.verbatim {
				return Diverge, "the blob's session attributes do not fit this record's values" + unshown
			}
			return Diverge, "the blob's session attributes do not fit this record's values: " + err.Error()
		}
		reason = b.SessionReason()
		session = true
	case rec.Event == decision.EventAuthorizeCommand:
		if rec.Request == nil {
			return Diverge, "the record has no request to replay"
		}
		if rec.Request.Redacted {
			// The command it decided is not in the log, by design: replaying
			// the redacted words would claim an agreement nobody can check.
			return Unverifiable, "the record was redacted before it was written (spec §5.8), so the command it " +
				"decided is not in the log"
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
		if !slices.Equal(logged, attrs) && p.verbatim {
			return Diverge, fmt.Sprintf("the verdict agrees but the session attributes do not: logged %q", logged) +
				unshown
		}
		if !slices.Equal(logged, attrs) {
			return Diverge, fmt.Sprintf("the verdict agrees but the session attributes do not: logged %q, replayed %q",
				logged, attrs)
		}
	}
	if pol != nil {
		logged, _ := json.Marshal(rec.Policy)
		replayed, _ := json.Marshal(pol)
		if string(logged) != string(replayed) && p.verbatim {
			return Diverge, fmt.Sprintf("the verdict agrees but the matched rules do not: logged %s", logged) + unshown
		}
		if string(logged) != string(replayed) {
			return Diverge, fmt.Sprintf("the verdict agrees but the matched rules do not: logged %s, replayed %s",
				logged, replayed)
		}
	}
	return Agree, ""
}
