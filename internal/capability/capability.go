// Package capability infers what each device is configured to authorize from
// the decision log it already writes (spec §9): a device capable of command
// authorization and not configured for it looks healthy while its commands
// go unauthorized, and port49 must say so without asking an operator to
// assert anything. It reads records only; it never contacts a device.
package capability

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
)

// The capabilities of spec §9's vocabulary, as `supports` names them.
const (
	Session        = "session"
	Commands       = "commands"
	ConfigCommands = "config_commands"
)

// Device is one inventory device as the report reads it: what its adapter
// declares, and whether policy admits it now.
type Device struct {
	Name, Platform string
	Supports       []string
	// Quarantine is the first cause the device is quarantined for at the
	// report's end, empty where it is admitted (spec §10).
	Quarantine string
}

// Options bound the inference. The zero value takes every record and the
// defaults below.
type Options struct {
	// From and To bound the window by record time; zero is unbounded.
	From, To time.Time
	// ConfigEntries is how many permitted configuration entries a device
	// needs in the window before the config-commands inference speaks, and
	// ConfigSilent the share of them that must see no authorization after
	// them: spec §9's observation is evidence, not proof, and is read over a
	// window, never per session. Defaults 5 and 0.8.
	ConfigEntries int
	ConfigSilent  float64
	// Redactor gives each platform's redaction patterns, which every example
	// echoed from the log goes through (spec §5.8); nil is the built-in ones.
	Redactor platform.Redactor
}

// Row is one device's line of the matrix, and its reconciliation.
type Row struct {
	Device   Device
	Observed []string
	Warnings []string
	// Notes are what the matrix says that is no fault: a capability observed
	// that the adapter does not declare is a lab measurement waiting to be
	// made, never one to assert by hand (spec §9, "Principle"); a device never
	// seen in the window is one nobody logged into, which pages nobody (plan
	// 5b pre-flight I13: "once that happens nobody reads the report again").
	Notes []string
	// Unauthorized counts command accounting records, in contexts port49
	// authenticated, that no authorization request of the same context
	// accounts for; Examples are up to three of their commands.
	Unauthorized int
	Examples     []string
	// ConfigEntered and ConfigSilent are the permitted configuration entries
	// and those no authorization request followed in their context.
	ConfigEntered, ConfigSilent int
	// Unattributed, Foreign and System count the device's accounting records
	// by attribution (spec §5.8): the stream's health for this device.
	Unattributed, Foreign, System int
}

// Report is the inference over one window.
type Report struct {
	From, To time.Time
	Rows     []Row
	// Gaps are the account_gap records whose drops can fall in the window,
	// from their since to when they were written: records port49 received
	// and did not write. Where there are any, a reconciliation
	// finding says "possibly": the gap may be the authorization it did not
	// find (spec §9, "What silence can and cannot mean").
	Gaps []decision.Gap
}

// Qualified reports whether the window's accounting stream is whole, so a
// reconciliation finding stands as a finding.
func (r Report) Qualified() bool { return len(r.Gaps) == 0 }

// Infer reads records, in log order, against devices (spec §9).
func Infer(records []decision.Record, devices []Device, opt Options) Report {
	if opt.ConfigEntries == 0 {
		opt.ConfigEntries = 5
	}
	if opt.ConfigSilent == 0 {
		opt.ConfigSilent = 0.8
	}
	if opt.Redactor == nil {
		opt.Redactor = platform.BuiltInRedactor
	}
	var rep Report
	type ctxKey struct{ device, ctx string }
	byDevice := map[string][]decision.Record{}
	authorized := map[ctxKey][]string{} // context → each authorized command, as text
	for _, r := range records {
		if r.Event == decision.EventAccountGap && r.Gap != nil {
			if gapOverlaps(r, opt) {
				rep.Gaps = append(rep.Gaps, *r.Gap)
			}
			continue
		}
		if (!opt.From.IsZero() && r.TS.Before(opt.From)) || (!opt.To.IsZero() && r.TS.After(opt.To)) {
			continue
		}
		if rep.From.IsZero() || r.TS.Before(rep.From) {
			rep.From = r.TS
		}
		if r.TS.After(rep.To) {
			rep.To = r.TS
		}
		if r.Device == nil {
			continue
		}
		byDevice[r.Device.Name] = append(byDevice[r.Device.Name], r)
		if r.Event == decision.EventAuthorizeCommand && r.Session != nil && r.Request != nil {
			k := ctxKey{r.Device.Name, r.Session.CtxID}
			authorized[k] = append(authorized[k], text(r.Request.Vector))
		}
	}
	for _, d := range devices {
		row := Row{Device: d}
		recs := byDevice[d.Name]
		observed := map[string]bool{}
		var entries []decision.Record    // permitted configuration entries
		unmatched := map[string]string{} // context and command → the command, redacted
		for i, r := range recs {
			switch r.Event {
			case decision.EventAuthorizeSession:
				observed[Session] = true
			case decision.EventAuthorizeCommand:
				observed[Commands] = true
				if r.Verdict == decision.VerdictPermit && r.Request != nil && configEntry(r.Request.Vector) {
					entries = append(entries, r)
					if followed(recs[i+1:], r.Session) {
						observed[ConfigCommands] = true
					} else {
						row.ConfigSilent++
					}
				}
			case decision.EventAccount:
				switch r.Attribution {
				case "unattributed":
					row.Unattributed++
				case "foreign":
					row.Foreign++
				case "system":
					row.System++
				}
				if !slices.Contains(d.Supports, Commands) || r.Attribution != "resolved" || r.Session == nil ||
					r.AcctRecord == nil || isExec(d.Platform, r.AcctRecord.Raw) {
					continue
				}
				cmd := text(r.AcctRecord.Vector)
				if cmd == "" {
					continue
				}
				if !slices.ContainsFunc(authorized[ctxKey{d.Name, r.Session.CtxID}], func(a string) bool {
					return a != "" && strings.Contains(cmd, a)
				}) {
					_, vector, _ := platform.RedactRecord(opt.Redactor(d.Platform), r.AcctRecord.Raw, r.AcctRecord.Vector)
					unmatched[r.Session.CtxID+"\x00"+cmd] = text(vector)
				}
			}
		}
		row.ConfigEntered = len(entries)
		for _, c := range []string{Session, Commands, ConfigCommands} {
			if observed[c] {
				row.Observed = append(row.Observed, c)
			}
		}
		keys := make([]string, 0, len(unmatched))
		for k := range unmatched {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		row.Unauthorized = len(keys)
		for _, k := range keys {
			cmd := unmatched[k]
			if len(row.Examples) < 3 && !slices.Contains(row.Examples, cmd) {
				row.Examples = append(row.Examples, cmd)
			}
		}
		row.Warnings = warnings(row, opt, rep.Qualified())
		if !rep.Qualified() {
			n := 0
			for _, g := range rep.Gaps {
				n += g.Records
			}
			row.Notes = append(row.Notes, fmt.Sprintf("qualified: account_gap records overlapping this window say %d "+
				"accounting records port49 received are not in the log, so a reconciliation finding is possible, not certain", n))
		}
		if row.Device.Quarantine == "" && len(row.Observed) == 0 {
			row.Notes = append(row.Notes, "never seen: no record in the window, so nothing is inferred")
		}
		for _, c := range row.Observed {
			if !slices.Contains(d.Supports, c) {
				row.Notes = append(row.Notes, c+" observed, and the adapter does not declare it")
			}
		}
		rep.Rows = append(rep.Rows, row)
	}
	return rep
}

func warnings(row Row, opt Options, qualified bool) []string {
	var out []string
	d := row.Device
	if slices.Contains(d.Supports, Commands) && row.ConfigEntered >= opt.ConfigEntries &&
		float64(row.ConfigSilent) >= opt.ConfigSilent*float64(row.ConfigEntered) {
		out = append(out, fmt.Sprintf("config-commands probably off: %d of %d configuration entries saw no "+
			"authorization request after them in their session", row.ConfigSilent, row.ConfigEntered))
	}
	if row.Unauthorized > 0 {
		possibly := ""
		if !qualified {
			possibly = "possibly "
		}
		out = append(out, fmt.Sprintf("%d commands in accounting %shad no corresponding authorization request",
			row.Unauthorized, possibly))
	}
	return out
}

// gapOverlaps reports whether an account_gap record's drops can fall in the
// window: they arrived from its since through its ts, when it was written, so
// a backlog drained after the window still qualifies it (spec §5.7). A since
// that does not read is taken as unbounded before, which qualifies more
// windows rather than fewer.
func gapOverlaps(r decision.Record, opt Options) bool {
	if !opt.From.IsZero() && r.TS.Before(opt.From) {
		return false
	}
	since, err := time.Parse(time.RFC3339Nano, r.Gap.Since)
	if err != nil {
		return true
	}
	return opt.To.IsZero() || !since.After(opt.To)
}

// text is a command vector as one lower-case line with no trailing `<cr>`:
// the form the join compares, where an accounting record's text holds the
// authorization's (NX-OS's accounting `cmd` is the configuration path joined
// with ` ; ` and a result, tests/lab/results/L21-cisco_nxos.md). Holding it
// is the test, so an unexpected accounting shape reads as authorized, which
// under-reports rather than accuses (spec §9).
func text(vector []string) string {
	for len(vector) > 0 && vector[len(vector)-1] == "<cr>" {
		vector = vector[:len(vector)-1]
	}
	return strings.ToLower(strings.Join(vector, " "))
}

// configEntry is a command that enters configuration mode on the platforms
// that authorize commands: `configure`, and what follows it.
func configEntry(vector []string) bool {
	return len(vector) > 0 && strings.EqualFold(vector[0], "configure")
}

// followed reports whether an authorization request of the same context
// comes after a configuration entry, before the context's session ends:
// spec §9's third observation reads silence up to the session's end.
func followed(after []decision.Record, s *decision.Session) bool {
	if s == nil {
		return false
	}
	for _, r := range after {
		if r.Session == nil || r.Session.CtxID != s.CtxID {
			continue
		}
		switch {
		case r.Event == decision.EventAuthorizeCommand:
			return true
		case r.Event == decision.EventAccount && r.Flags == "stop" && r.AcctRecord != nil &&
			len(r.AcctRecord.Vector) == 0:
			return false // the exec STOP: the session ended
		}
	}
	return false
}

// isExec reports whether an accounting record is the session's own exec
// record rather than a command's (spec §5.8).
func isExec(platformName string, raw []string) bool {
	cmd := ""
	for _, a := range raw {
		if strings.HasPrefix(a, "cmd=") || strings.HasPrefix(a, "cmd*") {
			cmd = a[4:]
		}
	}
	return platform.IsExecRecord(platformName, cmd)
}
