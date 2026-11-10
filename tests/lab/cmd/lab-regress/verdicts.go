package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	"github.com/blanketfish/port49/internal/decision"
)

// A results note states what a claim measured in a few shapes, and lab-regress compares each with HEAD's:
//
//   - a markdown table: every column after the first (the row key) is compared, except a free-text transcript
//     or rationale column (a header containing "transcript" or "what the device said", or exactly "why"). A
//     verdict column (outcome, verdict, result, held, reply, ...; every column of a yes/no matrix row) is
//     compared on its full normalised text, its parentheticals on their verdict words; a narrative column
//     (observed, the device, any other) on its verdict words only (verdictTokens). A narrative change whose
//     verdict words held is printed for a person and does not fail the entry. A row is keyed by the nearest
//     heading, the header row and its first cell.
//   - a bold verdict in prose ("- **(d) FAIL**: ...", "**PASS.** ..."), a qualification bullet
//     ("- `cell` (...): **pass**."), and a ruling bullet ("- **Ruling 15 may close on this run:** true (...)"),
//     keyed by their subject.
//   - a bullet under a "Read off" heading: keyed by its subject (the text before the first ": " or " = "),
//     compared on its full normalised remainder.
//   - a "<claim>: yes|no|true|false" inside a sentence ("Same URI SAN: yes (...); same public key: yes").
//
// A note that parses no row is refused unless its manifest entry says `verdicts: none` (checkVerdicts), so a
// shape this parser misses fails loudly. Comparing full text costs a person a look when a harness reworded a
// cell; a cut that hid a real change would let a wrong claim stand.

// A row's verdict is what decides a flag; shown is its compared columns' normalised text, which a report prints
// and which, when it changes while verdict does not, is a narrative change: printed, never failed.
type verdictRow struct{ key, label, verdict, shown string }

// narrativeOut is where checkVerdicts prints a narrative change for a person to read.
var narrativeOut io.Writer = os.Stdout

var (
	// A bold verdict opening a line, bulleted or not: "**(d) FAIL**" or "**PASS.**".
	proseVerdict = regexp.MustCompile(`^(?:[-*]\s+)?\*\*(?:(\([^)]*\))\s+)?(PASS|FAIL|INVALID|OBSERVED|TIMEOUT|SKIPPED)\b[^*]*\*\*`)
	// A qualification note's bullet: "- `token_login` (re-measures L1): **pass**. ..." or "**not_run**".
	cellVerdict = regexp.MustCompile("^- `([^`]+)`[^*]*?: \\*\\*([a-z_]+)\\*\\*")
	// A ruling bullet: "- **Ruling 15 may close on this run:** true (...)".
	boldClaim = regexp.MustCompile(`^- \*\*([^*]+?):\*\*\s+((?:true|false)\b.*)$`)
	// A bullet that states a value in bold after a colon: "- class_level_apply_groups: `show ...`: **stripped**; ...".
	boldValue = regexp.MustCompile(`^- [^*]+?: \*\*[A-Za-z_]+\*\*`)
	// A yes/no claim inside a sentence: ": yes", ": no", ": true", ": false" closing a clause.
	claimYN = regexp.MustCompile(`: (yes|no|true|false)\b`)
	// A header that makes a table a table of results: a verdict word, or a column the device's answer sits in.
	// Only such a table is read (timing, wire-capture and setup tables hold values no claim rests on, and
	// their rows are keyed by a port or a packet id that moves every run).
	resultColumn = regexp.MustCompile(`^(outcome|verdict|result|ssh result|held|against the docs|agrees with decision \d+|observed|reply|inert|device answered|the device|what the device saw|typed (first|second) .*|(sid|sub) = .*)$`)
	// A verdict column: its cell states the verdict itself, so its full normalised text is compared. Every other
	// compared column is narrative (observed, the device, what the device saw, a command's column, a count...).
	// `reply` is port49's reply in an observation table: its role strings are what the claim rests on (L22).
	verdictColumn = regexp.MustCompile(`^(outcome|verdict|result|ssh result|held|against the docs|agrees with decision \d+|reply|inert|device answered|typed (first|second) .*|(sid|sub) = .*)$`)
	// A free-text column header the comparison leaves out.
	excludedColumn = regexp.MustCompile(`transcript|what the device said`)

	// What a rerun moves, normalised before comparing: an RFC 3339 timestamp, a Go duration ("1m12.9s"), a run
	// of 12 or more hex characters (a container id, a digest), a 16-character upper-case id (a ctx_id), an
	// address with a port, "port 41234", a temp path, an etcd revision ("at 320"), a tty ("port=vty6").
	timeRe     = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
	durationRe = regexp.MustCompile(`\b\d+(?:\.\d+)?(?:h|ms|µs|us|ns|m|s)(?:\d+(?:\.\d+)?(?:h|ms|µs|us|ns|m|s))*\b`)
	hexRe      = regexp.MustCompile(`\b[0-9a-f]{12,}\b`)
	ctxRe      = regexp.MustCompile(`\b[A-Z0-9]{16}\b`)
	addrRe     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b|\[[0-9a-fA-F:]+\]:\d+`)
	portRe     = regexp.MustCompile(`\bport \d{4,5}\b`)
	tmpRe      = regexp.MustCompile(`/tmp/\S+`)
	revRe      = regexp.MustCompile(`\bat \d+\b(?:\.\d+)?`)
	ttyRe      = regexp.MustCompile(`\bport=[^\s;,)]*`)
	lineRe     = regexp.MustCompile(`\b(?:vty|tty|con|pts/)\d+\b`)
	rttRe      = regexp.MustCompile(`\d+\.\d+(?:/\d+\.\d+)+ ms`)
)

func splitRow(ln string) []string {
	ln = strings.TrimSpace(ln)
	if !strings.HasPrefix(ln, "|") {
		return nil
	}
	ln = strings.TrimSuffix(strings.TrimPrefix(ln, "|"), "|")
	// An escaped pipe, \|, belongs to its cell (a regexp in a code span, say); only a bare one ends it.
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(ln); i++ {
		switch {
		case ln[i] == '\\' && i+1 < len(ln) && ln[i+1] == '|':
			cur.WriteString(`\|`)
			i++
		case ln[i] == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(ln[i])
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

func isSeparator(cells []string) bool {
	for _, c := range cells {
		if strings.Trim(c, "-: ") != "" {
			return false
		}
	}
	return len(cells) > 0
}

// norm is a cell's text with the values a rerun moves normalised away, in this order, and its ';'-separated
// parts sorted (records arrive in a different order from run to run).
func norm(cell string) string {
	s := strings.NewReplacer("`", "", "*", "").Replace(cell)
	s = timeRe.ReplaceAllString(s, "<t>")
	s = durationRe.ReplaceAllString(s, "<d>")
	s = hexRe.ReplaceAllString(s, "<hex>")
	s = ctxRe.ReplaceAllString(s, "<id>")
	s = addrRe.ReplaceAllString(s, "<addr>")
	s = portRe.ReplaceAllString(s, "port <p>")
	s = tmpRe.ReplaceAllString(s, "<tmp>")
	s = revRe.ReplaceAllString(s, "at <rev>")
	s = ttyRe.ReplaceAllString(s, "port=<tty>")
	s = lineRe.ReplaceAllString(s, "<tty>")
	s = rttRe.ReplaceAllString(s, "<rtt>")
	parts := strings.Split(s, ";")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	slices.Sort(parts)
	return strings.Join(parts, "; ")
}

// verdictWords are the words a narrative cell's verdict is read from: a closed vocabulary, matched as whole
// words, case-insensitive. Besides the words below it holds every reason code of internal/decision/reasons.go,
// loaded from the code (identity_ambiguous, store_unavailable, credential_revoked, ...), and an LDAP "Result
// Code <n>" kept whole with its number. The directory and store packages export no clean list of snake_case
// sentinel names, so reasons.go is the only code-loaded source.
var verdictWords = func() *regexp.Regexp {
	alts := []string{`result\s+code\s+\d+`, `not\s+reached`, `not\s+observed`}
	for _, r := range decision.Reasons() {
		alts = append(alts, regexp.QuoteMeta(string(r)))
	}
	alts = append(alts, "pass", "fail", "invalid", "timeout", "refused", "accepted", "rejected", "ran", "reached",
		"opened", "observed", "denied", "permitted", "allowed", "failed", "succeeded", "yes", "no", "true", "false",
		"stripped", "expanded", "closed", "reset")
	return regexp.MustCompile(`(?i)\b(?:` + strings.Join(alts, "|") + `)\b`)
}()

var (
	spaceRun       = regexp.MustCompile(`\s+`)
	determinerNext = regexp.MustCompile(`^\s+[A-Za-z_<]`) // "no" then a word: "no error", "no <d>"
)

// verdictTokens is the sorted set of verdict words in a cell's normalised text, as "{refused yes}". Two uses of
// a verdict word are not verdicts and are skipped:
//   - a word followed by "'s" is a possessive noun: "the reset's packet" names a packet, it does not say a
//     connection was reset;
//   - "no" followed by a word is a determiner: "no error", "no data after the server's first data", "no request
//     in the capture" describe what a capture held, and come and go with timing (L73). A bare "no" (an answer,
//     "inert: no", "no;") is a verdict.
//
// A set, not a multiset: how many times a word occurs is how many connections a device opened, retried or
// accounted for, which a rerun moves. The 11-06 full regression (719721c7) shows it: L37's "connections:"
// lists ran 2 "accepted" one run and 5 the next, 2 "refused" and then 6, with the same verdict. A word that
// appears or disappears ("accepted; refused" -> "accepted", identity_ambiguous -> "no server answered") flags.
func verdictTokens(s string) string {
	var toks []string
	for _, m := range verdictWords.FindAllStringIndex(s, -1) {
		tok, rest := spaceRun.ReplaceAllString(strings.ToLower(s[m[0]:m[1]]), " "), s[m[1]:]
		if strings.HasPrefix(rest, "'s") || strings.HasPrefix(rest, "’s") || (tok == "no" && determinerNext.MatchString(rest)) {
			continue
		}
		toks = append(toks, tok)
	}
	slices.Sort(toks)
	return "{" + strings.Join(slices.Compact(toks), " ") + "}"
}

// splitParens splits a cell into its text outside top-level parentheses and the parentheticals' contents. A
// parenthesis inside a code span is the span's text (a regexp such as `^show( *\|.*)?$`), not a parenthetical.
func splitParens(cell string) (outside, inside string) {
	var out, in strings.Builder
	depth, code := 0, false
	for _, r := range cell {
		switch {
		case r == '`':
			code = !code
		case !code && r == '(':
			depth++
			in.WriteRune(' ')
			continue
		case !code && r == ')' && depth > 0:
			depth--
			in.WriteRune(' ')
			continue
		}
		if depth > 0 {
			in.WriteRune(r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String(), in.String()
}

// compareCell is what decides whether a compared cell changed.
//
// A verdict column's cell is compared on its full normalised text, but a parenthetical in it is narrative and
// compared on its verdict words only. Why: a parenthetical annotates the verdict before it with what the run
// happened to see. L29-reload's vJunos rows read "printed its output in 200ms (the reset's packet:
// `type=acct`)" on some runs and plain "printed its output in 200ms" on others, depending on which packet the
// device sent first after the change, while the verdict stayed the same. A verdict word inside the parenthetical
// ("(the second attempt refused)") still flags.
//
// A narrative column's cell is compared on its verdict words: its text carries figures a rerun moves and no
// normaliser can tell from a real difference (byte counts, round trips, "purged 153 token(s)", step counts).
func compareCell(cell string, verdict bool) string {
	if !verdict {
		return verdictTokens(norm(cell))
	}
	// A parenthetical with no verdict word compares as no parenthetical at all.
	outside, inside := splitParens(cell)
	if toks := verdictTokens(norm(inside)); toks != "{}" {
		return norm(outside) + " " + toks
	}
	return norm(outside)
}

// verdictRows lists the rows of a note in order. A key that repeats gets a "#2", "#3" suffix.
func verdictRows(note string) []verdictRow {
	var rows []verdictRow
	seen := map[string]int{}
	addRow := func(key, label, verdict, shown string) {
		seen[key]++
		if seen[key] > 1 {
			key = fmt.Sprintf("%s#%d", key, seen[key])
		}
		rows = append(rows, verdictRow{key, label, verdict, shown})
	}
	// A bullet or prose verdict is compared on its full text, which is also what a report shows.
	add := func(key, label, verdict string) { addRow(key, label, verdict, verdict) }
	heading, header := "", ""
	var compared []int   // the columns of the table being read that are compared
	var isVerdict []bool // per column of that table: a verdict column (full text) or narrative (verdict words)
	inTable, fenced, isResult := false, false, false
	for _, ln := range strings.Split(note, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "```") {
			fenced, inTable = !fenced, false
			continue
		}
		if fenced {
			continue // a code fence's lines are quoted text: no heading, row or bullet
		}
		if strings.HasPrefix(ln, "#") {
			heading = strings.TrimSpace(strings.TrimLeft(ln, "#"))
		}
		cells := splitRow(ln)
		if cells == nil {
			inTable = false
			proseRows(strings.TrimRight(ln, " \t"), heading, add)
			continue
		}
		if !inTable {
			// the first row of a table is its header
			inTable, header, compared = true, strings.Join(cells, "|"), nil
			isResult, isVerdict = false, make([]bool, len(cells))
			for i, c := range cells {
				l := strings.ToLower(strings.Trim(c, "*` "))
				isResult = isResult || resultColumn.MatchString(l)
				isVerdict[i] = verdictColumn.MatchString(l)
				if i > 0 && !excludedColumn.MatchString(l) && l != "why" {
					compared = append(compared, i)
				}
			}
			continue
		}
		matrix := boolMatrixRow(cells)
		if isSeparator(cells) || len(cells) < 2 || (!isResult && !matrix) {
			continue
		}
		var verdict, shown []string
		for _, i := range compared {
			if i < len(cells) {
				// every column of a bare yes/no matrix row is a verdict column, whatever its header says
				verdict = append(verdict, compareCell(cells[i], matrix || (i < len(isVerdict) && isVerdict[i])))
				shown = append(shown, norm(cells[i]))
			}
		}
		addRow(heading+"\x00"+header+"\x00"+cells[0], labelFor(heading, cells[0]), strings.Join(verdict, " | "), strings.Join(shown, " | "))
	}
	return rows
}

// boolMatrixRow is whether every cell after the first is a bare yes, no, true, false or "not parsed": a row of
// a matrix of answers, whatever its headers say (L57's "capture | p49g-tip | ..." table).
func boolMatrixRow(cells []string) bool {
	for _, c := range cells[1:] {
		switch strings.ToLower(strings.Trim(c, "*` ")) {
		case "yes", "no", "true", "false", "not parsed":
		default:
			return false
		}
	}
	return len(cells) > 1
}

// proseRows reads the verdicts a line that is not a table row states.
func proseRows(ln, heading string, add func(key, label, verdict string)) {
	t := strings.TrimSpace(ln)
	switch {
	case proseVerdict.MatchString(t):
		m := proseVerdict.FindStringSubmatch(t)
		add(heading+"\x00prose\x00"+m[1], labelFor(heading, strings.TrimSpace(m[1]+" "+m[2])), m[2])
	case cellVerdict.MatchString(t):
		m := cellVerdict.FindStringSubmatch(t)
		add(heading+"\x00cell\x00"+m[1], labelFor(heading, m[1]), m[2])
	case boldClaim.MatchString(t):
		m := boldClaim.FindStringSubmatch(t)
		add(heading+"\x00claim\x00"+m[1], labelFor(heading, m[1]), norm(m[2]))
	case boldValue.MatchString(t):
		i := boldValue.FindStringIndex(t)[0]
		add(heading+"\x00bold\x00"+strings.TrimPrefix(t[:i], "- "), labelFor(heading, strings.TrimPrefix(t[:i], "- ")), norm(t[i:]))
	case strings.HasPrefix(strings.ToLower(heading), "read off") && strings.HasPrefix(ln, "- "):
		claim, rest := readOffClaim(strings.TrimPrefix(ln, "- "))
		add(heading+"\x00readoff\x00"+claim, labelFor(heading, claim), norm(rest))
	default:
		yesNoClaims(t, heading, add)
	}
}

// yesNoClaims reads each "<claim>: yes|no|true|false" in a sentence. A claim runs back from its colon to the
// previous '(', ';', sentence end, earlier claim, or the line's start.
func yesNoClaims(t, heading string, add func(key, label, verdict string)) {
	if strings.HasPrefix(t, "#") {
		return
	}
	prev := 0
	for _, m := range claimYN.FindAllStringSubmatchIndex(t, -1) {
		start := prev
		for _, d := range []string{"(", ";", ". "} {
			if i := strings.LastIndex(t[start:m[0]], d); i >= 0 {
				start += i + len(d)
			}
		}
		claim := strings.TrimSpace(strings.TrimLeft(strings.NewReplacer("*", "").Replace(t[start:m[0]]), "-+ \t"))
		prev = m[1]
		if len(claim) < 3 || len(claim) > 140 {
			continue
		}
		add(heading+"\x00yn\x00"+claim, labelFor(heading, claim), t[m[2]:m[3]])
	}
}

// readOffClaim splits a "Read off the table" bullet into its subject and the rest: at the first ": " or " = ",
// "explicit anchors: true: ..." and "JunosFacts.CaseSensitive = false: ...". A bullet with neither is all subject.
func readOffClaim(b string) (claim, rest string) {
	i, j := strings.Index(b, ": "), strings.Index(b, " = ")
	switch {
	case i < 0 && j < 0:
		return b, ""
	case j >= 0 && (i < 0 || j < i):
		return b[:j], b[j+3:]
	}
	return b[:i], b[i+2:]
}

// labelFor is what a report names a row by: its first cell, and the heading it sits under.
func labelFor(heading, first string) string {
	if heading == "" {
		return first
	}
	return fmt.Sprintf("%s (under %q)", first, heading)
}

// verdictChanges describes each row whose verdict differs between the committed note and the rewritten one,
// and each row added or removed.
func verdictChanges(old, now string) []string {
	changes, _ := compareNotes(old, now)
	return changes
}

// compareNotes is verdictChanges plus the narrative changes: rows whose verdict held while their shown text
// changed. Both name the row and print its normalised text, old -> new.
func compareNotes(old, now string) (changes, narrative []string) {
	oldRows, newRows := verdictRows(old), verdictRows(now)
	was, is := map[string]verdictRow{}, map[string]bool{}
	for _, r := range oldRows {
		was[r.key] = r
	}
	for _, r := range newRows {
		is[r.key] = true
		o, ok := was[r.key]
		switch {
		case !ok:
			changes = append(changes, fmt.Sprintf("%s: added (%s)", r.label, r.shown))
		case o.verdict != r.verdict:
			changes = append(changes, fmt.Sprintf("%s: %s -> %s", r.label, o.shown, r.shown))
		case o.shown != r.shown:
			narrative = append(narrative, fmt.Sprintf("%s: %s -> %s", r.label, o.shown, r.shown))
		}
	}
	for _, r := range oldRows {
		if !is[r.key] {
			changes = append(changes, fmt.Sprintf("%s: removed (was %s)", r.label, r.shown))
		}
	}
	return changes, narrative
}

// noVerdicts is whether a note of the entry states no claim verdict (an observation-only note): the entry
// says `verdicts: none`, or lists the note in no_verdict_notes.
func noVerdicts(e Entry, note string) bool {
	return e.Verdicts == "none" || slices.Contains(e.NoVerdictNotes, note)
}

// gitShow is the note as HEAD has it. Any git failure is an error: git missing, a dubious-ownership
// refusal, a run outside the repository, a note HEAD does not have.
func gitShow(path string) (string, error) {
	out, err := exec.Command("git", "show", "HEAD:"+path).Output()
	if err != nil {
		msg := err.Error()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg += ": " + strings.TrimSpace(string(ee.Stderr))
		}
		return "", fmt.Errorf("%s has no readable copy at HEAD (%s)", path, msg)
	}
	return string(out), nil
}

// checkVerdicts fails an entry whose rewritten notes changed a claim's verdict from HEAD's: a flaked or
// regressed cell must not pass because the binary exited 0. It names the entry, the note, the row, and
// old -> new. Every manifest note belongs to a closed row, so it must exist at HEAD, and a note that parses
// no row is refused unless the entry says `verdicts: none`.
func checkVerdicts(e Entry) error { return checkVerdictsWith(e, gitShow) }

func checkVerdictsWith(e Entry, show func(path string) (string, error)) error {
	var all []string
	for _, n := range e.Notes {
		old, err := show(n)
		if err != nil {
			return fmt.Errorf("%s: %w", e.ID, err)
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		now := string(raw)
		switch rows := len(verdictRows(now)); {
		case noVerdicts(e, n) && rows > 0:
			return fmt.Errorf("%s: %s is marked as stating no verdicts but parses %d rows: remove the mark", e.ID, n, rows)
		case noVerdicts(e, n):
			continue
		case rows == 0:
			return fmt.Errorf("%s: %s parses no verdict rows: a shape verdicts.go misses, or the entry needs `verdicts: none`", e.ID, n)
		}
		changes, narrative := compareNotes(old, now)
		for _, c := range changes {
			all = append(all, fmt.Sprintf("%s: %s: %s", e.ID, n, c))
		}
		for _, c := range narrative {
			fmt.Fprintf(narrativeOut, "lab-regress: %s: %s: narrative changed (not a verdict, not failed): %s\n", e.ID, n, c)
		}
	}
	if len(all) > 0 {
		return fmt.Errorf("a claim's verdict changed from HEAD:\n  %s", strings.Join(all, "\n  "))
	}
	return nil
}
