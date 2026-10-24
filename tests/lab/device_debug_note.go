package lab

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The results note of an armed TestQualify run (PORT49_LAB_DEVICE_DEBUG=1),
// tests/lab/results/QUAL-DEBUG-<slug>-<platform>.md. The harness writes it from
// what the run measured, so a note never disagrees with the evidence next to it
// (the four first notes were written by hand and did). Platform and image
// version come from the run. Every open question is answered by a kept debug
// line, or says it is unmeasured and why. Only filtered text goes in: the kept
// lines, the closed-alphabet shape sample and the header-only connection lines.

// ddNoteCell is one armed cell: what its debug capture kept and what the arm
// measured around it.
type ddNoteCell struct {
	Cell       string
	Kept       deviceDebugKept
	RawLines   int          // the log lines the device returned
	Shapes     []string     // the shape sample of the lines the filter dropped, `command => skeleton`
	TLSConns   []string     // the cell's TLS connections from the header-only capture
	Ready      int          // readiness-probe connections that ran after debug went on
	CaptureErr bool         // the capture ended in an error (its text is not kept)
	Drops      ddDropCounts // lines dropped, by rule (numbers only)
	Tags       string       // the syslog process tag counts (Junos), numbers only
	Flags      []string     // the traceoptions flag words the CLI offered (Junos), each ddFlagWord
	AuthdPID   string       // ddAuthdPIDChange: yes, no or unmeasured (Junos), never the process line
}

// ddNoteRun is an armed run: the platform, the image and its cells.
type ddNoteRun struct {
	Platform string // the lab platform name, e.g. cisco_xrd
	Profile  string // its device-debug profile, a key of deviceDebugProfiles
	Image    string // the image version as the platform row carries it
	Cells    []ddNoteCell
}

const (
	ddNoteMaxShapes = 30 // shapes listed per cell; the rest are in the test log
	ddNoteTokenCell = "tls_token_login"
	ddNoteCACell    = "tls_unknown_ca"
)

// ddNoteFailure is a kept message that states a TLS failure.
var ddNoteFailure = regexp.MustCompile(`(?i)\b(?:ssl|tls)\b.*\b(?:fail|failed|error)\b|\b(?:fail|failed|error)\b.*\b(?:ssl|tls)\b`)

// ddNoteSafe is whether a line that did not come through Keep (a capture line, a
// shape) may go in a note: no secret word, no hex run and no long token run.
func ddNoteSafe(s string) bool {
	return !nxosDebugSecret.MatchString(s) && !nxosDebugHexRun.MatchString(s) && !nxosDebugLong.MatchString(s)
}

// ddNoteKeptSafe is whether a kept line may go in a note. Keep has redacted the
// run's secrets and masked long runs, and a debug line may say "password" or
// "challenge" without holding one, so this second gate is the payload word, a
// hex run and a long run: what Keep drops or masks, so none can be here.
func ddNoteKeptSafe(s string) bool {
	return !ddPayload.MatchString(s) && !nxosDebugHexRun.MatchString(s) && !ddHexView(s) && !nxosDebugLong.MatchString(s)
}

// ddNoteLines are the kept lines of cell whose message matches re.
func ddNoteLines(p *ddProfile, kept deviceDebugKept, re *regexp.Regexp) []string {
	var out []string
	if kept == "" || re == nil {
		return nil
	}
	for _, ln := range strings.Split(string(kept), "\n") {
		if _, msg := ddKeptMsg(ln); re.MatchString(msg) {
			out = append(out, ln)
		}
	}
	return out
}

// ddNoteRequest matches a request line of any kind.
func ddNoteRequest(p *ddProfile) *regexp.Regexp {
	var alts []string
	for _, re := range []*regexp.Regexp{p.authen, p.author, p.acct, p.authenAlt, p.authorAlt, p.acctAlt} {
		if re != nil {
			alts = append(alts, "(?:"+re.String()+")")
		}
	}
	return regexp.MustCompile(strings.Join(alts, "|"))
}

func ddNoteCode(ln string) string { return "`" + ln + "`" }

// ddDebugNote is the claim and the observation of the run's note, or an error
// when something that must not be in a note would be.
func ddDebugNote(in ddNoteRun) (claim, obs string, err error) {
	p := deviceDebugProfiles[in.Profile]
	cmds, ok := deviceDebugCmds[in.Profile]
	if p == nil || !ok {
		return "", "", errors.New("INVALID: no device-debug profile for " + in.Profile)
	}
	if len(in.Cells) == 0 {
		return "", "", errors.New("INVALID: the armed run collected no cell")
	}
	cell := map[string]ddNoteCell{}
	for _, c := range in.Cells {
		cell[c.Cell] = c
	}
	var (
		b      strings.Builder
		unsafe []string
		quote  = func(ln string) string { // a device-derived line, gated
			if !ddNoteKeptSafe(ln) {
				unsafe = append(unsafe, ln)
				return "(withheld)"
			}
			return ddNoteCode(ln)
		}
		reqRe   = ddNoteRequest(p)
		summary = map[string]deviceDebugSummary{}
	)
	for _, c := range in.Cells {
		summary[c.Cell] = deviceDebugSummarize(in.Profile, c.Kept)
		// Every kept line is checked, not only the ones the note quotes: the counts
		// in the note are read from all of them.
		if c.Kept != "" {
			for _, ln := range strings.Split(string(c.Kept), "\n") {
				if !ddNoteKeptSafe(ln) {
					unsafe = append(unsafe, ln)
				}
			}
		}
	}

	claim = fmt.Sprintf("What %s's own TACACS+ debug says about the TLS cells of a qualification run on %s: which debug line marks a "+
		"connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's "+
		"debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings "+
		"and long runs were redacted or masked in it.", in.Platform, in.Image)

	fmt.Fprintf(&b, "Platform %s, image %s. Debug on: %s (read with %s; off with %s).\n",
		in.Platform, in.Image, ddNoteCmds(cmds.Enable), ddNoteCmds(cmds.Collect), ddNoteCmds(cmds.Disable))
	b.WriteString("\n### What the filter kept\n\n")
	for _, c := range in.Cells {
		s := summary[c.Cell]
		reqs := 0
		for _, cn := range s.Conns {
			reqs += cn.Total()
		}
		n := ddArmLineCount(c.Kept)
		lifecycle := len(ddNoteLines(p, c.Kept, p.open)) + len(ddNoteLines(p, c.Kept, p.closed))
		fmt.Fprintf(&b, "- `%s`: the device returned %d log lines and the filter kept %d (%d connection open/close, %d request, %d other); "+
			"the capture holds %d TLS connection(s).\n", c.Cell, c.RawLines, n, lifecycle, reqs, max(n-lifecycle-reqs, 0), len(c.TLSConns))
		fmt.Fprintf(&b, "  Lines dropped by rule: %s.\n", c.Drops)
		closed := fmt.Sprint(s.Closed)
		if s.CloseUnknown {
			closed = "unknown"
		}
		fmt.Fprintf(&b, "  - debug connections opened=%d closed=%s single_connect_lines=%d server_dead_lines=%d fallback_lines=%d.\n",
			s.Opened, closed, s.SingleConnect, s.ServerDead, s.Fallback)
		if s.Failed > 0 {
			fmt.Fprintf(&b, "  - debug connections failed_opens=%d.\n", s.Failed)
		}
		if len(c.Flags) > 0 {
			fmt.Fprintf(&b, "  - traceoptions flag words the CLI offered: %s.\n", strings.Join(c.Flags, " "))
		}
		if c.AuthdPID != "" {
			fmt.Fprintf(&b, "  - authd_pid_changed=%s (the authd process id before and after the trace was enabled).\n", c.AuthdPID)
		}
		if c.Tags != "" {
			fmt.Fprintf(&b, "  - syslog process tags (counts only): %s.\n", c.Tags)
		}
		for i, cn := range s.Conns {
			open, end := cn.Opened, cn.Closed
			if open == "" {
				open = "before"
			}
			if end == "" {
				end = "open"
			}
			if s.CloseUnknown {
				end = "unknown"
			}
			fmt.Fprintf(&b, "  - debug connection %d: opened=%s closed=%s reason=%q authen=%d author=%d acct=%d requests=%d.\n",
				i+1, open, end, cn.Reason, cn.Authen, cn.Author, cn.Acct, cn.Total())
		}
		for _, l := range c.TLSConns {
			if !ddNoteSafe(l) {
				unsafe = append(unsafe, l)
				continue
			}
			fmt.Fprintf(&b, "  - capture: %s\n", ddNoteCode(l))
		}
		if c.Ready > 0 {
			fmt.Fprintf(&b, "  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): %d.\n", c.Ready)
		}
		if c.CaptureErr {
			b.WriteString("  - the capture ended in an error: the counts above may be short.\n")
		}
		if n == 0 {
			b.WriteString("  - **the filter kept nothing**: the shapes below are the lines it dropped.\n")
		}
	}
	if p.noClose {
		b.WriteString("\nThis platform's two debug files are joined in order, not merged by time, so a request is attributed to the last " +
			"connection opened in the trace, not necessarily the one it was sent on; and neither file has a close line.\n")
	}

	b.WriteString("\n### Open questions\n\n")
	// Q1: the line that marks a connection open.
	b.WriteString("- **Which debug line marks a connection open?** ")
	var answered []string
	for _, c := range in.Cells {
		if l := ddNoteLines(p, c.Kept, p.open); len(l) > 0 {
			answered = append(answered, fmt.Sprintf("`%s`: %s (%d in the cell)", c.Cell, quote(l[0]), len(l)))
		}
	}
	if len(answered) == 0 {
		b.WriteString("Unmeasured: no kept line is a connection open.\n")
	} else {
		b.WriteString(strings.Join(answered, "; ") + ".\n")
	}

	// Q2: the second connection of tls_token_login.
	b.WriteString("- **tls_token_login: why does the device open a second connection?** ")
	if c, ok := cell[ddNoteTokenCell]; !ok {
		b.WriteString("Unmeasured: the cell was not run armed.\n")
	} else if len(c.TLSConns) < 2 {
		fmt.Fprintf(&b, "Not asked in this run: the capture holds %d connection(s).\n", len(c.TLSConns))
	} else if lines := ddNoteLines(p, c.Kept, p.open); len(lines) < 2 {
		fmt.Fprintf(&b, "Unmeasured: the capture holds %d connections and the kept debug marks %d open(s).\n", len(c.TLSConns), len(lines))
	} else {
		all := strings.Split(string(c.Kept), "\n")
		before := ""
		for i, ln := range all {
			if ln == lines[1] && i > 0 {
				before = all[i-1]
				break
			}
		}
		fmt.Fprintf(&b, "The debug shows the second open at %s", quote(lines[1]))
		if before != "" {
			fmt.Fprintf(&b, ", after %s", quote(before))
		}
		b.WriteString(". That is the line that comes before it, not a stated cause.\n")
	}

	// Q3: how a connection ends.
	b.WriteString("- **How does a connection end?** ")
	var ends []string
	for _, name := range []string{ddNoteCACell, ddNoteTokenCell} {
		c, ok := cell[name]
		if !ok {
			continue
		}
		var found []string
		if !p.noClose {
			if l := ddNoteLines(p, c.Kept, p.closed); len(l) > 0 {
				found = append(found, "close "+quote(l[0]))
			}
		}
		if l := ddNoteLines(p, c.Kept, ddNoteFailure); len(l) > 0 {
			found = append(found, "TLS failure "+quote(l[0]))
		}
		if len(found) > 0 {
			ends = append(ends, fmt.Sprintf("`%s`: %s", name, strings.Join(found, ", ")))
		}
	}
	switch {
	case len(ends) > 0:
		b.WriteString(strings.Join(ends, "; ") + ".\n")
	case p.noClose:
		b.WriteString("Unmeasured: this platform's debug has no close line, and no kept line states a TLS failure.\n")
	default:
		b.WriteString("Unmeasured: no kept line is a close or a TLS failure.\n")
	}

	// Q4: requests per connection.
	b.WriteString("- **Do requests ride one connection together (pipelining)?** ")
	if c, ok := cell[ddNoteTokenCell]; !ok {
		b.WriteString("Unmeasured: the cell was not run armed.\n")
	} else {
		s := summary[c.Cell]
		placedConns, placedReqs, multi := s.Placed()
		reqs := placedReqs + s.Unplaced
		switch {
		case reqs == 0:
			b.WriteString("Unmeasured: no kept line is a request.\n")
		case s.Opened == 0:
			fmt.Fprintf(&b, "Unmeasured: %d request line(s) were kept but no connection open, so none can be assigned to a connection.\n", reqs)
		case p.noClose:
			fmt.Fprintf(&b, "Unmeasured: %d request line(s) were kept, but the trace's requests cannot be assigned to a connection (see above).\n", reqs)
		case s.Opened < len(c.TLSConns):
			fmt.Fprintf(&b, "Unmeasured: the debug kept %d open(s) for the capture's %d connection(s), so a request cannot be placed on every connection; "+
				"%d request line(s) are not placed on a connection.\n", s.Opened, len(c.TLSConns), s.Unplaced)
		default:
			first := ddNoteLines(p, c.Kept, reqRe)
			fmt.Fprintf(&b, "%d of %d debug connection(s) with a kept open carried more than one request (%d placed request line(s)); "+
				"requests not placed on a connection: %d; first request line %s.\n", multi, placedConns, placedReqs, s.Unplaced, quote(first[0]))
		}
	}

	b.WriteString("\n### Shapes of the lines the filter dropped\n\n")
	b.WriteString("Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.\n")
	for _, c := range in.Cells {
		fmt.Fprintf(&b, "\n`%s`: %d shape(s)", c.Cell, len(c.Shapes))
		if len(c.Shapes) > ddNoteMaxShapes {
			fmt.Fprintf(&b, ", the first %d", ddNoteMaxShapes)
		}
		b.WriteString("\n\n")
		for i, sh := range c.Shapes {
			if i == ddNoteMaxShapes {
				break
			}
			if !ddNoteSafe(sh) {
				unsafe = append(unsafe, sh)
				continue
			}
			fmt.Fprintf(&b, "- %s\n", ddNoteCode(sh))
		}
	}
	if len(unsafe) > 0 {
		return "", "", fmt.Errorf("INVALID: %d line(s) bound for the note hold a secret word, a hex run or a long token run (the filter should have dropped them)", len(unsafe))
	}
	return claim, b.String(), nil
}

// ddNoteCmds lists commands as code spans; an empty command (a bare Enter) is
// written as <enter>.
func ddNoteCmds(cmds []string) string {
	var out []string
	for _, c := range cmds {
		if c == "" {
			c = "<enter>"
		}
		out = append(out, "`"+c+"`")
	}
	return strings.Join(out, ", ")
}

// qualWriteDebug writes the run's note through write, or writes nothing and
// returns why: the same gates as every other results note (a credential this
// run used, a hash value under a *_sha256 key).
func qualWriteDebug(in ddNoteRun, secrets []string, write func(claim, obs string)) error {
	claim, obs, err := ddDebugNote(in)
	if err != nil {
		return err
	}
	if bad := qualNoteGate(claim+"\n"+obs, secrets); len(bad) > 0 {
		return fmt.Errorf("INVALID: the device-debug note was not written:\n  %s", strings.Join(bad, "\n  "))
	}
	write(claim, obs)
	return nil
}
