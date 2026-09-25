package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rhwendt/port49/internal/capability"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
)

// devicesCapabilities is `port49 devices capabilities` (spec §9): what each
// inventory device declares it authorizes beside what the decision log shows
// it asked, and each device whose accounting holds commands no authorization
// request accounts for. It reads the log a daemon wrote; it never contacts a
// device, and nobody asserts anything by hand. It exits 1 on a finding a
// cron job should page on, a contradiction between what a device declares and
// what it did: config-commands probably off, or an unauthorized tier in a
// window whose accounting stream is whole. A device never seen in the window
// is a note and exits 0: in a day's window every device nobody logged into
// is one, and a job that pages on them is a job nobody reads (spec §9; plan 5b
// pre-flight I13).
func devicesCapabilities(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 devices capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	since := fs.Duration("since", 0, "read only the records within this long of the newest one (default: all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || fs.NArg() == 0 || *since < 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	out, errOut, flush := redactOutput(stdout, stderr)
	defer flush()
	stdout, stderr = out, errOut
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices capabilities:", err)
		return 1
	}
	out.learn(p)
	errOut.learn(p)
	recs, unread, err := readLogs(fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices capabilities:", err)
		return 1
	}
	// Examples echoed from the log are redacted as port49d redacts a record:
	// the platform's built-in patterns and the policy's own (spec §5.8).
	opt := capability.Options{Redactor: func(name string) []platform.Redaction {
		return append(platform.Redactions(name), p.Dialect(name).Redact...)
	}}
	if *since > 0 && len(recs) > 0 {
		newest := recs[0].TS
		for _, r := range recs {
			if r.TS.After(newest) {
				newest = r.TS
			}
		}
		opt.From = newest.Add(-*since)
	}
	now := time.Now()
	var devices []capability.Device
	for _, d := range p.Devices() {
		cd := capability.Device{Name: d.Name, Platform: d.Platform, Supports: p.Dialect(d.Platform).Supports}
		cd.Quarantine, _ = p.Quarantined(d.Name, now)
		devices = append(devices, cd)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Name < devices[j].Name })
	rep := capability.Infer(recs, devices, opt)
	fmt.Fprintf(stdout, "window: %s; %s\n", rep.Window(), streamHealth(rep, unread))
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE\tPLATFORM\tADMISSION\tSUPPORTS\tOBSERVED\t")
	code := 0
	for _, r := range rep.Rows {
		admission, observed := "admitted", strings.Join(r.Observed, ",")
		if observed == "" {
			observed = "—"
		}
		var flags []string
		if r.Device.Quarantine != "" {
			admission = "quarantined"
			flags = append(flags, "✗ "+r.Device.Quarantine)
		}
		for _, w := range r.Warnings {
			if r.Unauthorized > 0 && strings.HasSuffix(w, "had no corresponding authorization request") {
				continue // the reconciliation section says it, qualified
			}
			flags = append(flags, "⚠ "+w)
			code = 1
		}
		for _, n := range r.Notes {
			flags = append(flags, "note: "+n)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Device.Name, r.Device.Platform, admission,
			strings.Join(r.Device.Supports, ","), observed, strings.Join(flags, "; "))
	}
	tw.Flush()
	for _, r := range rep.Rows {
		if r.Unauthorized == 0 {
			continue
		}
		head := "⚠ UNAUTHORIZED TIER"
		if !rep.Qualified() {
			head = "? POSSIBLY AN UNAUTHORIZED TIER (the accounting stream has a gap in this window)"
		} else {
			code = 1
		}
		quoted := make([]string, len(r.Examples))
		for i, e := range r.Examples {
			quoted[i] = out.quote(e)
		}
		fmt.Fprintf(stdout, "\n%s — %s\n    %d commands in accounting had no corresponding authorization request\n"+
			"    example: %s\n    accounting on %s in the window: %d unattributed, %d foreign, %d system\n", head,
			r.Device.Name, r.Unauthorized, strings.Join(quoted, ", "), r.Device.Name, r.Unattributed, r.Foreign, r.System)
	}
	return code
}

// streamHealth is the window's accounting stream as the report qualifies
// its findings by it (spec §9, "What silence can and cannot mean").
func streamHealth(rep capability.Report, unread int) string {
	s := "accounting stream: no account_gap in the window"
	if !rep.Qualified() {
		by := map[string]int{}
		for _, g := range rep.Gaps {
			by[g.Stage] += g.Records
		}
		var parts []string
		for _, stage := range []string{"offer_refused", "drain_unparseable", "drain_set_aside"} {
			if by[stage] > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", stage, by[stage]))
			}
		}
		s = "accounting stream: records dropped in the window (" + strings.Join(parts, ", ") +
			"), so a reconciliation finding below is possible, not proven"
	}
	if unread > 0 {
		s += fmt.Sprintf("; %d log lines did not read as records and were skipped", unread)
	}
	return s
}

// readLogs reads decision-log files, `-` for stdin, one JSON record a line.
// A line that does not read as a record is counted, never quoted.
func readLogs(names []string) (recs []decision.Record, unread int, err error) {
	for _, name := range names {
		if err := readLog(name, &recs, &unread); err != nil {
			return nil, 0, err
		}
	}
	return recs, unread, nil
}

func readLog(name string, recs *[]decision.Record, unread *int) error {
	in := io.Reader(os.Stdin)
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var r decision.Record
		if r.UnmarshalJSON(sc.Bytes()) != nil {
			*unread++
			continue
		}
		*recs = append(*recs, r)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s was not read to the end: %w", name, err)
	}
	return nil
}
