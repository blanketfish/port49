// Package keystatus reads a rotation's phase-out from the decision log (spec
// §10, "Phase-out has to be observable"; §12, `port49 keys status`): the key
// version each device's latest validated exchange used, which devices are
// still on a version other than current, which inventory devices the log
// never saw, and every source whose packets validated against nothing. It
// reads no secret.
package keystatus

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/decision"
)

// Device is an inventory device and the key_ref it is assigned.
type Device struct {
	Name, KeyRef string
	Addresses    []netip.Addr
}

// Version is one key version, as port49d.yaml declares it at the report's
// Now: "current", "accept", or "retired" (listed retired, or past RetireAt).
type Version struct {
	Number   int
	State    string
	RetireAt time.Time
}

// Key is one key_ref's versions.
type Key struct {
	Ref      string
	Versions []Version
}

// Options bound the report. A zero From reads every record.
type Options struct {
	From, Now time.Time
}

// Row is one key version: the devices whose latest validated exchange used
// it, and when the latest of those was.
type Row struct {
	KeyRef   string
	Version  int
	State    string
	RetireAt time.Time
	Devices  []string
	Last     time.Time
}

// Source is every unvalidated packet from one source address under one
// diagnosis.
type Source struct {
	Source, Device, KeyRef, Diagnosis string
	Version, Attempts                 int
	Last                              time.Time
}

// Report is the rotation's state as the log shows it.
type Report struct {
	Rows    []Row
	Unseen  []Device
	Sources []Source
}

type latest struct {
	ref     string
	version int
	at      time.Time
}

// Infer builds the report. A quarantined device's records are not a key
// matter and are left out of Sources.
func Infer(recs []decision.Record, devices []Device, keys []Key, opt Options) Report {
	byAddr := map[netip.Addr]string{}
	for _, d := range devices {
		for _, a := range d.Addresses {
			byAddr[a] = d.Name
		}
	}
	last := map[string]latest{}
	type srcKey struct{ source, diag string }
	srcs := map[srcKey]*Source{}
	for _, r := range recs {
		if !opt.From.IsZero() && r.TS.Before(opt.From) {
			continue
		}
		if r.Event == decision.EventUnvalidated && r.Unvalidated != nil {
			u := r.Unvalidated
			if u.Diagnosis == "device_quarantined" {
				continue
			}
			k := srcKey{u.Source, u.Diagnosis}
			s, ok := srcs[k]
			if !ok {
				s = &Source{Source: u.Source, Diagnosis: u.Diagnosis, KeyRef: u.KeyRef}
				if r.Device != nil && r.Device.Name != "" {
					s.Device = r.Device.Name
				} else if a, err := netip.ParseAddr(u.Source); err == nil {
					s.Device = byAddr[a]
				}
				srcs[k] = s
			}
			s.Attempts++
			if r.TS.After(s.Last) {
				s.Last = r.TS
				if u.Version > 0 {
					s.Version = u.Version
				}
			}
			continue
		}
		// An unvalidated record is never a version in use, whatever else it
		// carries.
		if r.Event == decision.EventUnvalidated || r.Device == nil || r.Device.Name == "" || r.Device.KeyVersion == 0 {
			continue
		}
		if l, ok := last[r.Device.Name]; !ok || r.TS.After(l.at) {
			last[r.Device.Name] = latest{r.Device.KeyRef, r.Device.KeyVersion, r.TS}
		}
	}
	var rep Report
	type verKey struct {
		ref     string
		version int
	}
	rows := map[verKey]int{}
	sorted := append([]Key(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Ref < sorted[j].Ref })
	for _, k := range sorted {
		vs := append([]Version(nil), k.Versions...)
		sort.Slice(vs, func(i, j int) bool { return vs[i].Number > vs[j].Number })
		for _, v := range vs {
			rows[verKey{k.Ref, v.Number}] = len(rep.Rows)
			rep.Rows = append(rep.Rows, Row{KeyRef: k.Ref, Version: v.Number, State: v.State, RetireAt: v.RetireAt})
		}
	}
	names := make([]string, 0, len(last))
	for name := range last {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		l := last[name]
		i, ok := rows[verKey{l.ref, l.version}]
		if !ok {
			// A version the log names and port49d.yaml no longer declares.
			i = len(rep.Rows)
			rows[verKey{l.ref, l.version}] = i
			rep.Rows = append(rep.Rows, Row{KeyRef: l.ref, Version: l.version, State: "undeclared"})
		}
		rep.Rows[i].Devices = append(rep.Rows[i].Devices, name)
		if l.at.After(rep.Rows[i].Last) {
			rep.Rows[i].Last = l.at
		}
	}
	for _, d := range devices {
		if _, ok := last[d.Name]; !ok {
			rep.Unseen = append(rep.Unseen, d)
		}
	}
	sort.Slice(rep.Unseen, func(i, j int) bool { return rep.Unseen[i].Name < rep.Unseen[j].Name })
	for _, s := range srcs {
		rep.Sources = append(rep.Sources, *s)
	}
	sort.Slice(rep.Sources, func(i, j int) bool {
		if !rep.Sources[i].Last.Equal(rep.Sources[j].Last) {
			return rep.Sources[i].Last.After(rep.Sources[j].Last)
		}
		return rep.Sources[i].Source < rep.Sources[j].Source
	})
	return rep
}

// Write prints the report as spec §10 shows it.
func (r Report) Write(w io.Writer, now time.Time) {
	fmt.Fprintf(w, "%-12s %7s  %-10s %7s  %s\n", "KEY_REF", "VERSION", "STATE", "DEVICES", "LAST OLD-KEY USE")
	prev := ""
	for _, row := range r.Rows {
		ref := row.KeyRef
		if ref == prev {
			ref = ""
		}
		prev = row.KeyRef
		lastUse := "—"
		stalled := row.State != "current" && len(row.Devices) > 0
		if stalled {
			lastUse = ago(now, row.Last)
		}
		line := fmt.Sprintf("%-12s %7d  %-10s %7d  %s", ref, row.Version, row.State, len(row.Devices), lastUse)
		if stalled {
			line += "   ⚠ rotation not finished: " + strings.Join(row.Devices, ", ")
			if !row.RetireAt.IsZero() {
				line += fmt.Sprintf(" (retire_after %s)", row.RetireAt.AddDate(0, 0, -1).Format("2006-01-02"))
			}
		}
		fmt.Fprintln(w, line)
	}
	if len(r.Unseen) > 0 {
		names := make([]string, len(r.Unseen))
		for i, d := range r.Unseen {
			names[i] = d.Name
		}
		fmt.Fprintf(w, "never seen in the log: %s\n", strings.Join(names, ", "))
	}
	if len(r.Sources) == 0 {
		return
	}
	fmt.Fprintf(w, "\nUNVALIDATED SOURCES\n%-15s %-12s %-12s %8s  %-9s %s\n", "SOURCE", "DEVICE", "KEY_REF",
		"ATTEMPTS", "LAST", "DIAGNOSIS")
	for _, s := range r.Sources {
		dev, ref := s.Device, s.KeyRef
		if dev == "" {
			dev = "—"
		}
		if ref == "" {
			ref = "—"
		}
		fmt.Fprintf(w, "%-15s %-12s %-12s %8d  %-9s %s\n", s.Source, dev, ref, s.Attempts, ago(now, s.Last),
			Describe(s.Diagnosis, s.Version))
	}
}

// Describe is a diagnosis as the report words it (spec §10).
func Describe(diagnosis string, version int) string {
	switch diagnosis {
	case "matches_retired":
		return fmt.Sprintf("matches retired v%d", version)
	case "no_known_key_matches":
		return "no known key matches"
	case "unadmitted_source":
		return "unadmitted source"
	case "not_tacacs":
		return "not TACACS+ (header invalid)"
	case "unencrypted_refused":
		return "unencrypted — refused"
	case "malformed_after_validation":
		return "malformed after validation"
	case "admission_refused":
		return "in inventory, admission refused"
	case "admission_withdrawn":
		return "admission withdrawn on an open connection"
	}
	return diagnosis
}

func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
