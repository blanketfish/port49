package labpcap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// FileResult is one capture's outcome.
type FileResult struct {
	Name  string // base name, e.g. "L4-cisco_nxos.pcap"
	In    string
	Out   string
	Stats Stats
	Err   error
}

// RedactDir redacts every `*.pcap` in inDir into outDir, verifying each one
// before it is written.
//
// Nothing reaches outDir unverified: a capture whose redaction or verification
// fails leaves no file behind at all, so a half-redacted evidence file can
// never be the thing someone commits. The error is reported per file and the
// pass carries on, because one unreadable capture is not a reason to leave
// eleven good ones unredacted.
func RedactDir(inDir, outDir string, opt Options) ([]FileResult, error) {
	names, err := filepath.Glob(filepath.Join(inDir, "*.pcap"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	out := make([]FileResult, 0, len(names))
	for _, in := range names {
		r := FileResult{Name: filepath.Base(in), In: in, Out: filepath.Join(outDir, filepath.Base(in))}
		o := opt
		if opt.KeyFor != nil {
			if k := opt.KeyFor(r.Name); k != "" {
				o.Key = k
			}
		}
		r.Stats, r.Err = redactOne(in, r.Out, o)
		out = append(out, r)
	}
	return out, nil
}

func redactOne(in, out string, opt Options) (Stats, error) {
	raw, err := os.ReadFile(in)
	if err != nil {
		return Stats{}, err
	}
	red, st, err := Redact(raw, opt)
	if err != nil {
		return st, err
	}
	if err := Verify(raw, red, opt); err != nil {
		// The half-written file is the dangerous one: it looks like evidence.
		_ = os.Remove(out)
		return st, fmt.Errorf("verification failed, nothing written: %w", err)
	}
	if err := os.WriteFile(out, red, 0o644); err != nil {
		return st, err
	}
	// Read it back from disk and verify that, not the bytes in memory. A
	// truncated write is exactly the failure that would otherwise ship.
	back, err := os.ReadFile(out)
	if err != nil {
		return st, err
	}
	if err := Verify(raw, back, opt); err != nil {
		_ = os.Remove(out)
		return st, fmt.Errorf("the file written to disk did not verify, so it was removed: %w", err)
	}
	return st, nil
}
