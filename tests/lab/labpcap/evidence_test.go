package labpcap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// TestCommittedEvidenceMatchesTheCaptures audits what is actually on this
// machine: every committed evidence file against the capture it came from.
//
// The other tests in this package prove the redactor's behavior on captures
// they built themselves. This one proves the result — that the files in
// tests/lab/evidence, the ones every results note points at and the only ones
// anybody else will ever see, hold no credential and differ from the captures
// in nothing else.
//
// Captures are git-ignored, so a fresh checkout has none and this skips. That
// is not the "a test that measured nothing must fail" rule bending: it audits
// files against an input only the machine that ran the lab has.
func TestCommittedEvidenceMatchesTheCaptures(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Fatal(err)
	}
	names, _ := filepath.Glob(filepath.Join(root, "tests", "lab", "captures", "*.pcap"))
	if len(names) == 0 {
		t.Skip("no capture in tests/lab/captures; captures are git-ignored, so a checkout that has not run the lab has none")
	}
	secrets, err := labcreds.Secrets(filepath.Join(root, "tests", "lab", "port49d-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Key: labcreds.Key, Secrets: secrets}

	var pairs, diff, credBytes, alreadyFill int
	for _, cp := range names {
		base := filepath.Base(cp)
		in, err := os.ReadFile(cp)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.ReadFile(filepath.Join(root, "tests", "lab", "evidence", base))
		if err != nil {
			t.Errorf("%s has no committed evidence file; run `make evidence`", base)
			continue
		}
		pairs++
		if err := Verify(in, out, opt); err != nil {
			t.Errorf("%s: %v", base, err)
			continue
		}
		if len(in) != len(out) {
			t.Errorf("%s: evidence is %d bytes, the capture is %d", base, len(out), len(in))
			continue
		}
		for i := range in {
			if in[i] != out[i] {
				diff++
			}
		}

		// Account for every differing byte. A credential byte that was already
		// the fill character cannot change the obfuscated byte — the pad is the
		// same and so is the plaintext — and the long passwords L8 seeds are
		// built from an alphabet that contains one.
		f, err := Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		d, err := f.Decode(opt.Key, nil)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := d.Fields()
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range fields {
			if !fd.Credential || fd.Len == 0 {
				continue
			}
			p := d.Packets[fd.Packet]
			s := d.Streams[p.Stream]
			copies := 0
			for _, seg := range s.Segments {
				if p.BodyOff+fd.Off >= seg.StreamOff && p.BodyOff+fd.Off < seg.StreamOff+seg.Length {
					copies++
				}
			}
			b := fd.Bytes(p.Body)
			credBytes += fd.Len * copies
			alreadyFill += bytes.Count(b, []byte{Fill}) * copies
		}
	}

	if diff != credBytes-alreadyFill {
		t.Errorf("%d byte(s) differ between the captures and the evidence, but only %d credential byte(s) "+
			"could have changed (%d were already %q). Something outside a credential field was rewritten",
			diff, credBytes-alreadyFill, alreadyFill, string(rune(Fill)))
	}
	t.Logf("audited %d capture/evidence pair(s): %d byte(s) differ, all of them credential bytes "+
		"(%d credential bytes across every record copy, %d already %q)",
		pairs, diff, credBytes, alreadyFill, string(rune(Fill)))
}

// repoRootForTest walks up to the module root.
func repoRootForTest() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", os.ErrNotExist
		}
		d = parent
	}
}
