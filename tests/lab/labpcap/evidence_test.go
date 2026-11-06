package labpcap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blanketfish/port49/tests/lab/labcreds"
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
//
// What it does NOT depend on is the secret list. port49d mints every seeded
// pair now, and writes it to a file in /tmp that the next run truncates and a
// reboot removes — so a verifier built on "search for these exact strings"
// could only ever audit the machine and the hour that produced the evidence,
// and would go quiet everywhere else. So the audit is stated as the invariant
// the redactor enforces instead of as a lookup:
//
//   - every credential-carrying field in the evidence is entirely Fill;
//   - no token-shaped string, and no surviving lab token prefix, appears in any
//     decoded body;
//   - the evidence differs from its capture in credential bytes and nothing
//     else.
//
// None of those expire, so this runs against evidence committed by any run.
// When the seed-token file of THIS run does happen to be present, the exact
// secrets are checked too — Verify's stronger form — but their absence costs
// coverage of nothing above.
func TestCommittedEvidenceMatchesTheCaptures(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Fatal(err)
	}
	names, _ := filepath.Glob(filepath.Join(root, "tests", "lab", "captures", "*.pcap"))
	if len(names) == 0 {
		t.Skip("no capture in tests/lab/captures; captures are git-ignored, so a checkout that has not run the lab has none")
	}
	opt := Options{Key: labcreds.Key}
	// The exact tokens, when this machine still has the run that made them.
	// Neither "the config names no seed-token file" nor "the file is gone" is
	// an error here: both mean only that the perishable half is unavailable,
	// and the shape rules below are not.
	switch seedPath, err := labcreds.SeedTokenFile(filepath.Join(root, "tests", "lab", "port49d-lab.yaml")); {
	case err != nil:
		t.Logf("no seed-token file is configured (%v): auditing by the shape rules alone", err)
	default:
		if _, err := os.Stat(seedPath); err != nil {
			t.Logf("no seed-token file at %s, so the run that produced these captures is gone: auditing by "+
				"the shape rules alone (every credential field all %q, no token-shaped string in any body)",
				seedPath, string(rune(Fill)))
			break
		}
		if opt.Secrets, err = labcreds.Secrets(seedPath); err != nil {
			t.Fatal(err)
		}
		t.Logf("seed-token file %s is present: auditing against %d exact secret(s) as well as the shape rules",
			seedPath, len(opt.Secrets))
	}

	var pairs, diff, credBytes, alreadyFill, shapeTripped int
	for _, cp := range names {
		base := filepath.Base(cp)
		opt := opt
		if k := labcreds.CaptureKey(base); k != "" {
			opt.Key = k // L28's rotation capture, taken under the device's new key
		}
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
		// A patched record's TCP checksum is recomputed when the capture's was
		// correct (a capture taken without offload, such as SR Linux's). Verify
		// above has already checked those bytes are a correct checksum and that
		// no other byte moved, so they are not credential bytes and not counted.
		inFile, err := Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		cksum := map[int]bool{}
		for _, r := range inFile.Records {
			if fl, ok := FlowOf(inFile.Link, inFile.Bytes(r)); ok {
				cksum[r.DataOff+fl.TCPOff+16], cksum[r.DataOff+fl.TCPOff+17] = true, true
			}
		}
		for i := range in {
			if in[i] != out[i] && !cksum[i] {
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

		// A stream's unframed tail is overwritten whole, so it counts the same way.
		for _, tl := range d.Tails() {
			s := d.Streams[tl.Stream]
			for k := 0; k < tl.Len; k++ {
				off := tl.Off + k
				for _, seg := range s.Segments {
					if off >= seg.StreamOff && off < seg.StreamOff+seg.Length {
						credBytes++
						if s.Payload[off] == Fill {
							alreadyFill++
						}
					}
				}
			}
		}

		// The shape rules, read off the EVIDENCE rather than the capture, by the same
		// function CI runs on the committed files alone (AuditEvidence). This is the half
		// that needs no secret list, so it is what audits a file whose run is long gone.
		if _, err := AuditEvidence(out, opt); err != nil {
			t.Errorf("%s: %v", base, err)
			continue
		}
		// The same scan over the CAPTURE, which is the unredacted original and
		// therefore must trip it. A rule nobody has seen fire is not known to
		// fire, and these are the whole audit once a run's secrets are gone, so
		// the captures are their live positive control — counted across the
		// corpus rather than asserted per file, since a single capture need not
		// contain a credential.
		//
		// Only the shape half has a control. The prefix half used to be counted
		// here too, and required to fire, until the captures on the lab host
		// all came from minted runs: a minted token carries no TokenPrefix, so
		// a capture can no longer contain one and a control that demands it
		// can only fail. The prefix is still forbidden in the evidence below,
		// which costs nothing and would catch an old capture redacted wrong.
		// Counting the two separately is also what exposed the earlier bug in
		// the shape rule: every one of the 306 trips of the combined counter
		// was TokenPrefix, so the shape half had never been exercised.
		for _, p := range d.Packets {
			if labcreds.TokenShaped(p.Body) != "" {
				shapeTripped++
			}
		}

	}

	if diff != credBytes-alreadyFill {
		t.Errorf("%d byte(s) differ between the captures and the evidence, but only %d credential byte(s) "+
			"could have changed (%d were already %q). Something outside a credential field was rewritten",
			diff, credBytes-alreadyFill, alreadyFill, string(rune(Fill)))
	}
	if shapeTripped == 0 {
		t.Errorf("labcreds.TokenShaped found nothing in any of the %d unredacted capture(s), so the shape rule "+
			"is not known to be able to find anything at all — and it is the only half of this audit that "+
			"survives a run's secrets being gone. Either the captures carry no token, in which case this "+
			"proves nothing about the evidence beside them, or the rule no longer describes a minted token",
			pairs)
	}
	t.Logf("audited %d capture/evidence pair(s): %d byte(s) differ, all of them credential bytes "+
		"(%d credential bytes across every record copy, %d already %q); over the unredacted captures the "+
		"shape rule trips on %d packet(s), so it is known to be able to fire",
		pairs, diff, credBytes, alreadyFill, string(rune(Fill)), shapeTripped)
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
