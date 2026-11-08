package docgen

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// labIntro tells a reader who has never seen the lab register what an L-number is.
const labIntro = `Every page of this site that says how a device behaves rests on a claim that port49's lab can test.
Each claim has an ID, an **L-number** such as the ones linked throughout the site, and this page lists them
all. A claim is one question about a device or a protocol, for example whether a switch shows a message
port49 sends with a denial, and the lab answers it on real device images.

- **Open** means the lab has not finished measuring the claim. The documentation never asserts an open
  claim as fact: where a page mentions one, it says the behavior is unmeasured, or it cites the results
  note for the platform it measured. A row can be open while one platform is measured and others are not.
- **Closed** means a lab test passed and a results note records the platform, the image version, what was
  observed and where the capture is. The note is the evidence.

A results note wins over any page: when a note and a page disagree, the page is wrong and is corrected to
match the note. The register itself is section 15 of [the policy-engine spec](` + specLabURL + `), and the
rows below are shortened from it. Follow the spec link for a row's full wording.
`

var (
	measuredOn = regexp.MustCompile(`measured ([0-9]{4}-[0-9]{2}-[0-9]{2})`)
	// claimLimit is the longest a shortened claim runs before it is cut at a word.
	claimLimit = 260
)

// claimRewordings say a few rows in site words. The spec's first sentence for each names the lab's own
// machine, when a person is free, or a command the product no longer has, none of which belongs on a public
// page. From is how the spec's shortened claim starts, so a row the spec has since changed is not
// reworded from a stale text.
var claimRewordings = map[string]struct{ From, Text string }{
	"L53": {"The SSH host key each platform presents", "The SSH host key each platform presents to the device scan, and what the scan does to the device."},
	"L60": {"A YubiKey's PIV applet", "A YubiKey's PIV applet through `libykcs11` under purego, on the lab's dedicated machine."},
	"L62": {"A real TPM 2.0", "A real TPM 2.0 through `/dev/tpmrm0` on the lab's dedicated machine, for a non-root user in `tss`: whether `issued_key_store: tpm` creates a key under the ECC SRK, signs a TLS 1.3 handshake and a refresh, survives an agent restart and a reboot, and is refused (cannot load) on another machine given the same key file."},
	"L86": {"An admin call's touch", "An admin call's touch on a real YubiKey, on the lab's dedicated machine."},
	"L91": {"`port49 hwkey status`", "`port49 hwkey status` and `setup` on a real YubiKey, on the lab's dedicated machine."},
}

// LabRegisterText is the lab register page: an introduction, then one section per register row, in
// numeric order, anchored "#l15". resultsDir is tests/lab/results; a row lists every note whose name
// leads with its ID. The register must hold each ID the page links.
func LabRegisterText(reg map[string]LabRow, resultsDir string) (string, error) {
	notes, err := notesByID(resultsDir)
	if err != nil {
		return "", err
	}
	ids := make([]string, 0, len(reg))
	for id := range reg {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		ni, si := idKey(ids[i])
		nj, sj := idKey(ids[j])
		if ni != nj {
			return ni < nj
		}
		return si < sj
	})
	var b strings.Builder
	fmt.Fprintf(&b, "---\ntitle: \"Lab register\"\ndescription: %s\n---\n\n%s\n\n# Lab register\n\n%s",
		jsonString("What each L-number on this site means, whether the lab has measured it, and the results notes that say so."),
		Header, labIntro)
	b.WriteString("\n## The register\n")
	for _, id := range ids {
		row := reg[id]
		status := "**Open.**"
		if !row.Open {
			status = "**Closed.**"
			if m := measuredOn.FindStringSubmatch(row.Status); m != nil {
				status = "**Closed**, measured " + m[1] + "."
			}
		}
		claim := shortClaim(row.Claim)
		if o, ok := claimRewordings[id]; ok && strings.HasPrefix(claim, o.From) {
			claim = o.Text
		}
		fmt.Fprintf(&b, "\n### %s {#%s}\n\n%s %s\n\n", id, strings.ToLower(id), status, claim)
		if ns := notes[id]; len(ns) > 0 {
			links := make([]string, len(ns))
			for i, n := range ns {
				links[i] = fmt.Sprintf("[%s](%s%s)", n, resultsURL, n)
			}
			fmt.Fprintf(&b, "Results notes: %s\n", strings.Join(links, ", "))
		} else {
			b.WriteString("No results note yet.\n")
		}
	}
	return LinkLabIDs(b.String(), reg, "")
}

// notesByID maps a lab ID to the results notes that lead with it, in name order.
func notesByID(dir string) (map[string][]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		ids, _ := NoteParts(e.Name())
		for _, id := range ids {
			out[id] = append(out[id], e.Name())
		}
	}
	return out, nil
}

// shortClaim is the first sentence of a claim cell without its bold marks, cut at a word and ended with an
// ellipsis when the sentence runs past claimLimit. A full stop in a code span, or after "e.g." or "i.e.",
// does not end the sentence.
func shortClaim(cell string) string {
	s := strings.Join(strings.Fields(strings.ReplaceAll(cell, "**", "")), " ")
	ticks := 0
	cut := len(s)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '`':
			ticks++
		case ticks%2 == 0 && (c == '.' || c == '?' || c == '!') && (i+1 == len(s) || s[i+1] == ' '):
			head := s[:i]
			if strings.HasSuffix(head, "e.g") || strings.HasSuffix(head, "i.e") || strings.HasSuffix(head, " vs") {
				continue
			}
			cut = i + 1
		}
		if cut != len(s) {
			break
		}
	}
	s = s[:cut]
	if len([]rune(s)) <= claimLimit {
		return s
	}
	ticks = 0
	last := -1
	for i, r := range []rune(s) {
		if i >= claimLimit {
			break
		}
		switch r {
		case '`':
			ticks++
		case ' ':
			if ticks%2 == 0 {
				last = len(string([]rune(s)[:i]))
			}
		}
	}
	if last < 0 {
		return s
	}
	return strings.TrimRight(s[:last], " ,;:—-") + " …"
}
