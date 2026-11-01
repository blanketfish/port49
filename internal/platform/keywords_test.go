package platform

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/blanketfish/port49/platforms"
)

const keywordFixture = `platform: juniper_junos
nodes:
  "": {words: [show], argument: false}
  "show": {words: [interfaces, version], argument: false}
  "show interfaces": {words: [terse], argument: true}
`

// A keyword tree answers only what the capture reached: a word is a keyword
// where its path's node lists it, and an argument may be typed wherever the
// node says so or no node was captured (spec §8; §15 L26).
func TestKeywords(t *testing.T) {
	name, k, err := ParseKeywords([]byte(keywordFixture))
	if err != nil || name != "juniper_junos" || k.Len() != 3 {
		t.Fatalf("%s %v %v", name, k, err)
	}
	for _, c := range []struct {
		path []string
		word string
		want bool
	}{
		{nil, "show", true},
		{nil, "SHOW", true},
		{[]string{"show"}, "interfaces", true},
		{[]string{"show", "interfaces"}, "terse", true},
		{[]string{"show", "interfaces"}, "fxp0", false},
		{[]string{"show", "version"}, "brief", false}, // not captured: proves nothing
		{nil, "request", false},
	} {
		if got := k.Keyword(c.path, c.word); got != c.want {
			t.Errorf("Keyword(%q, %q) = %v", c.path, c.word, got)
		}
	}
	if k.TakesArgument([]string{"show"}) || !k.TakesArgument([]string{"show", "interfaces"}) ||
		!k.TakesArgument([]string{"show", "version"}) {
		t.Error("TakesArgument")
	}
	var none *Keywords
	if none.Keyword(nil, "show") || !none.TakesArgument(nil) {
		t.Error("a nil tree proves nothing")
	}
}

// A file that could let the projection prove what the lab did not measure
// is refused: an orphan node, an unsorted or upper-case word, an unknown key,
// and one past the bounds.
func TestParseKeywordsRefuses(t *testing.T) {
	for _, bad := range []string{
		"platform: juniper_junos\nnodes:\n  \"\": {words: [show]}\n  \"show interfaces\": {words: []}\n",
		"platform: juniper_junos\nnodes:\n  \"\": {words: [version, show]}\n",
		"platform: juniper_junos\nnodes:\n  \"\": {words: [Show]}\n",
		"platform: juniper_junos\nnodes:\n  \"\": {words: [show], keyword: true}\n",
		"platform: juniper_junos\nnodes:\n  \"show\": {words: []}\n",
		"nodes:\n  \"\": {words: []}\n",
		"platform: juniper_junos\nnodes:\n  \"\": {words: [x]}\n" + strings.Repeat("#", MaxKeywordBytes),
		// An argument is proven absent only by the capture saying so: a
		// node that omits the key, or is null, is not read as false.
		"platform: juniper_junos\nnodes:\n  \"\": {words: [show], argument: false}\n  \"show\": {words: []}\n",
		"platform: juniper_junos\nnodes:\n  \"\": {words: [show], argument: false}\n  \"show\": ~\n",
		"platform: juniper_junos\nnodes:\n  \"\": {words: [show], argument: false}\n  \"show\": {words: [], argument: ~}\n",
		// A second document is not read past.
		"platform: juniper_junos\nnodes:\n  \"\": {words: [], argument: false}\n---\nplatform: other\n",
	} {
		if _, _, err := ParseKeywords([]byte(bad)); err == nil {
			t.Errorf("parsed: %.80q", bad)
		}
	}
	// MaxKeywordNodes children of the root and the root: one node too many.
	var words, nodes []string
	for i := range MaxKeywordNodes {
		w := fmt.Sprintf("w%05d", i)
		words = append(words, w)
		nodes = append(nodes, fmt.Sprintf("  %q: {words: []}\n", w))
	}
	raw := "platform: p\nnodes:\n  \"\": {words: [" + strings.Join(words, ", ") + "]}\n" + strings.Join(nodes, "")
	if _, _, err := ParseKeywords([]byte(raw)); err == nil || !strings.Contains(err.Error(), "past the bound") {
		t.Errorf("past the node bound: %v", err)
	}
}

// A set's tree is read from keywords/<version>/<platform>.yaml, absent is
// nil, and a file for another platform is a build defect.
func TestKeywordsFor(t *testing.T) {
	fsys := fstest.MapFS{"keywords/9.9.9/juniper_junos.yaml": {Data: []byte(keywordFixture)},
		"keywords/9.9.9/other.yaml": {Data: []byte(keywordFixture)}}
	if k := keywordsIn(fsys, "9.9.9", "juniper_junos"); k.Len() != 3 {
		t.Fatal("not read")
	}
	if keywordsIn(fsys, "9.9.8", "juniper_junos") != nil || KeywordsFor("1.0.0", "juniper_junos") != nil {
		t.Fatal("a set with no tree has none")
	}
	defer func() {
		if recover() == nil {
			t.Error("a file naming another platform loaded")
		}
	}()
	keywordsIn(fsys, "9.9.9", "other")
}

// Two images' captures merge to what both prove: a keyword on one image only
// is not a keyword, an argument on either is one, and a node under a word the
// merge dropped goes with it. The merge writes what ParseKeywords reads.
func TestMergeKeywords(t *testing.T) {
	_, a, _ := ParseKeywords([]byte(keywordFixture))
	_, b, err := ParseKeywords([]byte(`platform: juniper_junos
nodes:
  "": {words: [request, show], argument: false}
  "show": {words: [interfaces], argument: true}
  "show interfaces": {words: [terse], argument: false}
  "request": {words: [], argument: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	m := MergeKeywords(a, b)
	// The argument is either image's, whichever holds it: `show` takes one
	// on b only, `show interfaces` on a only.
	if !m.Keyword(nil, "show") || m.Keyword(nil, "request") || m.Keyword([]string{"show"}, "version") ||
		!m.Keyword([]string{"show", "interfaces"}, "terse") || !m.TakesArgument([]string{"show"}) ||
		!m.TakesArgument([]string{"show", "interfaces"}) || m.TakesArgument(nil) || m.Len() != 3 {
		t.Fatalf("%s", MarshalKeywords("juniper_junos", m))
	}
	// A merge that proves nothing is nil, and so proves nothing: an image
	// missing, or no root both hold.
	_, rootless, _ := ParseKeywords([]byte("platform: juniper_junos\nnodes:\n  \"\": {words: [], argument: false}\n"))
	if MergeKeywords() != nil || MergeKeywords(a, nil) != nil || MergeKeywords(nil, a) != nil {
		t.Error("a merge with no image, or a missing one, proves something")
	}
	if MergeKeywords(a, rootless).Keyword(nil, "show") {
		t.Error("a word one image lacks is proven")
	}
	name, back, err := ParseKeywords(MarshalKeywords("juniper_junos", m))
	if err != nil || name != "juniper_junos" || back.Len() != 3 || !back.TakesArgument([]string{"show"}) {
		t.Fatalf("round trip: %v", err)
	}
}

// Every tree the binary ships loads, names its own platform and sits within
// the bounds; a set's tree is frozen with its set (Task 20).
func TestShippedKeywordTreesLoad(t *testing.T) {
	err := fs.WalkDir(platforms.Keywords, "keywords", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".yaml" {
			return err
		}
		parts := strings.Split(p, "/")
		if len(parts) != 3 {
			t.Errorf("%s: not keywords/<version>/<platform>.yaml", p)
			return nil
		}
		if k := KeywordsFor(parts[1], strings.TrimSuffix(parts[2], ".yaml")); k.Len() == 0 {
			t.Errorf("%s: no nodes", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The lab's captures (Task 3b, both images, and the first vSRX run the rerun
// replaced) load as they are written, and merge to what every run proves:
// 528 keywords. Nothing under `show configuration` is one (a hierarchy is
// not proven a keyword to deny-commands), and neither `summary` after `show
// route` nor `cli` after `show` is proven on both. `show rsvp interface`,
// which the first vSRX run proved and the rerun did not, is not one, and
// `show rsvp` takes an argument; `show interfaces terse extensive`, which
// only the rerun proved on vSRX, is not one either.
func TestTheLabCapturesLoadAndMerge(t *testing.T) {
	var trees []*Keywords
	for image, runs := range labRuns(t) {
		for i, raw := range runs {
			name, k, err := ParseKeywords(raw)
			if err != nil || name != "juniper_junos" || k.Len() == 0 {
				t.Fatalf("%s run %d: %s %d %v", image, i, name, k.Len(), err)
			}
			trees = append(trees, k)
		}
	}
	m := MergeKeywords(trees...)
	words := 0
	for _, n := range m.nodes {
		words += len(n.Words)
	}
	if words != 528 {
		t.Errorf("the merged tree proves %d keywords", words)
	}
	if m.Keyword([]string{"show", "rsvp"}, "interface") || !m.TakesArgument([]string{"show", "rsvp"}) ||
		m.Keyword([]string{"show", "interfaces", "terse"}, "extensive") ||
		m.Keyword([]string{"show", "system", "processes"}, "detail") {
		t.Error("a word one vSRX run does not prove is a keyword")
	}
	if !m.Keyword(nil, "show") || !m.Keyword([]string{"show"}, "version") ||
		!m.Keyword([]string{"show"}, "configuration") || !m.Keyword([]string{"show", "interfaces"}, "terse") {
		t.Error("a keyword both images prove is not one")
	}
	if m.Keyword([]string{"show", "configuration"}, "system") || !m.TakesArgument([]string{"show", "configuration"}) ||
		m.Keyword([]string{"show", "route"}, "summary") || m.Keyword([]string{"show"}, "cli") {
		t.Error("an unproven word is a keyword")
	}
	name, back, err := ParseKeywords(MarshalKeywords("juniper_junos", m))
	if err != nil || name != "juniper_junos" || back.Len() != m.Len() {
		t.Fatalf("round trip: %d %v", back.Len(), err)
	}
}

// An overlay (tests/lab/results/L26b-keywords-<image>.yaml) is laid over the
// capture it names by sha256 and no other: its words join the capture's at
// its nodes, its argument replaces the capture's there, and a node the
// capture lacks is added (spec §15 L26; decision 27).
func TestOverlayKeywords(t *testing.T) {
	sum := sha256.Sum256([]byte(keywordFixture))
	overlay := fmt.Sprintf("# computed against keywords.yaml sha256 %x\n", sum) + `platform: juniper_junos
nodes:
  "": {words: [set, show], argument: false}
  "set": {words: [cli], argument: true}
  "show": {words: [cli], argument: true}
`
	k, err := OverlayKeywords([]byte(keywordFixture), []byte(overlay))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Keyword(nil, "set") || !k.Keyword([]string{"set"}, "cli") || !k.Keyword([]string{"show"}, "cli") ||
		!k.Keyword([]string{"show"}, "version") || !k.Keyword([]string{"show", "interfaces"}, "terse") ||
		!k.TakesArgument([]string{"show"}) || !k.TakesArgument([]string{"set"}) || k.Len() != 4 {
		t.Fatalf("%s", MarshalKeywords("juniper_junos", k))
	}
	// A capture that changed since the overlay was computed is refused.
	_, err = OverlayKeywords([]byte(strings.Replace(keywordFixture, `"show": {words: [interfaces, version], argument: false}`,
		`"show": {words: [interfaces, version], argument: true}`, 1)), []byte(overlay))
	if err == nil {
		t.Fatal("an overlay laid over a tree it was not computed against")
	}
	for _, bad := range []string{
		strings.SplitN(overlay, "\n", 2)[1], // no header
		strings.Replace(overlay, fmt.Sprintf("%x", sum), strings.Repeat("0", 64), 1),
		strings.Replace(overlay, "platform: juniper_junos", "platform: other", 1),
	} {
		if _, err := OverlayKeywords([]byte(keywordFixture), []byte(bad)); err == nil {
			t.Errorf("laid: %.120q", bad)
		}
	}
	// The overlay's argument wins either way: here it proves `show` takes
	// none where the capture said it may.
	off := strings.Replace(overlay, `"show": {words: [cli], argument: true}`, `"show": {words: [cli], argument: false}`, 1)
	base := strings.Replace(keywordFixture, `"show": {words: [interfaces, version], argument: false}`,
		`"show": {words: [interfaces, version], argument: true}`, 1)
	sum = sha256.Sum256([]byte(base))
	off = fmt.Sprintf("# computed against keywords.yaml sha256 %x\n", sum) + strings.SplitN(off, "\n", 2)[1]
	if k, err := OverlayKeywords([]byte(base), []byte(off)); err != nil || k.TakesArgument([]string{"show"}) {
		t.Fatalf("the overlay's argument: %v", err)
	}
}

// An overlay pins an image's latest run and is laid over each earlier run
// too, at its nodes only: its words join and its argument replaces there,
// every other node stays the run's own for the merge to intersect, and an
// earlier run that offers other words at an overlay node is refused.
func TestOverlayRuns(t *testing.T) {
	sum := sha256.Sum256([]byte(keywordFixture))
	overlay := fmt.Sprintf("# computed against keywords.yaml sha256 %x\n", sum) + `platform: juniper_junos
nodes:
  "": {words: [show], argument: false}
  "show": {words: [cli], argument: false}
`
	earlier := `# an earlier run
platform: juniper_junos
nodes:
  "": {words: [show], argument: true}
  "show": {words: [interfaces, version], argument: true}
  "show interfaces": {words: [extensive, terse], argument: false}
`
	ks, err := OverlayRuns([]byte(overlay), []byte(keywordFixture), []byte(earlier))
	if err != nil || len(ks) != 2 {
		t.Fatalf("%d %v", len(ks), err)
	}
	e := ks[1]
	if !e.Keyword([]string{"show"}, "cli") || e.TakesArgument(nil) || e.TakesArgument([]string{"show"}) ||
		!e.Keyword([]string{"show", "interfaces"}, "extensive") || e.TakesArgument([]string{"show", "interfaces"}) {
		t.Fatalf("%s", MarshalKeywords("juniper_junos", e))
	}
	m := MergeKeywords(ks...)
	if m.Keyword([]string{"show", "interfaces"}, "extensive") || !m.TakesArgument([]string{"show", "interfaces"}) ||
		!m.Keyword([]string{"show"}, "cli") || m.TakesArgument([]string{"show"}) {
		t.Fatalf("%s", MarshalKeywords("juniper_junos", m))
	}
	for _, bad := range []string{
		strings.Replace(earlier, "[interfaces, version]", "[interfaces]", 1), // other words at an overlay node
		strings.Replace(earlier, "platform: juniper_junos", "platform: other", 1),
	} {
		if _, err := OverlayRuns([]byte(overlay), []byte(keywordFixture), []byte(bad)); err == nil {
			t.Errorf("laid: %.120q", bad)
		}
	}
	// The overlay is pinned to the latest run: given an earlier one first, it
	// is refused.
	if _, err := OverlayRuns([]byte(overlay), []byte(earlier), []byte(keywordFixture)); err == nil {
		t.Error("an overlay laid with an earlier run as the one it pins")
	}
}

// labRuns is every L26 capture the lab committed, by image, the latest run
// first: tests/lab/results/L26-keywords-<image>.yaml and each earlier
// L26-keywords-<image>.run<N>.yaml, as tests/lab/cmd/junos-keywords reads
// them. A run committed later is in it without a change here; a file named
// as a capture otherwise, or an image with no latest run, fails the test.
func labRuns(t *testing.T) map[string][][]byte {
	t.Helper()
	files, err := filepath.Glob("../../tests/lab/results/L26-keywords-*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no L26 captures: %v", err)
	}
	named := regexp.MustCompile(`^L26-keywords-([^.]+)(\.run[0-9]+)?\.yaml$`)
	runs := map[string][][]byte{}
	for _, f := range files {
		m := named.FindStringSubmatch(filepath.Base(f))
		if m == nil {
			t.Fatalf("%s: not an L26-keywords-<image>[.run<N>].yaml capture", f)
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m[2] == "" {
			runs[m[1]] = append([][]byte{raw}, runs[m[1]]...)
		} else {
			runs[m[1]] = append(runs[m[1]], raw)
		}
	}
	for image, rs := range runs {
		if _, err := os.Stat("../../tests/lab/results/L26-keywords-" + image + ".yaml"); err != nil {
			t.Fatalf("%s: %d earlier runs and no latest: %v", image, len(rs), err)
		}
	}
	return runs
}

// The shipped Junos tree is exactly what the lab's captures and overlays
// merge to (tests/lab/cmd/junos-keywords), each overlay laid over every run
// of its image: L26b's words proven on both images are keywords, `save`
// (proven on vJunos only) and every `show configuration` hierarchy are not,
// no argument follows `show`, and `show rsvp interface` (proven by one vSRX
// run of two) is not a keyword.
func TestTheShippedJunosTreeIsTheLabs(t *testing.T) {
	var trees []*Keywords
	for image, raws := range labRuns(t) {
		overlay, err := os.ReadFile("../../tests/lab/results/L26b-keywords-" + image + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		ks, err := OverlayRuns(overlay, raws...)
		if err != nil {
			t.Fatalf("%s: %v", image, err)
		}
		trees = append(trees, ks...)
	}
	want := MarshalKeywords("juniper_junos", MergeKeywords(trees...))
	got, err := fs.ReadFile(platforms.Keywords, "keywords/1.1.0/juniper_junos.yaml")
	if err != nil || string(got) != string(want) {
		t.Fatalf("platforms/keywords/1.1.0/juniper_junos.yaml is not the merge (%v): rerun tests/lab/cmd/junos-keywords", err)
	}
	k := KeywordsFor("1.1.0", "juniper_junos")
	for _, w := range []string{"cli", "host", "ingress-replication", "policy", "task", "version", "interfaces"} {
		if !k.Keyword([]string{"show"}, w) {
			t.Errorf("show %s is not a keyword", w)
		}
	}
	if !k.Keyword(nil, "exit") || !k.Keyword([]string{"set"}, "cli") || k.Keyword(nil, "save") ||
		k.Keyword([]string{"show", "configuration"}, "system") || !k.TakesArgument([]string{"show", "configuration"}) ||
		k.TakesArgument([]string{"show"}) || k.TakesArgument(nil) ||
		k.Keyword([]string{"show", "rsvp"}, "interface") || !k.TakesArgument([]string{"show", "rsvp"}) {
		t.Errorf("%s", got)
	}
}

// releasedKeywords is each released set's keyword tree by the sha256 of its
// file: a released set's tree is never edited, and a new capture ships in a
// new set. 1.1.0's is the merge of every L26 run on both images with the L26b
// overlays (tests/lab/results/L26*-keywords-*.yaml; spec §15, L26), frozen
// by plan 5b Task 20.
var releasedKeywords = map[string]string{
	"1.1.0/juniper_junos": "aa1440897d46146ee4f6ae0b5be8b0ec89643b95f0bd0992b5062c142a4b0168",
	"1.2.0/juniper_junos": "2017ca9e10d5e3e7c53fb78cd65a5480aa91387212cef7a6924aa87110912688",
	"1.3.0/juniper_junos": "2017ca9e10d5e3e7c53fb78cd65a5480aa91387212cef7a6924aa87110912688",
}

// Set 1.3.0's Junos tree is 1.2.0's, byte for byte (decision 48 changes no
// keyword).
func TestTheSet130JunosTreeIsSet120s(t *testing.T) {
	was, err1 := fs.ReadFile(platforms.Keywords, "keywords/1.2.0/juniper_junos.yaml")
	is, err2 := fs.ReadFile(platforms.Keywords, "keywords/1.3.0/juniper_junos.yaml")
	if err1 != nil || err2 != nil || string(is) != string(was) {
		t.Fatal("platforms/keywords/1.3.0/juniper_junos.yaml is not 1.2.0's", err1, err2)
	}
}

func TestReleasedKeywordTreesAreFrozen(t *testing.T) {
	// A tree added to a released set later is an edit of that set too.
	err := fs.WalkDir(platforms.Keywords, "keywords", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		file := strings.TrimSuffix(strings.TrimPrefix(p, "keywords/"), ".yaml")
		if _, ok := released[strings.Split(file, "/")[0]]; ok && releasedKeywords[file] == "" {
			t.Errorf("%s: a tree in a released set that was not released with it", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range releasedKeywords {
		raw, err := fs.ReadFile(platforms.Keywords, "keywords/"+file+".yaml")
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s: sha256 %s, released as %s: a released tree is never edited; ship a new set", file, got, want)
		}
	}
}

// Set 1.2.0's Junos tree is 1.1.0's and `save` at the root, which L58 proved
// on both images (tests/lab/results/L58-juniper_*.md; decision 44 ruling 10):
// nothing else moves.
func TestTheSet120JunosTreeIsSet110AndSave(t *testing.T) {
	was, err1 := fs.ReadFile(platforms.Keywords, "keywords/1.1.0/juniper_junos.yaml")
	is, err2 := fs.ReadFile(platforms.Keywords, "keywords/1.2.0/juniper_junos.yaml")
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	want := strings.Replace(string(was), `"restart", "scp"`, `"restart", "save", "scp"`, 1)
	if want == string(was) || string(is) != want {
		t.Fatal("platforms/keywords/1.2.0/juniper_junos.yaml is not 1.1.0's with `save` at the root")
	}
	if !KeywordsFor("1.2.0", "juniper_junos").Keyword(nil, "save") || KeywordsFor("1.1.0", "juniper_junos").Keyword(nil, "save") {
		t.Error("save is a keyword in 1.2.0's tree only")
	}
}
