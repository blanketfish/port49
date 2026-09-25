package platform

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rhwendt/port49/platforms"
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
	if !m.Keyword(nil, "show") || m.Keyword(nil, "request") || m.Keyword([]string{"show"}, "version") ||
		!m.Keyword([]string{"show", "interfaces"}, "terse") || !m.TakesArgument([]string{"show"}) || m.Len() != 3 {
		t.Fatalf("%s", MarshalKeywords("juniper_junos", m))
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

// The lab's captures (Task 3b, both images) load as they are written, and
// merge to what both prove: 529 keywords. Nothing under `show configuration`
// is one (a hierarchy is not proven a keyword to deny-commands), and neither
// `summary` after `show route` nor `cli` after `show` is proven on both.
func TestTheLabCapturesLoadAndMerge(t *testing.T) {
	var trees []*Keywords
	for _, image := range []string{"juniper_vjunos-router", "juniper_vsrx"} {
		raw, err := os.ReadFile("../../tests/lab/results/L26-keywords-" + image + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		name, k, err := ParseKeywords(raw)
		if err != nil || name != "juniper_junos" || k.Len() == 0 {
			t.Fatalf("%s: %s %d %v", image, name, k.Len(), err)
		}
		trees = append(trees, k)
	}
	m := MergeKeywords(trees...)
	words := 0
	for _, n := range m.nodes {
		words += len(n.Words)
	}
	if words != 529 {
		t.Errorf("the merged tree proves %d keywords", words)
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
