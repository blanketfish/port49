package ci

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/blanketfish/port49/internal/docgen"
)

// "L15 means nothing to the uninitiated" (Ryan, 2026-11-08): every lab ID a reader can see on the site is a
// link to its section of the lab register page, so a reader who meets one can learn what it is. The rewriter
// (go run ./internal/docgen/cmd/linklabids) links the hand-written pages, generators link their own, and
// these tests keep it so.

const labIDFixtures = "testdata/labids"

func TestNoSitePageHoldsABareLabID(t *testing.T) {
	found, err := docgen.CheckLabIDs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Error(f)
	}
}

func TestTheLabIDCheckFailsItsFailFixtures(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(labIDFixtures, "fail", "*"))
	if err != nil || len(dirs) < 4 {
		t.Fatalf("fail fixtures: %d %v", len(dirs), err)
	}
	for _, dir := range dirs {
		want, _, _ := strings.Cut(filepath.Base(dir), "--")
		found, err := docgen.CheckLabIDs(dir)
		if err != nil {
			t.Errorf("%s: %v", dir, err)
			continue
		}
		if len(found) == 0 {
			t.Errorf("%s: no finding, want %s", dir, want)
		}
		for _, f := range found {
			if f.Rule != want {
				t.Errorf("%s: %s, want only %s", dir, f, want)
			}
		}
	}
}

func TestTheLabIDCheckPassesItsPassFixtures(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(labIDFixtures, "pass", "*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("pass fixtures: %d %v", len(dirs), err)
	}
	for _, dir := range dirs {
		found, err := docgen.CheckLabIDs(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range found {
			t.Errorf("%s: %s", dir, f)
		}
	}
}

// bareBuiltLabIDs counts the lab IDs in a built page's article that a reader sees as plain text: not in a
// link, a code span or a block, and not a heading that is the ID itself (the register page's anchors).
func bareBuiltLabIDs(doc []byte) (int, error) {
	root, err := html.Parse(bytes.NewReader(doc))
	if err != nil {
		return 0, err
	}
	var article *html.Node
	var find func(*html.Node)
	find = func(n *html.Node) {
		if article == nil && n.Type == html.ElementNode && n.Data == "article" {
			article = n
		}
		for c := n.FirstChild; c != nil && article == nil; c = c.NextSibling {
			find(c)
		}
	}
	find(root)
	if article == nil {
		return 0, nil
	}
	n := 0
	var walk func(*html.Node, bool)
	walk = func(node *html.Node, skip bool) {
		if node.Type == html.TextNode && !skip {
			// the source scanner's rule, so a note's file name in prose is not a mention in either
			n += len(docgen.BareLabIDs(node.Data))
		}
		if node.Type == html.ElementNode {
			switch node.Data {
			case "a", "code", "pre", "script", "style", "kbd":
				skip = true
			case "h1", "h2", "h3", "h4", "h5", "h6":
				// the heading that is only an ID is the anchor itself
				if id := attr(node, "id"); id != "" && strings.EqualFold(id, strings.TrimSpace(strings.TrimSuffix(textOf(node), "¶"))) {
					skip = true
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c, skip)
		}
	}
	walk(article, false)
	return n, nil
}

func TestTheBuiltLabIDCheckReadsItsFixtures(t *testing.T) {
	for name, want := range map[string]int{"bare.html": 1, "linked.html": 0} {
		b, err := os.ReadFile(filepath.Join(labIDFixtures, "built", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := bareBuiltLabIDs(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: %d bare IDs, want %d", name, got, want)
		}
	}
}

// The built site is what a reader sees: includes pasted in, admonition titles and table cells included.
func TestTheBuiltSiteHoldsNoBareLabID(t *testing.T) {
	dir := builtSiteDir(t)
	pages := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		pages++
		n, err := bareBuiltLabIDs(b)
		if err != nil {
			return err
		}
		if n > 0 {
			rel, _ := filepath.Rel(dir, p)
			t.Errorf("%s: %d lab IDs outside a link or code", rel, n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if pages == 0 {
		t.Fatalf("no pages under %s", dir)
	}
}
