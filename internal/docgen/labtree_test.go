package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readTree(t *testing.T, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const treeReadme = "# Title\n\nSee L4 before the include.\n\n<!-- --8<-- [start:part] -->\nThe part says L15 and `L4`.\n<!-- --8<-- [end:part] -->\n\nAfter: L5.\n"

func treeFixture(t *testing.T) string {
	return writeTree(t, map[string]string{
		"docs/site/reference/a.md": "---\ntitle: A\n---\n\nSee L4.\n\n--8<-- \"deploy/x/README.md:part\"\n\n--8<-- \"deploy/x/README.md:7:\"\n",
		"docs/site/admin/b.md":     "# B\n\nL5 and `L4`.\n",
		"docs/site/gen.md":         Header + "\n\nGenerated L4 stays for its generator.\n",
		"deploy/x/README.md":       treeReadme,
	})
}

func TestTheRewriterLinksPagesRelativelyAndIncludedRegionsAbsolutely(t *testing.T) {
	root := treeFixture(t)
	changed, err := LinkLabIDsInTree(root, refsReg)
	if err != nil {
		t.Fatal(err)
	}
	if got := readTree(t, root, "docs/site/reference/a.md"); !strings.Contains(got, "See [L4](lab-register.md#l4).") {
		t.Errorf("a page in reference/ is not linked beside the register:\n%s", got)
	}
	if got := readTree(t, root, "docs/site/admin/b.md"); !strings.Contains(got, "[L5](../reference/lab-register.md#l5) and `L4`") {
		t.Errorf("a page in admin/ is not linked up one level:\n%s", got)
	}
	readme := readTree(t, root, "deploy/x/README.md")
	abs := "[L15](" + LabRegisterSiteURL + "#l15)"
	if !strings.Contains(readme, "The part says "+abs+" and `L4`.") {
		t.Errorf("an included section is not linked by the site URL:\n%s", readme)
	}
	if !strings.Contains(readme, "After: ["+"L5]("+LabRegisterSiteURL+"#l5)") {
		t.Errorf("a line an open-ended include reaches is not linked:\n%s", readme)
	}
	if !strings.Contains(readme, "See L4 before the include.") {
		t.Errorf("a line no include reaches was rewritten:\n%s", readme)
	}
	if got := readTree(t, root, "docs/site/gen.md"); strings.Contains(got, "[L4]") {
		t.Errorf("a generated page was rewritten:\n%s", got)
	}
	if len(changed) != 3 {
		t.Errorf("changed = %v, want the two pages and the README", changed)
	}
}

// A section is the lines between its markers, a "file:7:" include runs from line 7 to the end, and
// regions that touch are one.
func TestIncludedRegionsFollowTheSnippetSyntax(t *testing.T) {
	got, err := IncludedRegions(treeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []Region{{"deploy/x/README.md", 6, 9}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("regions = %v, want %v", got, want)
	}
	root := writeTree(t, map[string]string{
		"docs/site/p.md": "--8<-- \"a.md:2:3\"\n--8<-- \"a.md:5\"\n--8<-- \"a.md\"\n--8<-- \"docs/site/_snippets/s.md\"\n" +
			"```text\n--8<-- \"code.tpl\"\n```\n",
		"a.md":     "1\n2\n3\n4\n5\n6\n",
		"code.tpl": "L4 in a listing\n", // pasted into a fence: it renders as code, not prose
	})
	got, err = IncludedRegions(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (Region{"a.md", 1, 6}) {
		t.Errorf("regions = %v, want the whole of a.md once", got)
	}
	root = writeTree(t, map[string]string{"docs/site/p.md": "--8<-- \"a.md:2:3\"\n--8<-- \"a.md:5:\"\n", "a.md": "1\n2\n3\n4\n5\n6\n"})
	got, _ = IncludedRegions(root)
	if len(got) != 2 || got[0] != (Region{"a.md", 2, 3}) || got[1] != (Region{"a.md", 5, 6}) {
		t.Errorf("regions = %v, want 2-3 and 5-6", got)
	}
}

func TestTheRewriterIsIdempotent(t *testing.T) {
	root := treeFixture(t)
	if _, err := LinkLabIDsInTree(root, refsReg); err != nil {
		t.Fatal(err)
	}
	before := readTree(t, root, "deploy/x/README.md") + readTree(t, root, "docs/site/reference/a.md")
	changed, err := LinkLabIDsInTree(root, refsReg)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Errorf("a second run changed %v", changed)
	}
	if after := readTree(t, root, "deploy/x/README.md") + readTree(t, root, "docs/site/reference/a.md"); after != before {
		t.Error("a second run rewrote text")
	}
}

func TestTheRewriterRefusesAnIDTheRegisterLacks(t *testing.T) {
	root := writeTree(t, map[string]string{"docs/site/p.md": "See L99.\n"})
	if _, err := LinkLabIDsInTree(root, refsReg); err == nil || !strings.Contains(err.Error(), "L99") {
		t.Fatalf("err = %v, want L99 named", err)
	}
	if got := readTree(t, root, "docs/site/p.md"); got != "See L99.\n" {
		t.Error("a page with an unknown ID was written anyway")
	}
}

func TestTheCheckFindsABareIDAndARelativeLinkInAnIncludedFile(t *testing.T) {
	root := treeFixture(t)
	got, err := CheckLabIDs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"docs/site/reference/a.md:5:bare_lab_id": true, "docs/site/admin/b.md:3:bare_lab_id": true,
		"deploy/x/README.md:6:bare_lab_id": true, "deploy/x/README.md:9:bare_lab_id": true,
		"docs/site/gen.md:3:bare_lab_id": true,
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.String()] = true
		if !want[f.String()] {
			t.Errorf("unexpected finding %s", f)
		}
	}
	for w := range want {
		if !seen[w] {
			t.Errorf("missing finding %s", w)
		}
	}
	// the line before the include is not a site page's text
	for _, f := range got {
		if f.File == "deploy/x/README.md" && f.Line == 3 {
			t.Errorf("a line no page includes was checked: %s", f)
		}
	}

	root = writeTree(t, map[string]string{
		"docs/site/p.md":     "--8<-- \"deploy/x/README.md:1:\"\n",
		"deploy/x/README.md": "See [L4](../../docs/site/reference/lab-register.md#l4).\n",
	})
	got, err = CheckLabIDs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Rule != "relative_register_link_in_included_file" {
		t.Errorf("findings = %v, want one relative_register_link_in_included_file", got)
	}
}

func TestACleanTreePassesTheCheck(t *testing.T) {
	root := treeFixture(t)
	if _, err := LinkLabIDsInTree(root, refsReg); err != nil {
		t.Fatal(err)
	}
	// the generated page is not the rewriter's; its generator links, so give it the link
	gen := Header + "\n\nGenerated [L4](lab-register.md#l4).\n"
	if err := os.WriteFile(filepath.Join(root, "docs/site/gen.md"), []byte(gen), 0o644); err != nil {
		t.Fatal(err)
	}
	// README line 3 sits outside every include, so the check leaves its bare L4 alone
	got, err := CheckLabIDs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("findings after the rewrite: %v", got)
	}
}
