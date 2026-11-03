//go:build compose

package compose

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// matrixNames is the first column of design §12's failure table, each row cut
// at its bold name (the parenthetical after it is prose).
func matrixNames(t *testing.T, design string) []string {
	t.Helper()
	b, err := os.ReadFile(design)
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(b), "## 12. Failure model")
	if !ok {
		t.Fatal("design has no section 12")
	}
	section, _, _ := strings.Cut(after, "### Consequences")
	var names []string
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| **") {
			continue
		}
		rest := strings.TrimPrefix(line, "| **")
		name, _, ok := strings.Cut(rest, "**")
		if !ok {
			t.Fatalf("design §12 row has an unclosed bold name: %.60s", line)
		}
		names = append(names, name)
	}
	if len(names) < 18 {
		t.Fatalf("design §12's table has %d rows, want at least 18: the parse is wrong", len(names))
	}
	return names
}

var (
	// A lab row is L<N> standing alone: not the start of a results file's name (L4-error-x.md).
	evidenceRef = regexp.MustCompile("`(TestFailureMatrix/[a-z_0-9]+|Test[A-Za-z0-9_]+|tests/lab/results/[A-Za-z0-9_.-]+\\.md)`|(?:^|[^A-Za-z0-9/-])(L[0-9]+)(?:[^A-Za-z0-9-]|$)")
	subtestRef  = regexp.MustCompile(`TestFailureMatrix/([a-z_0-9]+)`)
)

// TestEveryMatrixRowHasEvidence: each row of design §12 is a row of
// deploy/failure-matrix.md with an evidence cell (its last) that names a
// subtest of TestFailureMatrix, a Test function that exists, or a lab entry.
func TestEveryMatrixRowHasEvidence(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	names := matrixNames(t, filepath.Join(root, "docs", "design", "2026-08-21-port49-design.md"))
	table, err := os.ReadFile(filepath.Join(root, "deploy", "failure-matrix.md"))
	if err != nil {
		t.Fatal(err)
	}
	matrix, err := os.ReadFile(filepath.Join(root, "tests", "compose", "failmatrix_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	tests := testFunctions(t, root)
	closed := closedLabRows(t, filepath.Join(root, "docs", "design", "2026-08-23-policy-engine-spec.md"))
	for _, name := range names {
		var cells []string
		for _, line := range strings.Split(string(table), "\n") {
			if strings.HasPrefix(line, "| **"+name+"**") {
				cells = strings.Split(strings.Trim(line, "| "), "|")
				break
			}
		}
		if cells == nil {
			t.Errorf("deploy/failure-matrix.md has no row for %q", name)
			continue
		}
		evidence := cells[len(cells)-1]
		refs := evidenceRef.FindAllString(evidence, -1)
		if len(cells) < 5 || len(refs) == 0 {
			t.Errorf("%q: the row has no evidence cell naming a subtest, a Test function or an L<N> (a gap is not filled with prose)", name)
		}
		for _, m := range subtestRef.FindAllStringSubmatch(evidence, -1) {
			if !strings.Contains(string(matrix), `("`+m[1]+`"`) {
				t.Errorf("%q: evidence names subtest %s, which failmatrix_test.go does not run", name, m[1])
			}
		}
		for _, m := range evidenceRef.FindAllStringSubmatch(evidence, -1) {
			switch r := strings.Trim(m[0], "` "); {
			case m[2] != "":
				if !closed[m[2]] {
					t.Errorf("%q: evidence cites %s, which spec §15 does not show closed (an open row is unmeasured; cite its results note or a test)", name, m[2])
				}
			case strings.HasPrefix(r, "tests/lab/results/"):
				if _, err := os.Stat(filepath.Join(root, r)); err != nil {
					t.Errorf("%q: evidence cites %s, which does not exist", name, r)
				}
			case strings.HasPrefix(r, "Test") && !strings.Contains(r, "/") && !tests[r]:
				t.Errorf("%q: evidence names %s, which no _test.go file declares", name, r)
			}
		}
	}
}

// closedLabRows is the set of lab register entries (L<N>) whose row in spec
// §15 says `closed — measured` (or **closed**); a row with platforms still open
// says so and is not in it.
func closedLabRows(t *testing.T, spec string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`^\| \*\*(L[0-9]+)\*\* \|`)
	done := regexp.MustCompile(`closed(\*\*)? — measured`)
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if m := row.FindStringSubmatch(line); m != nil && done.MatchString(line) && !strings.Contains(line, "Still open") {
			out[m[1]] = true
		}
	}
	if !out["L28"] || out["L4"] {
		t.Fatalf("the §15 parse is wrong: L28 closed %v, L4 closed %v (want true, false)", out["L28"], out["L4"])
	}
	return out
}

// testFunctions is every Test function declared in a _test.go file under root.
func testFunctions(t *testing.T, root string) map[string]bool {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	out := map[string]bool{}
	for _, dir := range []string{"internal", "cmd", "tests"} {
		filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, m := range decl.FindAllSubmatch(b, -1) {
				out[string(m[1])] = true
			}
			return nil
		})
	}
	return out
}
