package ci

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/docgen"
)

// Task 18: monitoring and troubleshooting. Each string is a fact the page owes the person reading it
// during an outage.
func init() {
	mustSay["operate/troubleshooting/index.md"] = append(mustSay["operate/troubleshooting/index.md"],
		"cached directory membership", "the logout queue is full", "port49_revocations_file_failed", "store_unavailable",
		"the session store was restored from a snapshot", "../../reference/alerts.md#port49_target_absent",
	)
	mustSay["operate/troubleshooting/will-not-start.md"] = append(mustSay["operate/troubleshooting/will-not-start.md"],
		"--ready", "/healthz", "docker stack deploy", "service_healthy", "debug pod",
		"start_timeout", "`retries` from 3 to 6",
	)
	mustSay["operate/monitoring.md"] = append(mustSay["operate/monitoring.md"],
		"task_id", "global_cap", "10 ms", "etcd_disk_slow", "port49_accounting_spool_disk_slow",
		"load-beehive-gates.md", `job="port49-broker"`,
	)
	mustSay["operate/troubleshooting/failure-matrix.md"] = append(mustSay["operate/troubleshooting/failure-matrix.md"],
		`--8<-- "deploy/failure-matrix.md:3"`,
	)
}

const indexPage = "operate/troubleshooting/index.md"

// goStringLiterals is every string literal in non-test Go under internal/ and cmd/, and every run of
// literals joined by + (one BinaryExpr of BasicLits) as one string.
func goStringLiterals(t *testing.T) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "cmd"} {
		root := filepath.Join(repoRoot, dir)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BasicLit:
					if n.Kind == token.STRING {
						if s, err := strconv.Unquote(n.Value); err == nil {
							out = append(out, s)
						}
					}
				case *ast.BinaryExpr:
					if s, ok := joinedLiterals(n); ok {
						out = append(out, s)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// joinedLiterals is the value of an expression made only of string literals joined by +.
func joinedLiterals(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, ok := joinedLiterals(e.X)
		if !ok {
			return "", false
		}
		r, ok := joinedLiterals(e.Y)
		return l + r, ok
	case *ast.ParenExpr:
		return joinedLiterals(e.X)
	}
	return "", false
}

var (
	youSee      = regexp.MustCompile("^\\*\\*You see:\\*\\* `([^`]+)`")
	placeholder = regexp.MustCompile(`<[^>]*>`)
	wildcard    = `(?:%[svdq]|[^ ]+)`
)

// quotedLinesOf is the code span of each "**You see:**" in the "A log line says" section of the 3am
// index, and the lines of that section that start a "**You see:**" without a whole code span on the same
// line (a wrapped span would otherwise be skipped).
func quotedLinesOf(text string) (spans, bad []string) {
	in := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "## ") {
			in = strings.HasPrefix(line, "## A log line says")
			continue
		}
		if !in || !strings.HasPrefix(line, "**You see:**") {
			continue
		}
		if m := youSee.FindStringSubmatch(line); m != nil {
			spans = append(spans, m[1])
		} else {
			bad = append(bad, line)
		}
	}
	return spans, bad
}

func TestAWrappedYouSeeIsAnError(t *testing.T) {
	text := "## A log line says\n\n**You see:** `a line that wraps\nonto a second line`\n\n**You see:** `fine`\n"
	spans, bad := quotedLinesOf(text)
	if len(spans) != 1 || spans[0] != "fine" || len(bad) != 1 {
		t.Errorf("spans %q, bad %q: want the one whole span and the wrapped one reported", spans, bad)
	}
}

func quotedLines(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docsRoot, filepath.FromSlash(indexPage)))
	if err != nil {
		t.Fatal(err)
	}
	spans, bad := quotedLinesOf(string(b))
	for _, l := range bad {
		t.Errorf("a **You see:** in the log-line section has no whole code span on its line: %.60s", l)
	}
	return spans
}

// lineRegexp is a quoted line as a pattern: each <...> is one word or a format verb (%s, %d, %v, %q),
// not any run of text.
func lineRegexp(line string) *regexp.Regexp {
	parts := placeholder.Split(line, -1)
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("(?s)" + strings.Join(parts, wildcard))
}

func TestEveryQuotedLogLineIsInTheCode(t *testing.T) {
	lines := quotedLines(t)
	if len(lines) < 5 {
		t.Fatalf("the log-line section quotes %d lines, want at least 5", len(lines))
	}
	lits := goStringLiterals(t)
	for _, line := range lines {
		re := lineRegexp(line)
		found := false
		for _, s := range lits {
			if re.MatchString(s) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no string literal under internal/ or cmd/ holds %q", line)
		}
	}
}

// Every alert, page or ticket, is in the index linked to its section of the alerts reference, so a new
// rule cannot ship without a family to belong to. At least the page ones must exist in the file.
func TestEveryAlertIsInTheIndex(t *testing.T) {
	rules, err := os.ReadFile(filepath.Join(repoRoot, "deploy", "alerts", "port49.rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := docgen.Alerts(rules)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(docsRoot, filepath.FromSlash(indexPage)))
	if err != nil {
		t.Fatal(err)
	}
	pages := 0
	for _, a := range alerts {
		if a.Severity == "page" {
			pages++
		}
		if want := "../../reference/alerts.md#" + a.Name + ")"; !strings.Contains(string(b), want) {
			t.Errorf("%s does not link alert %s (%s)", indexPage, a.Name, want)
		}
	}
	if pages == 0 {
		t.Fatal("no page-severity alert found")
	}
}
