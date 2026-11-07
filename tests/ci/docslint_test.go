package ci

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/docgen"
	"github.com/blanketfish/port49/internal/port49d"
	"github.com/blanketfish/port49/tests/alerts"
)

const repoRoot = "../.."

// A finding names the file, the line and the rule, never the text it matched: a failure of the lint
// must not print a secret.
func report(t *testing.T, fs []Finding) {
	t.Helper()
	for _, f := range fs {
		t.Errorf("%s:%d: %s", f.File, f.Line, f.Rule)
	}
}

// fixture reads testdata/docslint/<name>.md. A fixture never holds a real-looking secret (the
// pre-commit gitleaks hook would stop the commit), so it spells one as {{a|b}} and the test joins the
// halves at run time.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "docslint", name+".md"))
	if err != nil {
		t.Fatal(err)
	}
	join := regexp.MustCompile(`\{\{([^|{}]*)\|([^{}]*)\}\}`)
	return join.ReplaceAll(b, []byte("${1}${2}"))
}

func TestEachLintRuleCatchesItsFixture(t *testing.T) {
	rules := []string{"token_shaped", "jwt", "pem_block", "totp_seed", "long_hex", "home_path", "lab_host",
		"session_link", "device_secret", "removed_name"}
	for _, rule := range rules {
		fs := LintText(rule+".md", fixture(t, rule))
		if len(fs) != 1 || fs[0].Rule != rule {
			t.Errorf("%s fixture: got %d findings %v, want exactly one %s", rule, len(fs), fs, rule)
		}
	}
	report(t, LintText("clean.md", fixture(t, "clean")))
}

// A results note's path carries a host name past the lint only when the note exists in the repository.
func TestLabResultPathExemptionNeedsTheNoteToExist(t *testing.T) {
	existing := "see tests/lab/results/load-beehive-ram.md."
	if fs := LintText("a.md", []byte(existing)); len(fs) != 0 {
		t.Errorf("a path to an existing note: got findings %v", fs)
	}
	// A ".." segment can reach an existing file from a path that is not a results note's.
	climbing := "see tests/lab/results/../results/load-beehive-ram.md."
	if fs := LintText("a.md", []byte(climbing)); len(fs) != 1 || fs[0].Rule != "lab_host" {
		t.Errorf("a path with a .. segment: got %v, want one lab_host", fs)
	}
	invented := "see tests/lab/results/load-beehive-invented.md."
	if fs := LintText("a.md", []byte(invented)); len(fs) != 1 || fs[0].Rule != "lab_host" {
		t.Errorf("a path to a note that does not exist: got %v, want one lab_host", fs)
	}
}

func TestThePagesPassTheLint(t *testing.T) {
	pages, err := DocSources(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) == 0 {
		t.Fatal("no page sources found")
	}
	for _, name := range sortedKeys(pages) {
		report(t, LintText(name, pages[name]))
	}
}

func TestTheBuiltSitePassesTheLint(t *testing.T) {
	dir := builtSiteDir(t)
	site, err := BuiltSite(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(site) == 0 {
		t.Fatalf("no *.html under %s", dir)
	}
	for _, name := range sortedKeys(site) {
		report(t, LintText(name, site[name]))
	}
}

// BuiltSite strips the tags and unescapes the entities, so a snippet the build expanded is read as a
// reader sees it.
func TestBuiltSiteStripsTagsAndEntities(t *testing.T) {
	dir := t.TempDir()
	html := `<html><head><script>var secret_env = 1</script></head><body><p>a<span>b</span> &lt;c&gt; &amp; d</p></body></html>`
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
	site, err := BuiltSite(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := string(site["index.html"])
	if got != "ab <c> & d" {
		t.Errorf("BuiltSite = %q, want %q", got, "ab <c> & d")
	}
}

// The lint's device_secret rule is every [[rules]] regex in .gitleaks.toml, read at run time: a rule
// added to the file is in the lint at once, and one that Go's regexp cannot compile is a failure here,
// not a silent gap.
func TestTheLintMirrorsGitleaks(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, ".gitleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	inRules := false
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "[["):
			inRules = strings.TrimSpace(line) == "[[rules]]"
		case inRules && strings.HasPrefix(line, "id = "):
			ids = append(ids, strings.Trim(strings.TrimPrefix(line, "id = "), `" `))
		}
	}
	rules, err := GitleaksRules()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rules {
		got = append(got, r.ID)
		if r.Re == nil {
			t.Errorf("rule %s has no compiled regex", r.ID)
		}
	}
	sort.Strings(ids)
	sort.Strings(got)
	if len(ids) < 2 || strings.Join(ids, ",") != strings.Join(got, ",") {
		t.Errorf(".gitleaks.toml has rules %v, the lint has %v", ids, got)
	}
}

// metricName is a port49_ word; one followed by "-" is a compose volume (port49_port49d-keys).
var metricName = regexp.MustCompile(`\bport49_[a-z0-9_]+`)

func TestEveryMetricTheDocsNameIsRegistered(t *testing.T) {
	names, err := alerts.RegisteredNames()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, n := range names {
		known[n] = true
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot, "deploy", "alerts", "port49.rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var rules struct {
		Groups []struct {
			Rules []struct {
				Alert string `yaml:"alert"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			if r.Alert != "" {
				known[r.Alert] = true
			}
		}
	}
	if len(known) < 10 {
		t.Fatalf("only %d registered names: the list is broken", len(known))
	}
	pages, err := DocSources(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedKeys(pages) {
		text := string(pages[name])
		for _, m := range metricName.FindAllStringIndex(text, -1) {
			if m[1] < len(text) && text[m[1]] == '-' {
				continue
			}
			if !metricKnown(known, strings.TrimRight(text[m[0]:m[1]], "_")) {
				report(t, []Finding{{File: name, Line: 1 + strings.Count(text[:m[0]], "\n"), Rule: "unknown_metric"}})
			}
		}
	}
}

func metricKnown(known map[string]bool, n string) bool {
	if known[n] || known[n+"_total"] {
		return true
	}
	for _, suffix := range []string{"_bucket", "_sum", "_count", "_total"} {
		if base, ok := strings.CutSuffix(n, suffix); ok && (known[base] || known[base+"_total"]) {
			return true
		}
	}
	return false
}

// dispatch is what the binaries accept: the top-level words of port49, and for each the second words
// its own function dispatches. Both are read from the source with go/ast.
type dispatch struct {
	top map[string]bool
	sub map[string]map[string]bool
}

func parseDir(t *testing.T, dir string) (map[string]*ast.FuncDecl, []*ast.File) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(repoRoot, dir, "*.go"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no Go files in %s: %v", dir, err)
	}
	funcs := map[string]*ast.FuncDecl{}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	return funcs, files
}

func strLit(e ast.Expr) (string, bool) {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(l.Value, "\"`"), true
}

// argsIndex reports whether e is args[N].
func argsIndex(e ast.Expr) bool {
	ix, ok := e.(*ast.IndexExpr)
	if !ok {
		return false
	}
	id, ok := ix.X.(*ast.Ident)
	return ok && id.Name == "args"
}

// words collects the names a node dispatches on: the case labels of a switch on args[N] and the
// literals args[N] is compared to. A call that hands args[1:] on is followed into the function it calls.
func words(n ast.Node, funcs map[string]*ast.FuncDecl, seen map[string]bool, out map[string]bool) {
	ast.Inspect(n, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SwitchStmt:
			if x.Tag != nil && argsIndex(x.Tag) {
				for _, c := range x.Body.List {
					for _, e := range c.(*ast.CaseClause).List {
						if s, ok := strLit(e); ok {
							out[s] = true
						}
					}
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.EQL || x.Op == token.NEQ {
				for _, pair := range [][2]ast.Expr{{x.X, x.Y}, {x.Y, x.X}} {
					if s, ok := strLit(pair[1]); ok && argsIndex(pair[0]) {
						out[s] = true
					}
				}
			}
		case *ast.CallExpr:
			id, ok := x.Fun.(*ast.Ident)
			if !ok || funcs[id.Name] == nil || seen[id.Name] {
				break
			}
			for _, a := range x.Args {
				if se, ok := a.(*ast.SliceExpr); ok && argsIdent(se.X) {
					if lo, ok := se.Low.(*ast.BasicLit); ok && lo.Value == "1" {
						seen[id.Name] = true
						words(funcs[id.Name].Body, funcs, seen, out)
					}
				}
			}
		}
		return true
	})
}

func argsIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "args"
}

// refusedSubcommands are the words port49 dispatches only to refuse them: `port49 directory
// init-enrollments` and `export` run on the broker host as `port49-broker`, and cmd/port49/directory.go
// prints that and exits 2.
var refusedSubcommands = map[string][]string{"directory": {"init-enrollments", "export"}}

func portDispatch(t *testing.T) dispatch {
	t.Helper()
	funcs, _ := parseDir(t, "cmd/port49")
	d := dispatch{top: map[string]bool{}, sub: map[string]map[string]bool{}}
	for _, fd := range funcs {
		if fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || sw.Tag == nil || !argsIndex(sw.Tag) {
				return true
			}
			isTop := false
			for _, c := range sw.Body.List {
				for _, e := range c.(*ast.CaseClause).List {
					if s, ok := strLit(e); ok && s == "login" {
						isTop = true
					}
				}
			}
			if !isTop {
				return true
			}
			for _, c := range sw.Body.List {
				cc := c.(*ast.CaseClause)
				set := map[string]bool{}
				for _, stmt := range cc.Body {
					words(stmt, funcs, map[string]bool{}, set)
				}
				for _, e := range cc.List {
					if s, ok := strLit(e); ok {
						d.top[s] = true
						d.sub[s] = set
					}
				}
			}
			return false
		})
	}
	if len(d.top) < 10 {
		t.Fatalf("found %d top-level port49 commands: the scan is broken", len(d.top))
	}
	// A refused word is a case label in the source (it has a clause that prints where the command
	// runs and exits 2) but not a command. Each must still be one, so a refusal that is removed or
	// renamed fails here instead of leaving a stale entry.
	for top, subs := range refusedSubcommands {
		for _, sub := range subs {
			if !d.sub[top][sub] {
				t.Errorf("port49 %s %s is listed as refused, but the source has no case for it", top, sub)
			}
			delete(d.sub[top], sub)
		}
	}
	return d
}

func inventoryDispatch(t *testing.T) map[string]bool {
	t.Helper()
	funcs, _ := parseDir(t, "cmd/port49-inventory")
	set := map[string]bool{}
	if fd := funcs["main"]; fd != nil {
		words(fd.Body, funcs, map[string]bool{}, set)
	}
	return set
}

// hasSubcommand are the port49 commands whose second word is checked.
var hasSubcommand = map[string]bool{"policy": true, "platform": true, "store": true, "directory": true,
	"hwkey": true, "keys": true, "devices": true, "access": true, "grants": true, "inventory": true}

var (
	binaries = map[string]bool{"port49": true, "port49d": true, "port49-broker": true, "port49-inventory": true}
	wordRe   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	spanRe   = regexp.MustCompile("`([^`\n]+)`")
	shellLng = map[string]bool{"": true, "sh": true, "bash": true, "shell": true, "console": true, "zsh": true, "session": true}
)

// commandRefs is every command a page names, as the binary and up to two words: each `<binary> <word>
// [<word>]` code span, and each line that starts a fenced shell block (after a "$ " or "sudo ") and is
// not the continuation of the line before.
func commandRefs(text string) []struct {
	line   int
	fields []string
} {
	var refs []struct {
		line   int
		fields []string
	}
	add := func(n int, s string) {
		f := strings.Fields(s)
		if len(f) > 0 && binaries[f[0]] {
			refs = append(refs, struct {
				line   int
				fields []string
			}{n, f})
		}
	}
	inFence, shell, cont := false, false, false
	for i, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "```") {
			if inFence {
				inFence = false
			} else {
				inFence = true
				lang, _, _ := strings.Cut(strings.TrimLeft(trim, "`"), " ")
				shell = shellLng[strings.ToLower(lang)]
			}
			cont = false
			continue
		}
		if inFence {
			if shell && !cont && !strings.HasPrefix(trim, "#") {
				s := strings.TrimPrefix(strings.TrimPrefix(trim, "$ "), "sudo ")
				add(i+1, s)
			}
			cont = strings.HasSuffix(trim, `\`)
			continue
		}
		for _, m := range spanRe.FindAllStringSubmatch(line, -1) {
			add(i+1, m[1])
		}
	}
	return refs
}

func TestEveryCommandTheDocsNameExists(t *testing.T) {
	port := portDispatch(t)
	inv := inventoryDispatch(t)
	daemon, broker := set(port49d.DaemonSubcommands()), set(port49d.BrokerSubcommands())
	pages, err := DocSources(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedKeys(pages) {
		for _, ref := range commandRefs(string(pages[name])) {
			bin, f := ref.fields[0], ref.fields[1:]
			if len(f) == 0 || !wordRe.MatchString(f[0]) {
				continue
			}
			ok := true
			switch bin {
			case "port49":
				ok = port.top[f[0]]
				if ok && hasSubcommand[f[0]] && len(f) > 1 && wordRe.MatchString(f[1]) {
					ok = port.sub[f[0]][f[1]]
				}
			case "port49d":
				ok = daemon[f[0]]
			case "port49-broker":
				ok = broker[f[0]]
			case "port49-inventory":
				ok = inv[f[0]]
			}
			if !ok {
				report(t, []Finding{{File: name, Line: ref.line, Rule: "unknown_command"}})
			}
		}
	}
}

// The scan has to find the commands it is meant to find, or a broken scan would pass every page.
func TestTheCommandScanReadsTheDispatch(t *testing.T) {
	port := portDispatch(t)
	for top, sub := range map[string]string{"policy": "test", "platform": "list", "store": "status", "devices": "check-config",
		"access": "review", "grants": "remove", "keys": "status", "hwkey": "setup", "inventory": "sync", "directory": "forget"} {
		if !port.top[top] || !port.sub[top][sub] {
			t.Errorf("the scan does not find port49 %s %s", top, sub)
		}
	}
	for _, bad := range []string{"trust", "start"} {
		if port.top[bad] {
			t.Errorf("the scan finds port49 %s", bad)
		}
	}
	// The CLI refuses these two (they run on the broker host), though its source has them as case labels.
	for _, sub := range []string{"init-enrollments", "export"} {
		if port.sub["directory"][sub] {
			t.Errorf("the scan accepts port49 directory %s, which the CLI refuses", sub)
		}
	}
	if port.sub["policy"]["lint"] {
		t.Error("the scan finds port49 policy lint")
	}
	text := "Run `port49 policy test` or\n```sh\n$ port49d keys-diagnose \\\n  port49d nope\nport49-broker forget-issuer --x\n```\n"
	got := fmt.Sprint(commandRefs(text))
	want := "[{1 [port49 policy test]} {3 [port49d keys-diagnose \\]} {5 [port49-broker forget-issuer --x]}]"
	if got != want {
		t.Errorf("commandRefs = %s, want %s", got, want)
	}
}

func set(names []string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

var repoLink = regexp.MustCompile("https://github\\.com/blanketfish/port49/(?:blob|tree)/main/([^\\s)\"'<>#?`\\]]+)")

func TestRepoLinksNameTrackedFiles(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	tracked := map[string]bool{}
	dirs := map[string]bool{}
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" {
			continue
		}
		tracked[f] = true
		for d := filepath.Dir(f); d != "."; d = filepath.Dir(d) {
			dirs[d] = true
		}
	}
	pages, err := DocSources(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedKeys(pages) {
		text := string(pages[name])
		for _, m := range repoLink.FindAllStringSubmatchIndex(text, -1) {
			p := strings.TrimRight(text[m[2]:m[3]], ".,;:")
			if !tracked[p] && !dirs[strings.TrimSuffix(p, "/")] {
				report(t, []Finding{{File: name, Line: 1 + strings.Count(text[:m[0]], "\n"), Rule: "dead_repo_link"}})
			}
		}
	}
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// A configuration example on a page is a fenced yaml block titled with the file it is for:
//
//	```yaml title="port49d.yaml"
//
// The test below decodes each one with that file's own loader, so a page cannot show a key the
// loader refuses.
var exampleFence = regexp.MustCompile("^(\\s*)```ya?ml\\s+title=\"([^\"]+)\"")

type configExample struct {
	File string
	Line int
	Body []byte
}

func configExamples(text string) []configExample {
	var out []configExample
	var cur *configExample
	var indent string
	var body []string
	for i, line := range strings.Split(text, "\n") {
		switch {
		case cur == nil:
			if m := exampleFence.FindStringSubmatch(line); m != nil {
				cur, indent, body = &configExample{File: m[2], Line: i + 1}, m[1], nil
			}
		case strings.TrimSpace(line) == "```":
			cur.Body = []byte(strings.Join(body, "\n") + "\n")
			out = append(out, *cur)
			cur = nil
		default:
			body = append(body, strings.TrimPrefix(line, indent))
		}
	}
	return out
}

func decodeExample(ex configExample) error {
	for _, s := range docgen.Schemas() {
		if s.File == ex.File {
			return s.Decode(ex.Body)
		}
	}
	return fmt.Errorf("%s is not a file with a schema; the title is one of the six config file names", ex.File)
}

func TestTheExampleScannerFindsTitledBlocks(t *testing.T) {
	text := "text\n```yaml title=\"policy.yaml\"\nscopes: []\n```\n\n!!! note\n    ```yaml title=\"config.yaml\"\n    broker: b\n    ```\n```yaml\nplain: 1\n```\n"
	got := configExamples(text)
	if len(got) != 2 || got[0].File != "policy.yaml" || got[0].Line != 2 || string(got[0].Body) != "scopes: []\n" ||
		got[1].File != "config.yaml" || string(got[1].Body) != "broker: b\n" {
		t.Fatalf("configExamples = %+v", got)
	}
	if err := decodeExample(configExample{File: "policy.yaml", Body: []byte("not_a_key: 1\n")}); err == nil {
		t.Error("an example with an unknown key decoded")
	}
	if err := decodeExample(configExample{File: "other.yaml"}); err == nil {
		t.Error("an example titled with no schema decoded")
	}
}

// The titles port49d.yaml and port49-broker.yaml are two files of one schema, told apart by the role
// each is read under. These fixtures go through decodeExample, so they prove Schemas wires each title
// to its own role's decode, not only that the decodes refuse.
func TestTheConfigExamplesAreHeldToTheirFilesRole(t *testing.T) {
	for _, tc := range []struct {
		file, body string
		ok         bool
	}{
		// Split, so the repository's scan for a config that still sets the removed key (adminsocket_test.go)
		// does not read the fixture as one.
		{"port49d.yaml", "admin_" + "socket: /run/x\n", false},
		{"port49-broker.yaml", "admin_" + "socket: /run/x\n", false},
		{"port49-broker.yaml", "listen: \":49\"\n", false},
		{"port49d.yaml", "broker:\n  state_dir: /x\n", false},
		{"port49d.yaml", "tls_listener:\n", false},
		{"port49-broker.yaml", "tls_listener:\n", false},
		{"port49d.yaml", "listen: \":49\"\n", true},
		{"port49-broker.yaml", "broker:\n  state_dir: /x\n", true},
	} {
		err := decodeExample(configExample{File: tc.file, Body: []byte(tc.body)})
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: %q was refused: %v", tc.file, tc.body, err)
		case !tc.ok && err == nil:
			t.Errorf("%s: %q was accepted", tc.file, tc.body)
		}
	}
}

func TestEveryConfigExampleDecodes(t *testing.T) {
	pages, err := DocSources(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedKeys(pages) {
		for _, ex := range configExamples(string(pages[name])) {
			if err := decodeExample(ex); err != nil {
				t.Errorf("%s:%d: the %s example does not decode: %v", name, ex.Line, ex.File, err)
			}
		}
	}
}
