// Package ci holds the repository's CI checks. docslint.go is the documentation lint (plan 13): it
// keeps credentials, PEM blocks, TOTP seeds, anything a gitleaks rule matches, personal home paths,
// lab hosts and removed names out of the docs. It has no build tag, so the tests here and the
// docs build share it.
package ci

import (
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/blanketfish/port49/internal/config"
)

// Finding is one lint hit. It names the file, the line and the rule and never the text it matched, so
// a failure prints no secret.
type Finding struct {
	File string
	Line int
	Rule string
}

// GitleaksRule is one [[rules]] entry of .gitleaks.toml.
type GitleaksRule struct {
	ID string
	Re *regexp.Regexp
}

var (
	gitleaksOnce  sync.Once
	gitleaksRules []GitleaksRule
	gitleaksErr   error
)

// GitleaksRules reads every [[rules]] id and regex from the repository's .gitleaks.toml (found from
// this file, so the caller's directory does not matter) and compiles each with Go's regexp.
func GitleaksRules() ([]GitleaksRule, error) {
	gitleaksOnce.Do(func() {
		_, self, _, _ := runtime.Caller(0)
		path := filepath.Join(filepath.Dir(self), "..", "..", ".gitleaks.toml")
		b, err := os.ReadFile(path)
		if err != nil {
			gitleaksErr = err
			return
		}
		var id string
		inRules := false
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "["):
				inRules = strings.TrimSpace(line) == "[[rules]]"
				id = ""
			case !inRules:
			case strings.HasPrefix(line, "id = "):
				id = strings.Trim(strings.TrimPrefix(line, "id = "), `" `)
			case strings.HasPrefix(line, "regex = '''"):
				src := strings.TrimSuffix(strings.TrimPrefix(line, "regex = '''"), "'''")
				re, err := regexp.Compile(src)
				if err != nil {
					gitleaksErr = fmt.Errorf(".gitleaks.toml rule %s: regex does not compile: %w", id, err)
					return
				}
				gitleaksRules = append(gitleaksRules, GitleaksRule{ID: id, Re: re})
			}
		}
	})
	return gitleaksRules, gitleaksErr
}

type lintRule struct {
	name string
	re   *regexp.Regexp
	// ok reports that a match is allowed. It is given the match text.
	ok func(match string) bool
}

var labResultPath = regexp.MustCompile(`tests/lab/results/[A-Za-z0-9._/-]+`)

// noteLinkText matches [name.md](URL/tests/lab/results/name.md): group 1 is the text, group 3 the file the
// link goes to.
var noteLinkText = regexp.MustCompile(`\[([A-Za-z0-9._-]+\.md)\]\(([^)\s]*tests/lab/results/([A-Za-z0-9._-]+\.md))\)`)

// labNoteExists reports whether m, a match of labResultPath, names a file in the repository, by a path
// with no ".." segment. A
// trailing dot or dash is the sentence's, not the path's. Only an existing note's file name may carry a
// host name past the lint: an invented path must not.
func labNoteExists(m string) bool {
	if slices.Contains(strings.Split(m, "/"), "..") {
		return false
	}
	_, self, _, _ := runtime.Caller(0)
	info, err := os.Stat(filepath.Join(filepath.Dir(self), "..", "..", filepath.FromSlash(strings.TrimRight(m, ".-"))))
	return err == nil && info.Mode().IsRegular()
}

var lintRules = []lintRule{
	{"token_shaped", regexp.MustCompile(`[0-9A-Za-z]{20,}`), func(m string) bool {
		// A device token is 30 base62 characters. A placeholder (all x, X or 0) is allowed; a run
		// with no digit, no upper or no lower case is not shaped like one.
		var up, lo, dig, other bool
		for _, c := range m {
			switch {
			case c >= 'A' && c <= 'Z':
				up = true
			case c >= 'a' && c <= 'z':
				lo = true
			default:
				dig = true
			}
			if c != 'x' && c != 'X' && c != '0' {
				other = true
			}
		}
		return !(up && lo && dig) || !other
	}},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}`), nil},
	{"pem_block", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`), nil},
	{"totp_seed", regexp.MustCompile(`otpauth://|secret=[A-Z2-7]{16,}`), nil},
	{"long_hex", regexp.MustCompile(`[0-9A-Fa-f]{32,}`), func(m string) bool {
		// A git SHA is 40 characters; a run of one character is a placeholder.
		return len(m) == 40 || strings.Trim(m, string(m[0])) == ""
	}},
	{"home_path", regexp.MustCompile(`/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|C:\\Users\\|~[A-Za-z_][A-Za-z0-9._-]*/`), nil},
	{"lab_host", regexp.MustCompile(`(?i)beehive|\bser8\b|\.internal\b`), nil},
	{"removed_name", removedNames(), nil},
}

// removedNames matches what the product no longer has: a doc that teaches one is wrong.
func removedNames() *regexp.Regexp {
	names := []string{
		`port49 devices trust`, "`devices trust`", `pins file`, `receipt_ttl`, `admin_socket`, `meta/purged`,
		`restore guard`, `port49_redemption_restore_guarded`, `token_secret_env`, `webhook_secret_env`,
	}
	parts := make([]string, 0, len(names)+len(config.RemovedKeys()))
	for _, n := range names {
		parts = append(parts, regexp.QuoteMeta(n))
	}
	for _, k := range config.RemovedKeys() {
		parts = append(parts, `\b`+regexp.QuoteMeta(k)+`\b`)
	}
	return regexp.MustCompile(`(?i)` + strings.Join(parts, "|"))
}

// LintText returns every finding in text, which is named name. A rule that matches twice on a line is
// one finding.
func LintText(name string, text []byte) []Finding {
	s := string(text)
	var out []Finding
	seen := map[Finding]bool{}
	add := func(rule string, at int) {
		f := Finding{File: name, Line: 1 + strings.Count(s[:at], "\n"), Rule: rule}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for _, r := range lintRules {
		src := s
		if r.name == "lab_host" {
			// A link written with its note's file name, [load-beehive-gates.md](.../results/load-beehive-gates.md),
			// names that file: its text is the path's last segment.
			src = noteLinkText.ReplaceAllStringFunc(s, func(m string) string {
				sub := noteLinkText.FindStringSubmatch(m)
				if sub[1] != sub[3] || !labNoteExists("tests/lab/results/"+sub[3]) {
					return m
				}
				return strings.Repeat(" ", len(sub[1])+2) + m[len(sub[1])+2:]
			})
			// An existing results note's file name (load-beehive-gates.md) is a path, not a host.
			src = labResultPath.ReplaceAllStringFunc(src, func(m string) string {
				if !labNoteExists(m) {
					return m
				}
				return strings.Repeat(" ", len(m))
			})
		}
		for _, m := range r.re.FindAllStringIndex(src, -1) {
			if r.ok == nil || !r.ok(src[m[0]:m[1]]) {
				add(r.name, m[0])
			}
		}
	}
	rules, err := GitleaksRules()
	if err != nil {
		// A lint that cannot read the rules must fail, not pass.
		add("gitleaks_config", 0)
	}
	for _, g := range rules {
		rule := "device_secret"
		if g.ID == "claude-session-link" {
			rule = "session_link"
		}
		for _, m := range g.Re.FindAllStringIndex(s, -1) {
			add(rule, m[0])
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// DocSources reads the page sources under root (the repository): every .md under docs/site, snippets
// included, and README.md. The keys are slash-separated paths from root.
func DocSources(root string) (map[string][]byte, error) {
	out := map[string][]byte{}
	site := filepath.Join(root, "docs", "site")
	err := filepath.WalkDir(site, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(root, "README.md")); err == nil {
		out["README.md"] = b
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return out, nil
}

var (
	htmlBlocks = regexp.MustCompile(`(?is)<(script|style)\b.*?</(script|style)>`)
	htmlTags   = regexp.MustCompile(`(?s)<[^>]*>`)
)

// BuiltSite reads every *.html under dir (a built site, which holds each snippet expanded), drops
// script and style blocks and the tags, and unescapes the entities, so the text is what a reader sees.
// The keys are slash-separated paths from dir.
func BuiltSite(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		text := htmlBlocks.ReplaceAll(b, nil)
		text = htmlTags.ReplaceAll(text, nil)
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = []byte(html.UnescapeString(string(text)))
		return nil
	})
	return out, err
}
