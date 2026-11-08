package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Task 22: the pages for AI agents. Each string is a fact the page owes the agent that reads it and acts
// on it.
func init() {
	mustSay["agents/quick-start.md"] = append(mustSay["agents/quick-start.md"],
		"per_login_mfa_required", "port49 ssh:", "per_login_mfa_unavailable", "applies_to_machines",
		"no_grants_matched", "authorize_command", "no_log: true", "port49.Workload", "Never use `port49.Agent`",
		"An agent never runs `port49 token`", "show running-config **", "\n      register: out\n", "[WARNING]",
		"!!! warning \"Unmeasured\"", "L21-arista_eos.md", "never eAPI",
	)
	mustSay["agents/setup-runbook.md"] = append(mustSay["agents/setup-runbook.md"],
		"port49 policy test", "## Stop and ask a human", "merging a policy that grants access",
	)
}

// fencedBlocks is each fenced code block of text: its lines, without the fences.
func fencedBlocks(text string) [][]string {
	var blocks [][]string
	var cur []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			if in {
				blocks = append(blocks, cur)
				cur = nil
			}
			in = !in
			continue
		}
		if in {
			cur = append(cur, line)
		}
	}
	return blocks
}

func TestTheFencedBlockScannerFindsEachBlock(t *testing.T) {
	got := fencedBlocks("a\n```sh\none\ntwo\n```\nb\n  ```text\nthree\n  ```\n")
	if len(got) != 2 || len(got[0]) != 2 || len(got[1]) != 1 || got[1][0] != "three" {
		t.Errorf("blocks %q: want [one two] and [three]", got)
	}
}

// The runbook is links into the operator guide, so a step is never the guide's own text restated.
const runbookMaxBlockLines = 5

func TestTheRunbookLinksAndDoesNotRestate(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(docsRoot, "agents", "setup-runbook.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, blk := range fencedBlocks(string(b)) {
		if len(blk) > runbookMaxBlockLines {
			t.Errorf("setup-runbook.md holds a fenced block of %d lines (limit %d), starting %.50q: link the guide instead",
				len(blk), runbookMaxBlockLines, blk[0])
		}
	}
}

// A line that runs `port49 token`, or `port49 workload token` without the library around it, puts the
// token on standard output, which is the agent's context.
var runsToken = regexp.MustCompile("(^|[\\s;|&$(`/])port49\\s+([\"']?workload[\"']?\\s+)?[\"']?token\\b")

// The mint is caught however the shell quotes the word, and ordinary prose and other subcommands are not.
func TestRunsTokenSeesTheQuotedForms(t *testing.T) {
	for _, line := range []string{"port49 token leaf1", "port49 'token' leaf1", `port49 "token" leaf1`,
		"port49 workload token leaf1", "port49 workload 'token' leaf1", "x=$(port49 'token' leaf1)"} {
		if !runsToken.MatchString(line) {
			t.Errorf("%q is a mint and runsToken misses it", line)
		}
	}
	for _, line := range []string{"port49 login", "port49 tokens", "port49 revoke --list"} {
		if runsToken.MatchString(line) {
			t.Errorf("%q is not a mint and runsToken matches it", line)
		}
	}
}

func TestTheAgentPagesNeverRunPortTokenToStdout(t *testing.T) {
	pages, err := filepath.Glob(filepath.Join(docsRoot, "agents", "*.md"))
	if err != nil || len(pages) == 0 {
		t.Fatalf("no page under docs/site/agents: %v", err)
	}
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, blk := range fencedBlocks(string(b)) {
			for _, line := range blk {
				if runsToken.MatchString(line) || runsTokenArgv.MatchString(line) {
					t.Errorf("%s: a fenced block runs a token mint: %q", filepath.Base(p), line)
				}
			}
		}
	}
}

// runsTokenArgv is the same mint as a Python argv list.
var runsTokenArgv = regexp.MustCompile(`(["'])port49(["'])\s*,\s*(["']workload["']\s*,\s*)?["']token["']`)

// inlineSpans is each inline code span of text outside its fenced blocks. A span may wrap across lines
// and may be fenced by a longer run of backticks, so it can hold a single one.
func inlineSpans(text string) []string {
	var prose []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			in = !in
			continue
		}
		if !in {
			prose = append(prose, line)
		}
	}
	var spans []string
	for _, m := range regexp.MustCompile("(?s)(`+)(.+?)(`+)").FindAllStringSubmatch(strings.Join(prose, "\n"), -1) {
		if m[1] == m[3] {
			spans = append(spans, strings.TrimSpace(m[2]))
		}
	}
	return spans
}

// The only spans a page may hold that run a mint, because it names them as things never to run: the bare
// commands, and the one message of the Python library that advises a person to run one.
var namedAsNeverRun = map[string]bool{
	"port49 token": true, "port49 workload token": true, "port49 token --json": true,
	// the refusal table's label and format line for the CLI's own stderr, which carries no token
	"port49 workload token:": true, "port49 workload token: <device>: deny <reason>: <detail>": true,
}

const quotedAdvice = "port49: <device>: asks for"

func allowedSpan(s string) bool { return namedAsNeverRun[s] || strings.HasPrefix(s, quotedAdvice) }

// proseMints is each span that runs a mint in any spelling a fenced line is held to, except the allowed.
func proseMints(spans []string) []string {
	var out []string
	for _, s := range spans {
		if (runsToken.MatchString(s) || runsTokenArgv.MatchString(s)) && !allowedSpan(s) {
			out = append(out, s)
		}
	}
	return out
}

func TestAProseSpanThatIsAMintIsFound(t *testing.T) {
	text := "run `port49 token core1` now\n\nnever `port49 token` or `port49 workload token`\n\n" +
		"or `port49 workload token --broker B leaf1` or `port49 token --json`, `['port49','token',d]`\n\n" +
		"``port49: <device>: asks for x; run\n`port49 token d` at a terminal``\n\n```sh\nport49 token x\n```\n"
	got := proseMints(inlineSpans(text))
	want := []string{"port49 token core1", "port49 workload token --broker B leaf1", "['port49','token',d]"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("flagged %q: want %q", got, want)
	}
}

func TestNoProseSpanOnTheAgentPagesRunsAMint(t *testing.T) {
	pages, _ := filepath.Glob(filepath.Join(docsRoot, "agents", "*.md"))
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range proseMints(inlineSpans(string(b))) {
			t.Errorf("%s: a code span runs a mint: %q", filepath.Base(p), s)
		}
	}
}

func TestTheTokenScanFindsEachSpelling(t *testing.T) {
	for _, line := range []string{`["port49", "token", d]`, `cmd = ["port49", "workload", "token"]`,
		`['port49','token',d]`, `["port49", 'workload', 'token']`} {
		if !runsTokenArgv.MatchString(line) {
			t.Errorf("%q is not found as a token mint", line)
		}
	}
	for _, line := range []string{"port49 token leaf1", "  $ port49 token --json leaf1", "x=$(port49 token leaf1)",
		"echo `port49 token x`", "/usr/local/bin/port49 token x", "/opt/port49/bin/port49 workload token a",
		"port49 workload token --scope backup", "ssh a | port49  token b"} {
		if !runsToken.MatchString(line) {
			t.Errorf("%q is not found as a token mint", line)
		}
	}
	for _, line := range []string{"port49 workload identity", "port49 policy test", "# port49 tokens are not shown"} {
		if runsToken.MatchString(line) {
			t.Errorf("%q is found as a token mint", line)
		}
	}
}
