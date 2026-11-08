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
		"no_grants_matched", "authorize_command", "no_log: true",
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
var runsToken = regexp.MustCompile(`(^|[\s;|&$(])port49\s+(workload\s+)?token\b`)

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
				if runsToken.MatchString(line) {
					t.Errorf("%s: a fenced block runs a token mint: %q", filepath.Base(p), line)
				}
			}
		}
	}
}

func TestTheTokenScanFindsEachSpelling(t *testing.T) {
	for _, line := range []string{"port49 token leaf1", "  $ port49 token --json leaf1", "x=$(port49 token leaf1)",
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
