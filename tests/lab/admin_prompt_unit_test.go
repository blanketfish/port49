//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `port49 revoke` prints the agent's touch prompt on stderr before it waits for the key, and the
// harness reads stdout and stderr as one. A cell that quotes the first line, or looks for the
// broker's refusal at its start, must see the refusal and not the prompt (L74 d, e and j quoted
// only "touch your key to ..." on 2026-11-05).
func TestAnAdminRunDoesNotStartWithTheTouchPrompt(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"echo 'touch your key to revoke_principal user:alice@example.com' >&2\n" +
		"echo 'port49 revoke: broker: the revocation may not have been recorded: this region'\"'\"'s session store: 1 token keys deleted' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(repo, "bin", "port49"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := root
	root = repo
	defer func() { root = old }()
	out, code := (&labAdmin{env: os.Environ()}).run("--principal", "user:alice@example.com")
	if code != 1 || strings.Contains(out, "touch your key") || !strings.HasPrefix(out, "port49 revoke: broker:") {
		t.Fatalf("exit %d: %q", code, out)
	}
}

func TestWithoutTheTouchPromptKeepsEveryOtherLine(t *testing.T) {
	in := "touch your key to lift user:carol@example.com\nport49 revoke: refused\nsecond line\n"
	if got := withoutTouchPrompt(in); got != "port49 revoke: refused\nsecond line" {
		t.Errorf("%q", got)
	}
	if got := withoutTouchPrompt("revoked user:alice@example.com at 2026-11-05T05:00:00Z: ok"); !strings.HasPrefix(got, "revoked ") {
		t.Errorf("%q", got)
	}
}
