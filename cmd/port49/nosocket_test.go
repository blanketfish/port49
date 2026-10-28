package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// Ryan's rule: no user ever types or knows a socket path. Every command finds
// its agent at the per-user default, and only a test moves it.

// subcommands is every command line that takes flags, up to the flags.
var subcommands = [][]string{
	{"login"}, {"token"}, {"refresh"}, {"identity"}, {"ssh"}, {"agent"},
	{"workload", "token"}, {"workload", "identity"},
	{"explain"}, {"policy", "test"}, {"policy", "replay"}, {"policy", "diff"},
	{"inventory", "diff"}, {"inventory", "sync"}, {"inventory", "export"}, {"inventory", "keygen"},
	{"access", "review"}, {"grants", "remove"},
	{"platform", "list"}, {"platform", "show"}, {"platform", "export"}, {"platform", "upgrade"},
	{"devices", "check-config"}, {"devices", "capabilities"},
	{"keys"}, {"store"}, {"store", "status"}, {"revoke"}, {"directory"},
}

func TestNoCommandTakesASocket(t *testing.T) {
	for _, sub := range subcommands {
		for _, flagName := range []string{"--socket", "--agent-socket"} {
			args := append(append([]string{}, sub...), flagName, "/tmp/x.sock")
			var out, errb bytes.Buffer
			if code := run(args, &out, &errb); code != 2 {
				t.Errorf("%s: code %d, want 2 (an unknown flag); stderr %q", strings.Join(args, " "), code, errb.String())
			}
		}
	}
}

func TestNoHelpNamesASocket(t *testing.T) {
	check := func(what, text string) {
		t.Helper()
		for _, word := range []string{"socket", "PORT49_TEST_AGENT_SOCKET"} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(word)) {
				t.Errorf("%s names %q:\n%s", what, word, text)
			}
		}
	}
	check("the usage text", usage)
	for _, sub := range subcommands {
		var out, errb bytes.Buffer
		run(append(append([]string{}, sub...), "-h"), &out, &errb)
		check(strings.Join(sub, " ")+" -h", out.String()+errb.String())
	}
}

func TestTheTestVariableMovesTheAgent(t *testing.T) {
	p := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(api.Identity{Principal: "alice", Method: "certificate", Fingerprint: "sha256:ab"})
	}))
	t.Setenv("PORT49_TEST_AGENT_SOCKET", p)
	var out, errb bytes.Buffer
	if code := run([]string{"identity"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "alice") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// repoRoot is the module root, two directories above this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func TestNoSocketFlagAnywhere(t *testing.T) {
	for _, problem := range socketProblems(repoRoot(t)) {
		t.Error(problem)
	}
}

// The walk finds what it is meant to: a flag in the design docs, and the test
// variable in a markdown file under internal/, each planted in a tree of its own.
func TestTheSocketWalkFindsAPlantedLine(t *testing.T) {
	root := t.TempDir()
	plant := func(rel, text string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plant("docs/design/x.md", "run port49 token --socket /tmp/a.sock\n")
	plant("internal/agent/NOTES.md", "set PORT49_TEST_AGENT_SOCKET to move it\n")
	plant("tests/lab/runbooks/ok.md", "PORT49_TEST_AGENT_SOCKET=/tmp/x o login\n")
	plant("docs/superpowers/plans/ok.md", "PORT49_TEST_AGENT_SOCKET\n")
	got := strings.Join(socketProblems(root), "\n")
	for _, want := range []string{"docs/design/x.md", "internal/agent/NOTES.md"} {
		if !strings.Contains(got, want) {
			t.Errorf("the walk missed %s; it said:\n%s", want, got)
		}
	}
	if strings.Contains(got, "runbooks") || strings.Contains(got, "superpowers") {
		t.Errorf("the walk flagged an exempt file:\n%s", got)
	}
}

// socketProblems is every place under root that names a socket flag, or the
// test variable where only tests may.
func socketProblems(root string) (problems []string) {
	exemptFile := map[string]bool{
		"cmd/port49/nosocket_test.go": true,
		"cmd/port49/admin_test.go":    true,
	}
	const exemptDir = "tests/lab/captures/"
	const runbooks = "tests/lab/runbooks/"
	const plans = "docs/superpowers/plans/"
	const ruleDoc = "docs/design/2026-08-23-policy-engine-spec.md"
	flagForms := []string{`"--socket"`, "--socket ", "--agent-socket"}
	addf := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	for _, top := range []string{"cmd", "internal", "tests", "clients", "deploy", "examples", "docs"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "__pycache__" || strings.HasPrefix(rel+"/", exemptDir) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || exemptFile[rel] || strings.HasPrefix(rel, plans) {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil || bytes.IndexByte(b, 0) >= 0 {
				return nil // unreadable, or a binary
			}
			text := string(b)
			// docs/ other than the plans is checked for the flag too, but
			// only the design docs are held to the pattern list below.
			for _, form := range flagForms {
				if rel == ruleDoc {
					break // the spec states this rule, so it names the flag it forbids
				}
				if top != "docs" && strings.Contains(text, form) || top == "docs" && strings.HasPrefix(rel, "docs/design/") &&
					strings.Contains(text, "--socket") {
					addf("%s holds %s", rel, form)
					break
				}
			}
			if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") && strings.Contains(text, "--socket") &&
				!strings.Contains(text, `"--socket"`) && !strings.Contains(text, "--socket ") && !strings.Contains(text, "--agent-socket") {
				addf("%s names --socket in a message", rel) // a message must not tell anyone to pass it
			}
			isTest := strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "tests/") || strings.Contains(rel, "/tests/")
			markdown := strings.HasSuffix(rel, ".md")
			operatorFacing := (strings.HasPrefix(rel, "deploy/") || strings.HasPrefix(rel, "examples/") ||
				strings.HasPrefix(rel, "clients/")) && !isTest
			if (operatorFacing || markdown || top == "docs") && !strings.HasPrefix(rel, runbooks) &&
				strings.Contains(text, "PORT49_TEST_AGENT_SOCKET") {
				addf("%s names PORT49_TEST_AGENT_SOCKET, which only tests set", rel)
			}
			return nil
		})
	}
	return problems
}

// The two refusals that used to tell the person to pass --socket say what to
// do without it.
func TestNoErrorNamesASocketFlag(t *testing.T) {
	// A second agent holds the login's place.
	p, _ := countingRefreshStub(t, agent.Status{Broker: "https://prod-broker.example:8443"}, http.StatusOK, api.RefreshResponse{})
	t.Setenv("PORT49_TEST_AGENT_SOCKET", p)
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"login", "--broker", "https://other.example:8443", "--cert", filepath.Join(dir, testpki.LabClientCert),
		"--key", filepath.Join(dir, testpki.LabClientKey), "--broker-ca", filepath.Join(dir, testpki.LabCA)}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "already holds the agent; run 'port49 refresh'") ||
		strings.Contains(errb.String(), "--socket") {
		t.Errorf("the second-agent refusal: code %d %q", code, errb.String())
	}

	// The askpass directory is too long.
	long := filepath.Join(filepath.Dir(privateSocket(t)), strings.Repeat("d", 120), "agent.sock")
	_, _, err := listenAskpass(long)
	if err == nil || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") || strings.Contains(err.Error(), "--socket") {
		t.Errorf("the long askpass directory: %v", err)
	}
}

// Each command that finds no agent says the same next step, and still prints
// where it looked.
func TestEveryNoAgentLineSaysWhatToDo(t *testing.T) {
	sock := privateSocket(t)
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	for _, args := range [][]string{{"identity"}, {"refresh"}, {"token", "leaf1"}, {"ssh", "leaf1"},
		{"explain", "--device", "leaf1"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 1 {
			t.Errorf("%v: code %d, stderr %q", args, code, errb.String())
			continue
		}
		line := errb.String()
		if !strings.Contains(line, "no agent at "+sock+"; start one with 'port49 login'") ||
			!strings.HasSuffix(line, ", or check that XDG_RUNTIME_DIR is the one the agent started under\n") {
			t.Errorf("%v: %q", args, line)
		}
	}
}
