//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The workload certificate and key are read by bin/port49 through the 12c file fence, which refuses a
// file under a group-writable directory: the host copy lives in a private directory, not in the tree.
func TestStepCAHostWorkloadFilesAreOutsideTheTree(t *testing.T) {
	dir, err := stepCAHostDir()
	if err != nil {
		t.Fatal(err)
	}
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(dir, repo+string(filepath.Separator)) {
		t.Errorf("the workload's host files go to %s, inside the tree", dir)
	}
	fi, err := os.Stat(filepath.Dir(dir))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the private root is not 0700: %v %v", fi, err)
	}
	b, err := os.ReadFile("stepca_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `hostW: filepath.Join(logs, "host-w")`) {
		t.Error("startStepCA puts hostW back under the logs directory")
	}
	if !strings.Contains(string(b), "hostW: hostDir") {
		t.Error("startStepCA does not take hostW from stepCAHostDir")
	}
}

// A workload step that exits 2, or whose stderr is the fence's or a usage refusal, never reached the broker:
// a harness error, not a measurement. The renew refusal at exit 77 is the product's answer.
func TestWorkloadHarnessFaults(t *testing.T) {
	for _, c := range []struct {
		name   string
		exit   int
		stderr string
		fault  bool
	}{
		{"fence refusal", 2, "port49 workload token: keyfile: the directory $HOME/git is mode drwxrwxr-x", true},
		{"exit 2 alone", 2, "", true},
		{"the fence text at another exit", 1, "keyfile: the directory /x is mode drwxrwxr-x", true},
		{"a usage error", 2, "port49 workload token: flag provided but not defined: -socket", true},
		{"the broker did not answer", 75, "port49 workload token: the broker did not answer", true},
		{"a wrong broker CA", 77, "port49 workload token: the broker's certificate does not verify against --broker-ca", true},
		{"the CRL answer", 77, "port49 workload token: credential_status_unavailable: 503", false},
		{"revoked", 77, "port49 workload token: credential_revoked", false},
		{"renewal late", 77, "the certificate /p/w.pem expires 2026-10-08T14:00:55Z (in 1m) with under a quarter of its validity left", false},
		{"ok", 0, "", false},
	} {
		if got := workloadHarnessFault(c.exit, c.stderr) != ""; got != c.fault {
			t.Errorf("%s: fault = %v, want %v", c.name, got, c.fault)
		}
	}
}

func TestL48RunIsInvalidOnAHarnessFaultAndWritesNothing(t *testing.T) {
	r := &l48Run{}
	r.guard("workload_identity", tokenRun{Exit: 0})
	if len(r.invalid) != 0 {
		t.Fatalf("a clean step marked the run invalid: %v", r.invalid)
	}
	r.guard("token_after_issue", tokenRun{Exit: 2, Stderr: "keyfile: the directory /x is mode drwxrwxr-x"})
	if len(r.invalid) != 1 || !strings.Contains(r.invalid[0], "token_after_issue") {
		t.Fatalf("invalid = %v", r.invalid)
	}
	b, err := os.ReadFile("l48_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	tw := s[strings.Index(s, "func (r *l48Run) tokenWith("):]
	tw = tw[:strings.Index(tw, "\n}\n")]
	if !strings.Contains(tw, "r.guard(label, tr)") {
		t.Error("tokenWith does not guard its step")
	}
	i, w := strings.Index(s, "len(r.invalid) > 0"), strings.Index(s, "body, err := r.ev.encode(")
	if i < 0 || w < 0 || i > w {
		t.Errorf("the run must check r.invalid (%d) before it encodes and writes the evidence (%d)", i, w)
	}
	if c1 := strings.Index(s, "r.cell1Issue()\n"); c1 < 0 || !strings.Contains(s[c1:c1+200], "len(r.invalid) > 0") {
		t.Error("the run does not stop on a harness fault right after cell 1")
	}
}

// The CLI prints some paths as $HOME/...; one it prints in full, or a docker error, can carry the real home
// directory, which the tree must never hold (tests/ci TestNoPersonalPathInTheTree).
func TestWorkloadOutputHasNoHomeDirectory(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || len(home) < 2 {
		t.Skip("no home directory to look for")
	}
	line := "port49 workload token: the certificate " + home + "/git/x/w.pem expired"
	if tr := newTokenRun(77, line, time.Second); strings.Contains(tr.Stderr, home) || !strings.Contains(tr.Stderr, "$HOME/git/x/w.pem") {
		t.Errorf("newTokenRun stderr = %q", tr.Stderr)
	}
	var ev stepEvidence
	ev.add("renew_revoked", map[string]string{"error": "exit 1: " + home + "/x"})
	body, err := ev.encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), home) || !strings.Contains(string(body), "$HOME/x") {
		t.Errorf("the evidence holds the home directory: %s", body)
	}
	note := workloadNote("L48", "step_ca", "claim", "saw "+home+"/y", "ev.json", "run", "v")
	if strings.Contains(note, home) {
		t.Error("the note holds the home directory")
	}
}

// The committed L48 evidence is a run that measured: every step in it, the 77s after expiry, revocation
// and the CRL's 503 among them, is the product's answer and must not trip the guard.
func TestCommittedL48EvidencePassesTheGuard(t *testing.T) {
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "tests", "lab", "evidence", "L48-step_ca.json"))
	if err != nil {
		t.Fatal(err)
	}
	var steps []struct {
		Step  string          `json:"step"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &steps); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, st := range steps {
		var tr tokenRun
		if json.Unmarshal(st.Value, &tr) != nil || !strings.HasPrefix(st.Step, "token") && st.Step != "workload_identity" {
			continue
		}
		seen++
		if why := workloadHarnessFault(tr.Exit, tr.Stderr); why != "" {
			t.Errorf("%s (exit %d) is a fault: %s", st.Step, tr.Exit, why)
		}
	}
	if seen < 5 {
		t.Errorf("only %d workload steps found in the committed evidence", seen)
	}
}
