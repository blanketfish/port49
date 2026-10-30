// Package l82 holds the pure parts of lab entry L82 (spec §15): Kubernetes Secret volumes as
// port49d's key directory, on kind. The verdict rules, the results file and the check that nothing
// in it looks like a key. The harness (tests/lab/l82_test.go, tag lab) measures and records; this
// package decides and renders, so a results file is built from the cells and never typed by hand.
//
// The results file is an uploaded CI artifact and will be public: it holds stat lines, delays,
// PASS or FAIL and versions, and Results refuses any text that looks like a key, a token or a
// password.
package l82

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Verdicts a cell can end with.
const (
	Pass   = "PASS"
	Fail   = "FAIL"
	NotRun = "NOT RUN"
)

// The bounds of spec §15 L82.
const (
	// WholeMountWithin is (b): a key added to the Secret reaches a whole-volume mount.
	WholeMountWithin = 180 * time.Second
	// SubPathWait is (c): how long after the update the subPath file is compared.
	SubPathWait = 180 * time.Second
	// ESOWithin is (d): a version added to the ExternalSecret is in force, with no restart.
	ESOWithin = 240 * time.Second
)

// Row is one observation of a cell.
type Row struct{ Case, Observation string }

// Cell is one cell of L82: "a", "b", "c" or "d".
type Cell struct {
	ID, Verdict string
	Rows        []Row
}

// Env is what the results record about the run.
type Env struct {
	Date, Runner, Docker, Kernel, Kind, NodeImage, Kubectl, Helm, ESOChart, ESOApp, Run string
}

// Order is the cells' order in the results.
var Order = []string{"a", "b", "c", "d"}

func title(id string) string {
	return map[string]string{
		"a": "(a) the key directory's owner, group and mode; port49d starts with the key",
		"b": "(b) a key added to the Secret reaches a whole-volume mount",
		"c": "(c) a subPath mount does not see the update, the whole mount does",
		"d": "(d) an ExternalSecret's added version is in force with no restart",
	}[id]
}

// JudgeStart is (a): port49d starts with the key, which is fence.ReadSecret accepting it. The pod
// is Ready and its container never restarted.
func JudgeStart(ready bool, restarts int) string {
	if ready && restarts == 0 {
		return Pass
	}
	return Fail
}

// JudgeWholeMountDelay is (b): the file appeared, within WholeMountWithin.
func JudgeWholeMountDelay(appeared bool, d time.Duration) string {
	if appeared && d <= WholeMountWithin {
		return Pass
	}
	return Fail
}

// JudgeSubPath is (c): PASS iff the whole mount changed and the subPath file did not, which
// confirms "never subPath".
func JudgeSubPath(wholeChanged, subPathChanged bool) string {
	if wholeChanged && !subPathChanged {
		return Pass
	}
	return Fail
}

// ESOResult is what cell (d) saw.
type ESOResult struct {
	SecretGained bool          // the Secret gained the version's key
	LoginPassed  bool          // a login keyed with the new version passed
	Delay        time.Duration // from the ExternalSecret's edit to that login
	Restarted    bool          // port49d's container restarted, or its start time changed
}

// JudgeESO is (d).
func JudgeESO(r ESOResult) string {
	if r.SecretGained && r.LoginPassed && !r.Restarted && r.Delay <= ESOWithin {
		return Pass
	}
	return Fail
}

// StatLine normalises one line of `stat -c '%U %G %a %F %n'`: owner:group, a four-digit mode, the
// file type and the name.
func StatLine(line string) (string, error) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return "", fmt.Errorf("l82: not a stat line: %d fields", len(f))
	}
	mode, err := strconv.ParseUint(f[2], 8, 16)
	if err != nil {
		return "", fmt.Errorf("l82: not a stat line: the mode is not octal")
	}
	return fmt.Sprintf("%s:%s %04o %s", f[0], f[1], mode, strings.Join(f[3:], " ")), nil
}

// Save writes cells as JSON to path (mode 0644: the file is uploaded as evidence).
func Save(path string, cells []Cell) error {
	b, err := json.MarshalIndent(cells, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Load reads what Save wrote.
func Load(path string) ([]Cell, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cells []Cell
	if err := json.Unmarshal(b, &cells); err != nil {
		return nil, err
	}
	return cells, nil
}

func find(cells []Cell, id string) *Cell {
	for i := range cells {
		if cells[i].ID == id {
			return &cells[i]
		}
	}
	return nil
}

var (
	digest  = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	longRun = regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`)
	words   = regexp.MustCompile(`(?i)password|token|eyj`)
)

// Leak is why text must not be written to the results: a run of 24 or more key characters (an
// image digest is not one), or password, token or eyJ (a JWT). "Secret" is not on the list: the results name the Secret. Empty when the text is clean.
func Leak(s string) string {
	s = digest.ReplaceAllString(s, "sha256:<digest>")
	if longRun.MatchString(s) {
		return "a run of 24 or more key characters"
	}
	if w := words.FindString(s); w != "" {
		return "the word " + strconv.Quote(strings.ToLower(w))
	}
	return ""
}

// Results is the results file for the CI artifact, built from cells and nothing else. It fails,
// writing nothing, if any text in it looks like a key.
func Results(env Env, cells []Cell) (string, error) {
	var b strings.Builder
	b.WriteString("# L82: Kubernetes Secret volumes as port49d's key directory, on kind\n\n")
	b.WriteString("Generated by `make lab-l82` (tests/lab/l82_test.go) from the cells below; edit the harness, not this file.\n\n")
	fmt.Fprintf(&b, "- Date: %s\n- Platform: GitHub-hosted runner, %s\n- Run: %s\n- Docker: %s\n- Kernel: %s\n- kind: %s\n- Node image: %s\n- kubectl: %s\n- helm: %s\n- External Secrets Operator: chart %s, app %s\n\n",
		nz(env.Date), nz(env.Runner), nz(env.Run), nz(env.Docker), nz(env.Kernel), nz(env.Kind), nz(env.NodeImage), nz(env.Kubectl), nz(env.Helm), nz(env.ESOChart), nz(env.ESOApp))
	b.WriteString("## Verdicts\n\n| Cell | Verdict |\n|---|---|\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "| %s | %s |\n", title(id), verdict(cells, id))
	}
	b.WriteString("\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "## %s: %s\n\n", title(id), verdict(cells, id))
		c := find(cells, id)
		if c == nil || len(c.Rows) == 0 {
			b.WriteString("No observation.\n\n")
			continue
		}
		b.WriteString("| Case | Observation |\n|---|---|\n")
		for _, r := range c.Rows {
			fmt.Fprintf(&b, "| %s | %s |\n", cell(r.Case), cell(r.Observation))
		}
		b.WriteString("\n")
	}
	b.WriteString("The register row closes only when every cell has a PASS or a FAIL; a FAIL is a measured answer.\n")
	out := b.String()
	if why := Leak(out); why != "" {
		return "", fmt.Errorf("l82: the results hold %s: nothing is written", why)
	}
	return out, nil
}

func verdict(cells []Cell, id string) string {
	if c := find(cells, id); c != nil && c.Verdict != "" {
		return c.Verdict
	}
	return NotRun
}

func nz(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return s
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

// ExternalSecretFromExample is the ExternalSecret of the shipped example
// (deploy/helm/port49/examples/external-secret.yaml) as JSON, with its store's name replaced by
// store and nothing else changed, so that cell (d) measures what an operator copies, creationPolicy:
// Owner included. With withV2 false the core_v2 entry is left out: the first phase, which the
// second (the whole example) adds to. It refuses an example that is not a namespaced-store
// ExternalSecret with core_v1 and core_v2 entries.
func ExternalSecretFromExample(example []byte, store string, withV2 bool) ([]byte, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(example)))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("l82: the example holds no ExternalSecret")
		}
		if doc["kind"] != "ExternalSecret" {
			continue
		}
		spec, _ := doc["spec"].(map[string]any)
		ref, _ := spec["secretStoreRef"].(map[string]any)
		data, _ := spec["data"].([]any)
		if ref == nil || ref["kind"] != "SecretStore" {
			return nil, fmt.Errorf("l82: the example's store is not a namespaced SecretStore")
		}
		var keep []any
		var v1, v2 bool
		for _, d := range data {
			k, _ := d.(map[string]any)["secretKey"].(string)
			v1, v2 = v1 || k == "core_v1", v2 || k == "core_v2"
			if k != "core_v2" || withV2 {
				keep = append(keep, d)
			}
		}
		if !v1 || !v2 {
			return nil, fmt.Errorf("l82: the example's data lacks core_v1 or core_v2")
		}
		ref["name"], spec["data"] = store, keep
		return json.Marshal(doc)
	}
}
