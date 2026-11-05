// Package l89 holds the pure parts of lab entry L89 (spec §15): a Velero file-system backup (node
// agent) of a chart release's volumes, a deleted namespace and a restore, then a mint and a login. The
// verdicts, the files the harness hands to the object store and to Velero, and the results. The harness
// (tests/lab/l89_test.go, tag lab) measures and records; this package decides and renders, so a results
// file is built from the cells and never typed by hand.
//
// The backup holds the issuing CA's private key, and the results file is an uploaded CI artifact that
// will be public: Results refuses text that looks like a key, a PEM block or a credential, and the
// harness records only stat lines, versions, PASS or FAIL and the first characters of a fingerprint.
package l89

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/blanketfish/port49/tests/shapes/l82"
)

// Order is the cells' order in the results.
var Order = []string{"a", "b", "c", "d"}

func title(id string) string {
	return map[string]string{
		"a": "(a) back up both StatefulSets, delete the namespace, restore: ownership, mode, readiness, the CA",
		"b": "(b) after the restore, a mint and a login",
		"c": "(c) a restore with both StatefulSets at 0 replicas (the order the README measured hanging): volumes, the CA, marks.json, the spool",
		"d": "(d) the README's restore order (pods run for the volume restore, then scaled to 0): volumes, the CA, marks.json, the spool",
	}[id]
}

// Stat is one `stat -c '%a %u %g %n'` line of a volume.
type Stat struct {
	Path, Mode string
	UID, GID   int
}

func (s Stat) String() string { return fmt.Sprintf("%s %s %d:%d", s.Path, s.Mode, s.UID, s.GID) }

// Differences lists what changed between the stat lines taken before the backup and after the restore,
// one line each; a path in one list and not the other is a difference. Empty is "unchanged".
func Differences(before, after []Stat) []string {
	was := map[string]Stat{}
	for _, s := range before {
		was[s.Path] = s
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range after {
		seen[s.Path] = true
		b, ok := was[s.Path]
		switch {
		case !ok:
			out = append(out, s.Path+" is new after the restore")
		case b != s:
			out = append(out, fmt.Sprintf("%s was %s %d:%d, is %s %d:%d", s.Path, b.Mode, b.UID, b.GID, s.Mode, s.UID, s.GID))
		}
	}
	for _, s := range before {
		if !seen[s.Path] {
			out = append(out, s.Path+" is gone after the restore")
		}
	}
	return out
}

// A is cell (a)'s measurements.
type A struct {
	Ready             bool   // both StatefulSets became ready after the restore
	FenceRefusal      bool   // a pod's log holds the fence's refusal of its data directory
	FingerprintBefore string // the sha256 of the issuing CA certificate before the backup
	FingerprintAfter  string // and after the restore
	LogBefore         string // the fingerprint the broker's "issuing as" line printed before; "" when it printed none
	LogAfter          string // and after the restore
}

// JudgeA is PASS iff both StatefulSets became ready with no fence refusal and the issuing CA is the one
// it was. A fingerprint not read is a FAIL, never an equal pair of empty ones.
//
// The broker must have printed a fingerprint before the backup and print the same one after the
// restore: the spec's PASS, so a line never printed (a wrong container or pattern) is a FAIL.
func JudgeA(a A) string {
	if a.LogBefore == "" || a.LogBefore != a.LogAfter {
		return l82.Fail
	}
	if a.Ready && !a.FenceRefusal && a.FingerprintBefore != "" && a.FingerprintBefore == a.FingerprintAfter {
		return l82.Pass
	}
	return l82.Fail
}

// C is cell (c)'s and (d)'s measurements: the README's restore order, run step by step.
type C struct {
	RestorePhase      string            // the restore's phase, as the README's volume check prints it
	Volumes           map[string]string // the restore's pod volume restores, "pod/volume": phase
	Want              []string          // the chart's data volumes ("pod/volume"), each of which must be Completed
	FingerprintBefore string            // the issuing CA's sha256 before the namespace was deleted
	FingerprintAfter  string            // and after the scale-up
	Before            map[string]string // the sha256 of each file the cell compares, "claim:path", when the backup was taken ("" absent)
	AtZero            map[string]string // and after the restore, with both StatefulSets at 0, before the scale-up
	MarksBefore       map[string][]Mark // each broker's decoded marks.json, by claim, when the backup was taken
	MarksAtZero       map[string][]Mark // and with both StatefulSets at 0, before the scale-up
	// Fallback is cell (d): the brokers ran against the restored store before the check, and a broker
	// rewrites marks.json when the store and its copy disagree, so marks.json is compared by its decoded
	// marks (every one recorded before still there), not by its hash.
	Fallback  bool
	FreshCopy bool // a broker's log after the scale-up says it had no marks.json at this start
}

// FreshCopyLine is what a broker logs when it starts with no broker.state_dir/marks.json
// (internal/port49d/runner.go): after a restore, its state volume did not come back.
const FreshCopyLine = "had no marks.json at this start"

// JudgeC is PASS iff the restore Completed with a Completed pod volume restore for each of the chart's
// data volumes by name (the lab's etcd volumes are in the same restore and do not count), the issuing CA
// is the one it was, every file recorded at the backup is there with the same sha256 while both
// StatefulSets are at 0 (marks.json, in the fallback, by its marks instead), every broker held a mark at
// the backup and holds each of them at 0, and no broker started a fresh copy of the marks. A fingerprint
// or a hash not read is a FAIL.
func JudgeC(c C) string {
	if c.RestorePhase != "Completed" || len(c.Want) == 0 || len(c.Before) == 0 || len(c.MarksBefore) == 0 || c.FreshCopy {
		return l82.Fail
	}
	for _, v := range c.Want {
		if c.Volumes[v] != "Completed" {
			return l82.Fail
		}
	}
	if c.FingerprintBefore == "" || c.FingerprintBefore != c.FingerprintAfter {
		return l82.Fail
	}
	for k, h := range c.Before {
		if c.Fallback && strings.HasSuffix(k, ":"+MarksPath) {
			continue
		}
		if !sha256Hex.MatchString(h) || c.AtZero[k] != h {
			return l82.Fail
		}
	}
	for claim, before := range c.MarksBefore {
		// a broker with no mark at the backup has none to lose: the restore would prove nothing about marks
		if len(before) == 0 {
			return l82.Fail
		}
		kept := map[Mark]bool{}
		for _, m := range c.MarksAtZero[claim] {
			kept[m] = true
		}
		for _, m := range before {
			if !kept[m] {
				return l82.Fail
			}
		}
	}
	return l82.Pass
}

// Mark is one entry of broker.state_dir/marks.json (internal/port49d/markscopy.go): a revocation's kind
// and key, and when it took force, as written.
type Mark struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
	At   string `json:"at"`
}

// DecodeMarks reads marks.json. An entry it does not understand (no kind or key: a newer port49's) is
// skipped, as the copy keeps it unread; an empty body is no marks.
func DecodeMarks(body string) ([]Mark, error) {
	if strings.TrimSpace(body) == "" {
		return nil, nil
	}
	var f struct {
		Marks []json.RawMessage `json:"marks"`
	}
	if err := json.Unmarshal([]byte(body), &f); err != nil {
		return nil, fmt.Errorf("l89: marks.json does not decode: %w", err)
	}
	var out []Mark
	for _, raw := range f.Marks {
		var m Mark
		if json.Unmarshal(raw, &m) == nil && m.Kind != "" && m.Key != "" {
			out = append(out, m)
		}
	}
	return out, nil
}

// The files cells (c) and (d) compare with the backup.
const (
	// Sentinel is the file cell (a) writes in each port49d spool before the backup: the spool holds no
	// accounting record in the lab, and port49d writes restore.json there at every start, so a listing
	// of the directory cannot tell a restored spool from an empty one.
	Sentinel = "/v/data/l89-sentinel"
	// MarksPath is a broker's copy of the marks. The copy writes it only when its marks change
	// (markscopy.go), so it exists only once something was revoked.
	MarksPath = "/v/state/marks.json"
)

// Files is the paths compared on one volume claim, mounted at /v.
type Files struct {
	PVC   string
	Paths []string
}

// Hashed is the files cells (c) and (d) compare with the backup, by the kind lab's claims: each broker's
// marks.json and issuing CA certificate (never the key), and each spool's sentinel.
var Hashed = []Files{
	{"data-t-broker-0", []string{MarksPath, "/v/state/issuing-ca.pem"}},
	{"data-t-broker-1", []string{MarksPath, "/v/state/issuing-ca.pem"}},
	{"data-t-port49d-0", []string{Sentinel}},
	{"data-t-port49d-1", []string{Sentinel}},
}

// HashKeys is every "claim:path" of Hashed.
func HashKeys() []string {
	var keys []string
	for _, v := range Hashed {
		for _, p := range v.Paths {
			keys = append(keys, v.PVC+":"+p)
		}
	}
	return keys
}

func holdsMarks(f Files) bool {
	for _, p := range f.Paths {
		if p == MarksPath {
			return true
		}
	}
	return false
}

// Lab is what cell (a)'s step before the backup needs of the cluster.
type Lab interface {
	// Revoke revokes principal with revoke-offline.sh and returns once the brokers are back and ready.
	Revoke(principal string) error
	// Read is a file on a claim ("" when it is absent).
	Read(pvc, path string) string
	// WriteSentinel writes a random sentinel at path on a claim, owned by uid 65532, mode 0600.
	WriteSentinel(pvc, path string) error
	// Hashes is HashScript's result on a claim, as ParseHashes reads it.
	Hashes(pvc string, paths []string) map[string]string
	// Eventually is true once cond holds, false if it never did within the lab's time.
	Eventually(what string, cond func() bool) bool
}

// Before is what the step before the backup recorded.
type Before struct {
	Hashes map[string]string // "claim:path": sha256
	Marks  map[string][]Mark // each broker's decoded marks.json, by claim
}

// BeforeBackup is cell (a)'s step before the backup, in its order. It revokes principal, since a broker
// writes marks.json only on a change and the lab revokes nothing else, and waits until every broker's
// marks.json holds that revocation. Then it writes each spool's sentinel and hashes every file of Hashed.
// A file still absent is an error: the cells could not compare it.
func BeforeBackup(lab Lab, principal string) (Before, error) {
	b := Before{Hashes: map[string]string{}, Marks: map[string][]Mark{}}
	if err := lab.Revoke(principal); err != nil {
		return b, fmt.Errorf("l89: the revocation before the backup: %w", err)
	}
	for _, f := range Hashed {
		if !holdsMarks(f) {
			continue
		}
		var marks []Mark
		held := lab.Eventually("marks.json on "+f.PVC+" to hold "+principal, func() bool {
			marks, _ = DecodeMarks(lab.Read(f.PVC, MarksPath))
			for _, m := range marks {
				if m.Kind == "principal" && m.Key == principal {
					return true
				}
			}
			return false
		})
		if !held {
			return b, fmt.Errorf("l89: marks.json on %s never held the revocation of %s", f.PVC, principal)
		}
		b.Marks[f.PVC] = marks
	}
	for _, f := range Hashed {
		for _, p := range f.Paths {
			if p == Sentinel {
				if err := lab.WriteSentinel(f.PVC, p); err != nil {
					return b, fmt.Errorf("l89: the sentinel on %s: %w", f.PVC, err)
				}
			}
		}
	}
	for _, f := range Hashed {
		for k, h := range lab.Hashes(f.PVC, f.Paths) {
			b.Hashes[k] = h
		}
	}
	for _, k := range HashKeys() {
		if !sha256Hex.MatchString(b.Hashes[k]) {
			return b, fmt.Errorf("l89: %s is absent before the backup, so cells (c) and (d) cannot compare it", k)
		}
	}
	return b, nil
}

// StepScript is a README step as the lab runs it under bash -e: an ERR trap names the command that
// failed, so a FAIL's row can say which line of the README's text it was, and a DEBUG trap the command
// about to run, so a step stopped at its bound can say which command it was in.
func StepScript(script string) string {
	return "trap 'echo \"l89-failed: $BASH_COMMAND\" >&2' ERR\ntrap 'echo \"l89-running: $BASH_COMMAND\" >&2' DEBUG\n" + script
}

// FailedCommand is the command StepScript's ERR trap named in a step's output, for a results row: the
// README's text after Subst, through Reason (a long run as <LONG>, a line with a credential word
// withheld unless an allowed name is all that holds it).
func FailedCommand(out string) string { return trapLine(out, "l89-failed: ") }

// RunningCommand is the last command StepScript's DEBUG trap named: the one a step stopped at its bound
// was in. Shown as FailedCommand shows its own.
func RunningCommand(out string) string { return trapLine(out, "l89-running: ") }

// StepOutput is a step's output without StepScript's trap lines: what the README's command printed.
func StepOutput(out string) string {
	var keep []string
	for _, ln := range strings.Split(out, "\n") {
		if !strings.HasPrefix(ln, "l89-running: ") && !strings.HasPrefix(ln, "l89-failed: ") {
			keep = append(keep, ln)
		}
	}
	return strings.Join(keep, "\n")
}

func trapLine(out, prefix string) string {
	got := ""
	for _, ln := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(ln, prefix); ok {
			got = rest
		}
	}
	if got == "" {
		return "not named (no " + strings.TrimSuffix(prefix, ": ") + " line)"
	}
	return Reason(got)
}

// Reason is ReasonWith with no values of the run's own.
func Reason(msg string) string { return ReasonWith(msg) }

// DeleteJob is the delete Job of design §13 step 3 in the Velero README, and DeleteJobFile its example.
// The name holds no word the job log's filter drops a line for: run 42058930263 lost every line about
// the Job under its former name, its describe and logs among them.
const DeleteJob, DeleteJobFile = "restore-unspent", "restore-unspent.yaml"

// allowNames are the harness's own names that hold a word the job log's filter drops a line for: a
// port49 Secret named by its kind (run 42047911635 lost its reason to one). It is masked to <word>, and
// its line kept only when it is kubectl's own error or the harness's command line (kubectlShape), so no
// data after the name passes (m1r5e). Nothing else is masked. The step and bound names hold none
// (TestReasonKeepsASetupFailureReadable).
var allowNames = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`\bsecret(s?)( "| |/)(port49-[a-z0-9.-]+)`), "<word>$1$2$3"},
}

// kubectlShape is a line an allowed name may keep: kubectl's NotFound, Forbidden or AlreadyExists error,
// or the harness's own redacted kubectl command.
var kubectlShape = regexp.MustCompile(`^kubectl |\((NotFound|Forbidden|AlreadyExists)\)|" not found$|" is forbidden:|" already exists$`)

// keyValue is a credential word, or an allowed Secret's name, followed by : or = and a value.
var keyValue = regexp.MustCompile(`(?i)(password|token|secret)[\w-]*(\s+"?port49-[a-z0-9.-]+)?["']?\s*[:=]\s*\S`)

var printable = regexp.MustCompile(`^[\x20-\x7e\t]*$`)

// ReasonWith is a harness message as a row and a log line can both hold it. A line is dropped whole when
// it holds one of own (the run's generated values, some under Scrub's run length), a key and its value
// (keyValue), a byte the job log's filter refuses, or, once allowNames are masked, any credential word;
// the rest are Scrubbed and joined, and the whole is withheld if Leak still trips.
func ReasonWith(msg string, own ...string) string {
	var lines []string
next:
	for _, ln := range strings.Split(msg, "\n") {
		ln = strings.TrimSpace(ln)
		for _, o := range own {
			if o != "" && strings.Contains(ln, o) {
				continue next
			}
		}
		if ln == "" || keyValue.MatchString(ln) || !printable.MatchString(ln) {
			continue
		}
		for _, a := range allowNames {
			if a.re.MatchString(ln) && !kubectlShape.MatchString(ln) {
				continue next
			}
			ln = a.re.ReplaceAllString(ln, a.with)
		}
		if credWords.MatchString(ln) {
			continue
		}
		lines = append(lines, longRun.ReplaceAllString(ln, "<LONG>"))
	}
	got := strings.Join(lines, " / ")
	if got == "" || Leak(got) != "" {
		return "withheld (the line looks like it holds a credential)"
	}
	if len(got) > 400 {
		got = got[:400] + " ..."
	}
	return got
}

// JobProbe is the script the harness runs, bounded, when the README's wait for job in ns fails: the
// Job's conditions, each of its pods' phase and exit code, and the pods' last log lines. Each line is
// tagged (cond, pod, log) for JobRows; nothing is printed that JobRows does not pass through ReasonWith.
func JobProbe(ns, job string) string {
	return "kubectl -n " + ns + " get job " + job + ` -o jsonpath='{range .status.conditions[*]}cond {.type}={.status} {.reason}{"\n"}{end}'` + "\n" +
		"kubectl -n " + ns + " get pods -l job-name=" + job +
		` -o jsonpath='{range .items[*]}pod {.metadata.name} {.status.phase} {.status.containerStatuses[0].state.terminated.exitCode}{"\n"}{end}'` + "\n" +
		"kubectl -n " + ns + " logs -l job-name=" + job + " --all-containers=true --tail=10 --prefix=false | sed 's/^/log /'\n"
}

// JobRows is JobProbe's output as rows: the conditions, one row per pod, and the log lines through
// ReasonWith with the run's own values (own).
func JobRows(out string, own ...string) []l82.Row {
	var conds, logs []string
	var rows []l82.Row
	for _, ln := range strings.Split(out, "\n") {
		tag, rest, _ := strings.Cut(ln, " ")
		switch tag {
		case "cond":
			conds = append(conds, strings.TrimSpace(rest))
		case "pod":
			f := strings.Fields(rest)
			if len(f) >= 2 {
				obs := f[1]
				if len(f) == 3 {
					obs += ", exit " + f[2]
				}
				rows = append(rows, l82.Row{Case: "the delete Job's pod " + f[0], Observation: obs})
			}
		case "log":
			logs = append(logs, rest)
		}
	}
	cond := "none"
	if len(conds) > 0 {
		cond = ReasonWith(strings.Join(conds, "\n"), own...)
	}
	log := "none"
	if len(logs) > 0 {
		log = ReasonWith(strings.Join(logs, "\n"), own...)
	}
	return append([]l82.Row{{Case: "the delete Job's conditions", Observation: cond}}, append(rows,
		l82.Row{Case: "the delete Job's pods' last log lines", Observation: log})...)
}

// KubectlFailure is a failed kubectl call as a reason: the command (redacted by the caller), kubectl's
// exit, and its own stderr, unfiltered, which ReasonWith masks or drops line by line (the job filter
// would drop a NotFound naming a Secret whole, and with it the cause).
func KubectlFailure(cmd string, err error, stderr string, own ...string) string {
	return ReasonWith(cmd+"\n"+err.Error()+"\n"+stderr, own...)
}

// ParseVolumes reads the output of the README's volume check (the marker "volumes"): the restore's phase
// on the first line, then kubectl's PHASE POD VOLUME columns. It returns the phase and each pod volume
// restore as "pod/volume": phase. A line of any other shape (kubectl's "No resources found") is skipped:
// a volume missing from the map is a volume that did not come back.
func ParseVolumes(out string) (string, map[string]string) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	vols := map[string]string{}
	phase := strings.TrimSpace(lines[0])
	if strings.Contains(phase, " ") {
		phase = ""
	}
	for _, ln := range lines[1:] {
		f := strings.Fields(ln)
		if len(f) != 3 || f[0] == "PHASE" {
			continue
		}
		vols[f[1]+"/"+f[2]] = f[0]
	}
	return phase, vols
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HashScript is the debug pod's script that prints `sha256sum` of each path, or "absent <path>" for a
// path that is missing or empty.
func HashScript(paths ...string) string {
	return "for f in " + strings.Join(paths, " ") + `; do if [ -s "$f" ]; then sha256sum "$f"; else echo "absent $f"; fi; done`
}

// ParseHashes reads HashScript's output on claim's volume: "claim:path" to the sha256, "" for an absent
// path. A line of any other shape is skipped, so the path is missing from the map.
func ParseHashes(claim, out string) map[string]string {
	got := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		switch {
		case len(f) == 2 && f[0] == "absent":
			got[claim+":"+f[1]] = ""
		case len(f) == 2 && sha256Hex.MatchString(f[0]):
			got[claim+":"+f[1]] = f[0]
		}
	}
	return got
}

// The README's commands name etcd's namespace (the shipped etcd example's) and the release's, port49. The
// kind lab runs both in one namespace, so Steps puts etcd's into it; the release's is the lab's own.
const etcdNamespace = "port49-etcd"

// Steps is the Velero README's restore steps (their markers' commands) as the kind lab runs them: etcd's
// namespace replaced by the lab's ns everywhere a command names it, and the placeholders filled. It fails
// on a step whose command lacks what it replaces, so a changed README cannot run half-substituted.
func Steps(doc, ns, release, backup, restore string, brokers, port49d int) (map[string]string, error) {
	if ns != "port49" {
		return nil, fmt.Errorf("l89: the README's commands name the namespace port49, not %q", ns)
	}
	repl := map[string]map[string]string{
		"etcdrestore": {"<backup>": backup, etcdNamespace: ns},
		"deletejob":   {etcdNamespace: ns},
		"volumes":     {"<restore>": restore},
		"revoke":      {"<release>": release},
		"scaleup":     {"<release>": release, "<brokers>": fmt.Sprint(brokers), "<port49d>": fmt.Sprint(port49d)},
		"restore":     {"<restore>": restore, "<backup>": backup},
		"scalezero":   {"<release>": release},
	}
	out := map[string]string{}
	for name, r := range repl {
		cmd, err := Command(doc, name)
		if err != nil {
			return nil, err
		}
		if cmd, err = Subst(cmd, r); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = cmd
	}
	// (c)'s restore at 0 replicas, which the README no longer holds: the lab's input, ZeroReplicaRestore
	zero, err := Subst(ZeroReplicaRestore, map[string]string{"<restore>": restore, "<backup>": backup})
	if err != nil {
		return nil, fmt.Errorf("restorezero: %w", err)
	}
	out["restorezero"] = zero
	// step 1's wait for etcd, alone: the lab's etcd is restored with the release, so the restore line is
	// folded and only the wait is run
	for _, ln := range strings.Split(out["etcdrestore"], "\n") {
		if strings.HasPrefix(ln, "kubectl ") && strings.Contains(ln, " wait ") {
			out["etcdwait"] = ln + "\n"
		}
	}
	if out["etcdwait"] == "" {
		return nil, fmt.Errorf("l89: step 1 has no kubectl wait for etcd")
	}
	return out, nil
}

// ZeroReplicaRestore is cell (c)'s restore: the order the Velero README once gave, both StatefulSets
// restored at 0 replicas by the resource modifier in testdata/restore-scale-zero.yaml. L89 cell (c), run
// 42053716808, measured it hanging, and the README dropped it; (c) runs it as the measured negative.
const ZeroReplicaRestore = `kubectl -n velero create configmap restore-scale-zero --from-file=restore-scale-zero.yaml
velero restore create <restore> --from-backup <backup> --include-namespaces port49 \
  --resource-modifier-configmap restore-scale-zero --wait
`

// Recover is the README's recovery from a restore at 0 replicas (the marker "recover"), for the stuck
// restore named stuck.
func Recover(doc, stuck string) (string, error) {
	cmd, err := Command(doc, "recover")
	if err != nil {
		return "", err
	}
	return Subst(cmd, map[string]string{"<restore>": stuck})
}

// Subst replaces each key of repl in a README command. A key the command does not hold is an error, so
// a command that changed cannot run with a placeholder left in it.
func Subst(cmd string, repl map[string]string) (string, error) {
	keys := make([]string, 0, len(repl))
	for k := range repl {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.Contains(cmd, k) {
			return "", fmt.Errorf("l89: the command does not hold %q", k)
		}
		cmd = strings.ReplaceAll(cmd, k, repl[k])
	}
	return cmd, nil
}

// shippedModifier is the rule's conditions in testdata/restore-scale-zero.yaml. The kind lab runs etcd in the
// release's namespace, where the rule would also scale etcd to 0; LabModifier limits it to the release's
// two StatefulSets (named t-broker and t-port49d there), so the README's order is otherwise run as written.
const shippedModifier = "      groupResource: statefulsets.apps\n"

// LabDeleteJob is the shipped delete Job (DeleteJobFile) pointed at the lab's one namespace:
// its namespace and etcd's service names move to ns. The Secret port49-etcd-root keeps its name, which
// the lab's stack creates in ns; any other port49-etcd left is an error, so the lab never runs a Job
// that still reaches for a namespace it does not have.
func LabDeleteJob(example, ns string) (string, error) {
	out := strings.ReplaceAll(example, "port49-etcd.svc", ns+".svc")
	out = strings.ReplaceAll(out, "namespace: port49-etcd\n", "namespace: "+ns+"\n")
	if left := strings.ReplaceAll(out, "port49-etcd-root", ""); strings.Contains(left, "port49-etcd") {
		return "", fmt.Errorf("l89: the delete Job names port49-etcd in a way the lab does not rewrite")
	}
	return out, nil
}

func LabModifier(example, release string) (string, error) {
	if strings.Count(example, shippedModifier) != 1 {
		return "", fmt.Errorf("l89: the modifier does not hold %q exactly once", shippedModifier)
	}
	return strings.Replace(example, shippedModifier, shippedModifier+"      resourceNameRegex: \"^"+release+"-(broker|port49d)$\"\n", 1), nil
}

var issuingAs = regexp.MustCompile(`issuing as .* \(([^()\s]+)\), valid until `)

// FingerprintText is a logged fingerprint for the results: its first 12 characters after any
// "sha256:" prefix, or "not printed".
func FingerprintText(fp string) string {
	if fp == "" {
		return "not printed"
	}
	return Short(strings.TrimPrefix(fp, "sha256:"))
}

// LogFingerprint is the fingerprint in the last "issuing as <subject> (<fingerprint>), valid until"
// line of a broker's log, or "" when it printed none (internal/issuer).
func LogFingerprint(logs string) string {
	got := ""
	for _, ln := range strings.Split(logs, "\n") {
		if m := issuingAs.FindStringSubmatch(ln); m != nil {
			got = m[1]
		}
	}
	return got
}

// ScrubWith is Scrub that also drops each line holding one of the run's own generated values (a pod's
// log may echo the identity it was configured with, and a 20-character key is under Scrub's run length).
func ScrubWith(s string, own ...string) string {
	var keep []string
	for _, ln := range strings.Split(s, "\n") {
		hit := false
		for _, o := range own {
			if o != "" && strings.Contains(ln, o) {
				hit = true
			}
		}
		if !hit {
			keep = append(keep, ln)
		}
	}
	return Scrub(strings.Join(keep, "\n"))
}

var longRun = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
var credWords = regexp.MustCompile(`(?i)password|token|secret|eyJ`)

// Scrub is the filter every piece of diagnosis passes before it is kept: it drops each line with a
// credential word or a JWT, and replaces each run of 24 or more key characters with <LONG>.
func Scrub(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if credWords.MatchString(ln) {
			continue
		}
		out = append(out, longRun.ReplaceAllString(ln, "<LONG>"))
	}
	return strings.Join(out, "\n")
}

// The shipped example names the release's namespace and etcd's (examples/etcd); the kind lab runs both in
// one namespace (tests/kind applyExample). LabSchedule is the example with the etcd namespace folded
// into the release's, so the lab applies the file as shipped but for that. It fails on a file without
// the line it rewrites, so a changed example cannot go untested.
const shippedNamespaces = "includedNamespaces: [port49, port49-etcd]"

func LabSchedule(example string) (string, error) {
	if strings.Count(example, shippedNamespaces) != 1 {
		return "", fmt.Errorf("l89: the example does not hold %q exactly once", shippedNamespaces)
	}
	return strings.Replace(example, shippedNamespaces, "includedNamespaces: [port49]", 1), nil
}

// JudgeB is PASS iff both a mint and a login succeeded after the restore.
func JudgeB(mint, login bool) string {
	if mint && login {
		return l82.Pass
	}
	return l82.Fail
}

var markerName = regexp.MustCompile(`^[a-z]+$`)

// Command is the shell command the document marks between `<!-- l89:<name>:begin -->` and
// `<!-- l89:<name>:end -->`: the one fenced block between them, without its fence and its indent. The
// lab runs the README's own text, so a command that does not work cannot stay in it. Each marker must
// occur exactly once.
func Command(doc, name string) (string, error) {
	if !markerName.MatchString(name) {
		return "", fmt.Errorf("l89: the marker name %q", name)
	}
	begin, end := "<!-- l89:"+name+":begin -->", "<!-- l89:"+name+":end -->"
	if strings.Count(doc, begin) != 1 || strings.Count(doc, end) != 1 {
		return "", fmt.Errorf("l89: the document must hold each of %q and %q exactly once", begin, end)
	}
	i, j := strings.Index(doc, begin)+len(begin), strings.Index(doc, end)
	if j < i {
		return "", fmt.Errorf("l89: %q is before %q", end, begin)
	}
	var out []string
	indent, in, closed := "", false, false
	for _, ln := range strings.Split(doc[i:j], "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case !in && strings.HasPrefix(t, "```sh"):
			in, indent = true, ln[:len(ln)-len(strings.TrimLeft(ln, " "))]
		case in && t == "```":
			in, closed = false, true
		case in:
			out = append(out, strings.TrimPrefix(ln, indent))
		}
	}
	if !closed || len(out) == 0 {
		return "", fmt.Errorf("l89: no closed sh block between the markers for %q", name)
	}
	return strings.Join(out, "\n") + "\n", nil
}

const backupPlaceholder = "<the backup's name>"

// Fill names the backup in a command that holds the README's placeholder, exactly once.
func Fill(cmd, backup string) (string, error) {
	if strings.Count(cmd, backupPlaceholder) != 1 || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(backup) {
		return "", fmt.Errorf("l89: the command holds %q %d times, or the backup name %q", backupPlaceholder, strings.Count(cmd, backupPlaceholder), backup)
	}
	return strings.Replace(cmd, backupPlaceholder, backup, 1), nil
}

var imageDigest = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// ImageDigest is the sha256 digest in an image reference or a pod's imageID, or "" when it has none.
func ImageDigest(ref string) string { return imageDigest.FindString(ref) }

// CheckDigest is nil iff there is at least one imageID and every one carries the pinned digest: the image
// that ran is the image that was pinned. A different digest, an imageID with none, no imageID and an empty
// or malformed pin are errors, never a pass.
func CheckDigest(what string, imageIDs []string, pinned string) error {
	if ImageDigest(pinned) != pinned || pinned == "" {
		return fmt.Errorf("l89: the pinned digest of %s is %q", what, pinned)
	}
	if len(imageIDs) == 0 {
		return fmt.Errorf("l89: no running container of %s to check against the pinned digest %s", what, pinned)
	}
	for _, id := range imageIDs {
		if ImageDigest(id) != pinned {
			return fmt.Errorf("l89: a running container of %s is %q, not the pinned digest %s", what, id, pinned)
		}
	}
	return nil
}

// Short is the first characters of a fingerprint, enough to compare and too short to be a key.
func Short(fp string) string {
	if len(fp) < 12 {
		return "not read"
	}
	return fp[:12]
}

// Random is n random bytes as hex: a per-run credential, never printed.
func Random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var hexOnly = regexp.MustCompile(`^[0-9a-f]{16,128}$`)

func checkCred(id, secret string) error {
	if !hexOnly.MatchString(id) || !hexOnly.MatchString(secret) {
		return fmt.Errorf("l89: a credential is not lowercase hex of 16 to 128 characters")
	}
	return nil
}

// AWSCredentials is the credentials file Velero's AWS plugin reads (velero install --secret-file). The
// harness writes it 0600 and never prints it.
func AWSCredentials(id, secret string) (string, error) {
	if err := checkCred(id, secret); err != nil {
		return "", err
	}
	return "[default]\naws_access_key_id=" + id + "\naws_secret_access_key=" + secret + "\n", nil
}

// StoreConfig is the object store's identity file: one identity with the credentials, all actions.
func StoreConfig(id, secret string) (string, error) {
	if err := checkCred(id, secret); err != nil {
		return "", err
	}
	return `{"identities":[{"name":"velero","credentials":[{"accessKey":"` + id + `","secretKey":"` + secret +
		`"}],"actions":["Admin","Read","Write","List","Tagging"]}]}` + "\n", nil
}

// CurlConfig is a curl config file (curl -K) that makes the bucket with a signed request, so the
// credentials are in a 0600 file and never in curl's arguments.
func CurlConfig(id, secret, url, region string) (string, error) {
	if err := checkCred(id, secret); err != nil {
		return "", err
	}
	if !regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+/[a-z0-9-]+$`).MatchString(url) || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(region) {
		return "", fmt.Errorf("l89: the bucket URL or region")
	}
	return "silent\nshow-error\nfail\nmax-time = 10\nrequest = \"PUT\"\nurl = \"" + url + "\"\nuser = \"" + id + ":" + secret + "\"\naws-sigv4 = \"aws:amz:" + region + ":s3\"\n", nil
}

// Env is what the results record about the run.
type Env struct {
	Date, Runner, Run, Docker, Kernel, Kind, NodeImage, Kubectl, Helm string
	Velero, VeleroImage, AWSPlugin, ObjectStore, VolumeBackups        string
}

func nz(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return s
}

// img renders an image reference with its path separators spaced: "velero/velero-plugin-for-aws" is a
// run of 28 key characters to Leak, and the digest after it is replaced by Leak, not shortened.
func img(s string) string { return strings.ReplaceAll(s, "/", " / ") }

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func verdict(cells []l82.Cell, id string) string {
	for _, c := range cells {
		if c.ID == id && c.Verdict != "" {
			return c.Verdict
		}
	}
	return l82.NotRun
}

// Leak is why text must not be written: what l82.Leak refuses (24 or more key characters, a JWT, the
// words for a credential), and a PEM block. Empty when the text is clean.
func Leak(s string) string {
	if strings.Contains(s, "-----BEGIN") || strings.Contains(s, "-----END") || strings.Contains(s, "PRIVATE KEY") {
		return "a PEM block"
	}
	return l82.Leak(s)
}

// Results is the results file for the CI artifact, built from cells and nothing else. It fails,
// writing nothing, on a cell it does not know or if any text in it looks like a key. A cell never run
// is NOT RUN, which the harness fails on.
func Results(env Env, cells []l82.Cell) (string, error) {
	known := map[string]bool{}
	for _, id := range Order {
		known[id] = true
	}
	for _, c := range cells {
		if !known[c.ID] {
			return "", fmt.Errorf("l89: a cell %q that is not one of the entry's", c.ID)
		}
	}
	var b strings.Builder
	b.WriteString("# L89: a Velero file-system backup of a chart release's volumes, restored (kind)\n\n")
	b.WriteString("Generated by `make lab-l89` (tests/lab/l89_test.go) from the cells below; edit the harness, not this file.\n\n")
	b.WriteString("The backup holds `state/issuing-ca.key` (the issuing CA's private key), each broker's state and each port49d's accounting spool. The bucket alone also holds the namespaces' Secrets as Velero reads them, in the clear: the TACACS+ keys, the store's encryption key, the etcd client identities and the TLS key. The repository key protects only the volumes.\n\nThe lab's etcd shares the release's namespace; the example Schedule names the release's namespace and the shipped etcd example's.\n\n")
	fmt.Fprintf(&b, "- Date: %s\n- Platform: %s\n- Run: %s\n- Docker: %s\n- Kernel: %s\n- kind: %s\n- Node image: %s\n- kubectl: %s\n- helm: %s\n- Velero client: %s\n- Velero server and node agent image: %s\n- Velero AWS plugin image: %s\n- Object store image: %s\n- Pod volume backups completed: %s\n\n",
		nz(env.Date), nz(env.Runner), nz(env.Run), nz(env.Docker), nz(env.Kernel), nz(env.Kind), nz(env.NodeImage), nz(env.Kubectl), nz(env.Helm),
		nz(env.Velero), nz(img(env.VeleroImage)), nz(img(env.AWSPlugin)), nz(img(env.ObjectStore)), nz(env.VolumeBackups))
	b.WriteString("## Verdicts\n\n| Cell | Verdict |\n|---|---|\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "| %s | %s |\n", title(id), verdict(cells, id))
	}
	b.WriteString("\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "## %s: %s\n\n", title(id), verdict(cells, id))
		var rows []l82.Row
		for _, c := range cells {
			if c.ID == id {
				rows = c.Rows
			}
		}
		if len(rows) == 0 {
			b.WriteString("No observation.\n\n")
			continue
		}
		b.WriteString("| Case | Observation |\n|---|---|\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "| %s | %s |\n", cell(r.Case), cell(r.Observation))
		}
		b.WriteString("\n")
	}
	b.WriteString("The register row closes only when every cell has a PASS or a FAIL; a FAIL is a measured answer.\n")
	out := b.String()
	if why := Leak(out); why != "" {
		return "", fmt.Errorf("l89: the results hold %s: nothing is written", why)
	}
	return out, nil
}
