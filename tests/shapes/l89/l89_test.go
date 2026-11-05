package l89

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blanketfish/port49/tests/shapes/l82"
	"gopkg.in/yaml.v3"
)

func TestL89ResultsNeedEveryCell(t *testing.T) {
	out, err := Results(Env{Date: "2026-11-04"}, []l82.Cell{{ID: "a", Verdict: l82.Pass}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "NOT RUN") || !strings.Contains(out, "2026-11-04") || !strings.Contains(out, "not recorded") {
		t.Errorf("the cell never run is not NOT RUN, or the environment is not rendered:\n%s", out)
	}
	if strings.Count(out, "NOT RUN") != 6 {
		t.Errorf("one cell never run should read NOT RUN twice (the table and its heading):\n%s", out)
	}
	if _, err := Results(Env{}, []l82.Cell{{ID: "z"}}); err == nil {
		t.Error("a cell the entry does not have is accepted")
	}
}

func TestL89ResultsHoldNoKeyMaterial(t *testing.T) {
	for name, obs := range map[string]string{
		"a PEM block":         "-----BEGIN EC PRIVATE KEY-----",
		"a JWT":               "eyJhbGciOiJFUzI1NiJ9.e30.sig",
		"a base64 run":        strings.Repeat("Ab3+", 12),
		"a 40 character run":  strings.Repeat("a", 40),
		"the credential word": "the password is hunter2",
	} {
		c := l82.Cell{ID: "a", Verdict: l82.Pass, Rows: []l82.Row{{Case: "x", Observation: obs}}}
		if _, err := Results(Env{}, []l82.Cell{c}); err == nil {
			t.Errorf("%s in a row is written", name)
		}
	}
	// what the harness does write is accepted: stat lines, a short fingerprint, an image by digest
	ok := l82.Cell{ID: "a", Verdict: l82.Pass, Rows: []l82.Row{
		{Case: "state/issuing-ca.key", Observation: Stat{"/v/state/issuing-ca.key", "600", 65532, 65532}.String()},
		{Case: "the CA fingerprint", Observation: Short(strings.Repeat("ab12", 16)) + " before and after"},
	}}
	env := Env{VeleroImage: "velero/velero:v1.18.4@sha256:" + strings.Repeat("c8", 32),
		AWSPlugin: "velero/velero-plugin-for-aws:v1.14.4@sha256:" + strings.Repeat("c8", 32), ObjectStore: "chrislusf/seaweedfs:4.52@sha256:" + strings.Repeat("57", 32)}
	if _, err := Results(env, []l82.Cell{ok}); err != nil {
		t.Errorf("an ordinary row: %v", err)
	}
}

func TestVerdicts(t *testing.T) {
	good := A{Ready: true, FingerprintBefore: "ab", FingerprintAfter: "ab", LogBefore: "x", LogAfter: "x"}
	if JudgeA(good) != l82.Pass {
		t.Error("a ready restore with the same CA is not a PASS")
	}
	for name, a := range map[string]A{
		"not ready":       {Ready: false, FingerprintBefore: "ab", FingerprintAfter: "ab", LogBefore: "x", LogAfter: "x"},
		"a fence refusal": {Ready: true, FenceRefusal: true, FingerprintBefore: "ab", FingerprintAfter: "ab", LogBefore: "x", LogAfter: "x"},
		"a different CA":  {Ready: true, FingerprintBefore: "ab", FingerprintAfter: "cd", LogBefore: "x", LogAfter: "x"},
		"no fingerprint":  {Ready: true},
	} {
		if JudgeA(a) != l82.Fail {
			t.Errorf("%s is not a FAIL", name)
		}
	}
	if JudgeB(true, true) != l82.Pass || JudgeB(true, false) != l82.Fail || JudgeB(false, true) != l82.Fail {
		t.Error("cell (b) needs a mint and a login")
	}
}

func TestDifferences(t *testing.T) {
	a := []Stat{{"/v/state", "700", 65532, 65532}, {"/v/state/issuing-ca.key", "600", 65532, 65532}}
	if d := Differences(a, a); len(d) != 0 {
		t.Errorf("the same lines differ: %v", d)
	}
	b := []Stat{{"/v/state", "700", 0, 0}}
	d := strings.Join(Differences(a, b), "\n")
	if !strings.Contains(d, "/v/state was 700 65532:65532, is 700 0:0") || !strings.Contains(d, "issuing-ca.key is gone") {
		t.Errorf("differences: %q", d)
	}
}

func TestCredentialFiles(t *testing.T) {
	id, secret := strings.Repeat("a1", 10), strings.Repeat("b2", 16)
	aws, err := AWSCredentials(id, secret)
	if err != nil || !strings.HasPrefix(aws, "[default]\n") || !strings.Contains(aws, "aws_secret_access_key="+secret) {
		t.Errorf("aws credentials: %q, %v", aws, err)
	}
	for _, f := range []func() (string, error){
		func() (string, error) { return AWSCredentials("short", secret) },
		func() (string, error) { return StoreConfig(id, "has space and \"quote") },
		func() (string, error) { return CurlConfig(id, secret, "http://example.com/b", "r") },
	} {
		if _, err := f(); err == nil {
			t.Error("a bad credential or URL is accepted")
		}
	}
	c, err := CurlConfig(id, secret, "http://127.0.0.1:9999/bucket", "us-east-1")
	if err != nil || strings.Contains(c, "\n\n") || !strings.Contains(c, "show-error") || !strings.Contains(c, `user = "`+id+":"+secret+`"`) {
		t.Errorf("curl config: %q, %v", c, err)
	}
	r1, _ := Random(16)
	r2, _ := Random(16)
	if len(r1) != 32 || r1 == r2 {
		t.Error("Random is not 32 hex characters, or repeats")
	}
}

// the example is the repository's own file: tests run in tests/shapes/l89
func example(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheVeleroExampleBacksUpBothStatefulSets(t *testing.T) {
	var sch struct {
		Kind string `yaml:"kind"`
		Spec struct {
			SkipImmediately bool           `yaml:"skipImmediately"`
			Template        map[string]any `yaml:"template"`
		} `yaml:"spec"`
	}
	text := example(t, "schedule.yaml")
	if err := yaml.Unmarshal([]byte(text), &sch); err != nil {
		t.Fatal(err)
	}
	tpl := sch.Spec.Template
	if sch.Kind != "Schedule" {
		t.Errorf("kind %q", sch.Kind)
	}
	if tpl["defaultVolumesToFsBackup"] != true {
		t.Error("the Schedule does not back volumes up by file system (defaultVolumesToFsBackup: true)")
	}
	// the whole namespaces, never a label selector: the Secrets, ConfigMaps and etcd would be left out
	for _, k := range []string{"labelSelector", "orLabelSelectors"} {
		if _, ok := tpl[k]; ok {
			t.Errorf("the template has %s: a restore without the Secrets and etcd starts nothing", k)
		}
	}
	ns, _ := tpl["includedNamespaces"].([]any)
	if len(ns) != 2 || ns[0] != "port49" || ns[1] != "port49-etcd" {
		t.Errorf("includedNamespaces %v, want the release's and the shipped etcd example's", ns)
	}
	if !sch.Spec.SkipImmediately {
		t.Error("applying the file starts a backup at once")
	}
}

func TestTheVeleroExampleSaysWhatItHolds(t *testing.T) {
	text := example(t, "schedule.yaml")
	for _, c := range []string{"component=broker", "component=port49d"} {
		if !strings.Contains(text, "app.kubernetes.io/name=port49") || !strings.Contains(text, c) {
			t.Errorf("the example does not name the %s volumes' labels", c)
		}
	}
	readme := example(t, "README.md")
	for _, f := range []string{text, readme} {
		for _, want := range []string{"issuing-ca.key", "TACACS+ keys", "Read access to the bucket is enough", "BEFORE"} {
			if !strings.Contains(f, want) {
				t.Errorf("a file lacks %q", want)
			}
		}
		if strings.Contains(f, "when the Secret is absent") {
			t.Error("a file says the default is used when the Secret is absent: Velero writes it into the Secret")
		}
	}
}

func TestTheVeleroExampleNamesARepositoryPassword(t *testing.T) {
	text, readme := example(t, "schedule.yaml"), example(t, "README.md")
	for _, f := range []string{text, readme} {
		if !strings.Contains(f, "velero-repo-credentials") || !strings.Contains(f, "repository-password") {
			t.Error("a file does not name the Secret velero-repo-credentials and its key repository-password")
		}
	}
	lower := strings.ToLower(readme)
	for what, want := range map[string]string{
		"that the backup holds the CA key, the broker state and the spool": "the backup holds `issuing-ca.key`",
		"the broker state":  "broker state",
		"the spool":         "accounting spool",
		"bucket encryption": "must be encrypted",
		"access limited to the backup's own credentials": "limited to the backup's own credentials",
		"the order, Secret before install":               "created before velero is installed",
		"the order, Secret before the Schedule":          "apply `schedule.yaml` only after step 1",
		"the well-known default":                         "well-known static value",
	} {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Errorf("the README does not state %s (%q)", what, want)
		}
	}
	if strings.Contains(readme, "--from-literal") || strings.Contains(readme, "static-passw0rd") {
		t.Error("the README puts a password on a command line or names the default as a value")
	}
}

func TestBrokerLogFingerprintMustMatch(t *testing.T) {
	a := A{Ready: true, FingerprintBefore: "ab", FingerprintAfter: "ab", LogBefore: "SHA256:xyz", LogAfter: "SHA256:xyz"}
	if JudgeA(a) != l82.Pass {
		t.Error("the same logged fingerprint is not a PASS")
	}
	a.LogAfter = "SHA256:other"
	if JudgeA(a) != l82.Fail {
		t.Error("a different logged fingerprint is not a FAIL")
	}
	a.LogAfter = ""
	if JudgeA(a) != l82.Fail {
		t.Error("a fingerprint printed before and not after is not a FAIL")
	}
	a.LogBefore, a.LogAfter = "", ""
	if JudgeA(a) != l82.Fail {
		t.Error("a broker that printed no fingerprint before the backup is not a FAIL: the spec's PASS needs it")
	}
	if FingerprintText("sha256:abcdef0123456789") != "abcdef012345" || FingerprintText("") != "not printed" {
		t.Errorf("FingerprintText: %q, %q", FingerprintText("sha256:abcdef0123456789"), FingerprintText(""))
	}
	logs := "x\nissuance: issuing as CN=port49 (lab) (SHA256:abc), valid until 2027-01-01\n"
	if got := LogFingerprint(logs); got != "SHA256:abc" {
		t.Errorf("LogFingerprint = %q", got)
	}
	if LogFingerprint("nothing here") != "" {
		t.Error("a log with no line gives a fingerprint")
	}
}

func TestScrubDropsCredentialLinesAndLongRuns(t *testing.T) {
	in := "ok line\nthe password is x\nSecret thing\nBearer eyJhbGci\nkey " + strings.Repeat("a", 30) + " end\n"
	got := Scrub(in)
	if strings.Contains(got, "password") || strings.Contains(got, "Secret") || strings.Contains(got, "eyJ") || strings.Contains(got, strings.Repeat("a", 24)) {
		t.Errorf("not scrubbed: %q", got)
	}
	if !strings.Contains(got, "ok line") || !strings.Contains(got, "key <LONG> end") {
		t.Errorf("over-scrubbed: %q", got)
	}
}

func TestLabSchedulePutsEtcdInTheReleaseNamespace(t *testing.T) {
	got, err := LabSchedule(example(t, "schedule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "includedNamespaces: [port49]\n") || strings.Contains(got, "port49-etcd]") {
		t.Errorf("not folded:\n%s", got)
	}
	if _, err := LabSchedule("includedNamespaces: [port49]"); err == nil {
		t.Error("a file without the shipped line is accepted")
	}
}

func TestL89ResultsSayWhatTheBucketHolds(t *testing.T) {
	out, err := Results(Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"issuing-ca.key", "in the clear", "TACACS+ keys", "protects only the volumes"} {
		if !strings.Contains(out, want) {
			t.Errorf("the results do not say %q", want)
		}
	}
}

func readme(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCommandExtractsTheMarkedBlock(t *testing.T) {
	doc := "x\n  <!-- l89:one:begin -->\n  ```sh\n  a \\\n    b\n  ```\n  <!-- l89:one:end -->\ny ```sh\nz\n```\n"
	got, err := Command(doc, "one")
	if err != nil || got != "a \\\n  b\n" {
		t.Errorf("Command = %q, %v", got, err)
	}
	for name, d := range map[string]string{
		"no markers": "```sh\na\n```\n",
		"no block":   "<!-- l89:one:begin -->\ntext\n<!-- l89:one:end -->",
		"unclosed":   "<!-- l89:one:begin -->\n```sh\na\n<!-- l89:one:end -->",
		"twice":      doc + doc,
		"end first":  "<!-- l89:one:end -->\n```sh\na\n```\n<!-- l89:one:begin -->",
	} {
		if _, err := Command(d, "one"); err == nil {
			t.Errorf("%s is accepted", name)
		}
	}
	if _, err := Command(doc, "o ne"); err == nil {
		t.Error("a marker name with a space is accepted")
	}
}

func TestTheREADMEsCheckCommandsAreMarkedAndRunnable(t *testing.T) {
	doc := readme(t)
	host, err := Command(doc, "hostpath")
	if err != nil || !strings.Contains(host, "kubectl get pv") || !strings.Contains(host, "hostPath") {
		t.Fatalf("hostpath: %q, %v", host, err)
	}
	claims, err := Command(doc, "claims")
	if err != nil || !strings.Contains(claims, "podvolumebackups") || !strings.Contains(claims, "comm -23") {
		t.Fatalf("claims: %q, %v", claims, err)
	}
	filled, err := Fill(claims, "l89-backup")
	if err != nil || !strings.Contains(filled, "backup=l89-backup\n") || strings.Contains(filled, "<the backup") {
		t.Errorf("Fill: %q, %v", filled, err)
	}
	if _, err := Fill(host, "l89-backup"); err == nil {
		t.Error("Fill accepts a command with no placeholder")
	}
	if _, err := Fill(claims, "Bad Name"); err == nil {
		t.Error("Fill accepts a bad backup name")
	}
}

func TestCheckDigest(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	other := "sha256:" + strings.Repeat("cd", 32)
	if err := CheckDigest("x", []string{"docker.io/velero/velero@" + d, "docker.io/velero/velero@" + d}, d); err != nil {
		t.Errorf("every imageID matching: %v", err)
	}
	for name, ids := range map[string][]string{"a different digest": {"r@" + other}, "no imageID": nil, "no digest in it": {"r:latest"},
		"one of two different": {"r@" + d, "r@" + other}} {
		if CheckDigest("x", ids, d) == nil {
			t.Errorf("%s passes", name)
		}
	}
	if CheckDigest("x", []string{"r@" + d}, "") == nil || CheckDigest("x", []string{"r@" + d}, "v1") == nil {
		t.Error("an empty or malformed pin passes")
	}
}

func TestScrubWithDropsTheRunsOwnValues(t *testing.T) {
	got := ScrubWith("fine\nidentity ab12cd34ef56ab12cd34 loaded\nalso fine", "ab12cd34ef56ab12cd34")
	if strings.Contains(got, "ab12cd34") || !strings.Contains(got, "fine") || !strings.Contains(got, "also fine") {
		t.Errorf("ScrubWith: %q", got)
	}
	if got := ScrubWith("a line", ""); got != "a line" {
		t.Errorf("an empty own value drops lines: %q", got)
	}
}

var bob = Mark{Kind: "principal", Key: "user:bob@example.com", At: "2026-11-05T00:00:00Z"}

// fakeLab is the lab as cell (a)'s step before the backup sees it, with markscopy.go's behaviour: a
// broker's marks.json is written only when its set of marks changes, so it is absent until a revocation.
type fakeLab struct {
	files     map[string]string // "claim:path": content
	revoked   []string
	revokeErr error
	noCopy    bool // the revocation lands but no broker's copy writes it
	calls     []string
}

func newFakeLab() *fakeLab {
	f := &fakeLab{files: map[string]string{}}
	for _, v := range Hashed {
		if strings.HasPrefix(v.PVC, "data-t-broker") {
			f.files[v.PVC+":/v/state/issuing-ca.pem"] = "a certificate"
		}
	}
	return f
}

func (f *fakeLab) Revoke(principal string) error {
	f.calls = append(f.calls, "revoke")
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked = append(f.revoked, principal)
	if !f.noCopy {
		for _, v := range Hashed {
			if strings.HasPrefix(v.PVC, "data-t-broker") {
				f.files[v.PVC+":"+MarksPath] = `{"marks":[{"kind":"principal","key":"` + principal + `","at":"2026-11-05T00:00:00Z"}]}`
			}
		}
	}
	return nil
}

func (f *fakeLab) Read(pvc, path string) string { return f.files[pvc+":"+path] }

func (f *fakeLab) WriteSentinel(pvc, path string) error {
	f.calls = append(f.calls, "sentinel")
	f.files[pvc+":"+path] = "random"
	return nil
}

func (f *fakeLab) Hashes(pvc string, paths []string) map[string]string {
	f.calls = append(f.calls, "hash")
	got := map[string]string{}
	for _, p := range paths {
		got[pvc+":"+p] = ""
		if b := f.files[pvc+":"+p]; b != "" {
			got[pvc+":"+p] = fmt.Sprintf("%x", sha256.Sum256([]byte(b)))
		}
	}
	return got
}

func (f *fakeLab) Eventually(what string, cond func() bool) bool { return cond() }

// I1r4: cell (a)'s step before the backup, run in its own order against a lab that makes marks.json only
// on a change. Before the round 5 fix the step hashed with no revocation, and marks.json was absent.
func TestBeforeBackupRevokesSoMarksJSONExists(t *testing.T) {
	lab := newFakeLab()
	got, err := BeforeBackup(lab, bob.Key)
	if err != nil {
		t.Fatal(err)
	}
	if len(lab.revoked) != 1 || lab.revoked[0] != bob.Key || lab.calls[0] != "revoke" {
		t.Errorf("the step did not revoke first: revoked %v, calls %v", lab.revoked, lab.calls)
	}
	for _, k := range HashKeys() {
		if !sha256Hex.MatchString(got.Hashes[k]) {
			t.Errorf("%s is %q before the backup", k, got.Hashes[k])
		}
	}
	for _, pvc := range []string{"data-t-broker-0", "data-t-broker-1"} {
		if m := got.Marks[pvc]; len(m) != 1 || m[0] != bob {
			t.Errorf("%s's marks before the backup: %v", pvc, m)
		}
	}
	if len(got.Marks) != 2 {
		t.Errorf("marks read on %d claims, want the 2 brokers'", len(got.Marks))
	}

	lab = newFakeLab()
	lab.noCopy = true
	if _, err := BeforeBackup(lab, bob.Key); err == nil || !strings.Contains(err.Error(), "marks.json") {
		t.Errorf("a revocation no copy wrote: %v", err)
	}
	lab = newFakeLab()
	lab.revokeErr = fmt.Errorf("revoke-offline.sh: exit status 1")
	if _, err := BeforeBackup(lab, bob.Key); err == nil {
		t.Error("a failed revocation is accepted")
	}
}

func TestDecodeMarksReadsTheCopysFile(t *testing.T) {
	got, err := DecodeMarks(`{"marks":[{"kind":"principal","key":"user:bob@example.com","at":"2026-11-05T00:00:00Z"},{"future":1}]}`)
	if err != nil || len(got) != 1 || got[0] != bob {
		t.Errorf("DecodeMarks = %v, %v", got, err)
	}
	if _, err := DecodeMarks("not json"); err == nil {
		t.Error("a file that is not JSON decodes")
	}
	if got, err := DecodeMarks(""); err != nil || len(got) != 0 {
		t.Errorf("an absent file: %v, %v", got, err)
	}
}

func TestFailedCommandIsTheTrapsLineScrubbed(t *testing.T) {
	out := "some output\nl89-failed: kubectl -n port49 wait --for=condition=complete job/restore-token-delete --timeout=3m\nError: timed out\n"
	// the token delete's own lines hold a word Results refuses: the row shows it masked, and stays writable
	got := FailedCommand(out)
	// --for=condition=complete is 24 key characters, so Scrub shortens it
	if got != "kubectl -n port49 wait <LONG> job/restore-<word>-delete --timeout=3m" {
		t.Errorf("FailedCommand = %q", got)
	}
	if _, err := Results(Env{}, []l82.Cell{{ID: "c", Verdict: l82.Fail, Rows: []l82.Row{{Case: "README step 2", Observation: got}}}}); err != nil {
		t.Errorf("a row with the failed command cannot be written: %v", err)
	}
	if got := FailedCommand("no trap line\n"); got != "not named (no l89-failed line)" {
		t.Errorf("no trap line: %q", got)
	}
	if got := FailedCommand("l89-failed: echo " + strings.Repeat("A", 40) + "\n"); strings.Contains(got, strings.Repeat("A", 24)) {
		t.Errorf("a long run is kept: %q", got)
	}
	if got := FailedCommand("l89-failed: curl --password x\n"); got != "curl --<word> x" {
		t.Errorf("a credential word: %q", got)
	}
	if got := FailedCommand("l89-failed: echo eyJhbGciOi\n"); Leak(got) != "" {
		t.Errorf("a JWT's start is kept: %q", got)
	}
	if !strings.HasPrefix(StepScript("true\n"), "trap 'echo \"l89-failed: $BASH_COMMAND\" >&2' ERR\n") {
		t.Errorf("StepScript = %q", StepScript("true\n"))
	}
}

// Every results row the L89 harness writes with a literal case or observation must pass Leak, or Results
// refuses the whole file and the run records nothing. Round 4's "README step 2 (the token delete Job)"
// would have.
func TestTheHarnesssRowTextIsWritable(t *testing.T) {
	fset := token.NewFileSet()
	n := 0
	for _, name := range []string{"l89_test.go", "l89_order_test.go"} {
		f, err := parser.ParseFile(fset, filepath.Join("..", "..", "lab", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || (id.Name != "l82Row" && id.Name != "measured" && id.Name != "readme") {
				return true
			}
			// the arguments that become row text: l82Row's after the cell, measured's both, readme's label
			// (its other two are a directory and the script); every string literal in them, the parts of a
			// concatenation too
			args := call.Args
			switch id.Name {
			case "l82Row":
				args = args[1:]
			case "readme":
				args = args[:1]
			}
			for _, arg := range args {
				ast.Inspect(arg, func(a ast.Node) bool {
					lit, ok := a.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					n++
					if why := Leak(s); why != "" {
						t.Errorf("%s: the row text %q holds %s", fset.Position(lit.Pos()), s, why)
					}
					return true
				})
			}
			return true
		})
	}
	if n < 20 {
		t.Errorf("only %d literal row texts found: the call names changed", n)
	}
}

func TestJudgeCNeedsEveryCheck(t *testing.T) {
	h1, h2 := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	want := []string{"t-broker-0/data", "t-broker-1/data", "t-port49d-0/data", "t-port49d-1/data"}
	good := func() C {
		return C{RestorePhase: "Completed", Want: want,
			Volumes: map[string]string{"t-broker-0/data": "Completed", "t-broker-1/data": "Completed",
				"t-port49d-0/data": "Completed", "t-port49d-1/data": "Completed", "etcd-0/data": "Completed"},
			FingerprintBefore: "ab", FingerprintAfter: "ab",
			Before:      map[string]string{"data-t-broker-0:/v/state/marks.json": h1, "data-t-port49d-0:/v/data/l89-sentinel": h2},
			AtZero:      map[string]string{"data-t-broker-0:/v/state/marks.json": h1, "data-t-port49d-0:/v/data/l89-sentinel": h2},
			MarksBefore: map[string][]Mark{"data-t-broker-0": {bob}},
			MarksAtZero: map[string][]Mark{"data-t-broker-0": {bob}}}
	}
	if JudgeC(good()) != l82.Pass {
		t.Fatal("a complete restore is not a PASS")
	}
	// the fallback: the brokers ran before the check, so marks.json may be rewritten; every mark recorded
	// before must still be there, and a mark added is not a FAIL
	fb := good()
	fb.Fallback = true
	fb.AtZero["data-t-broker-0:/v/state/marks.json"] = h2
	fb.MarksAtZero["data-t-broker-0"] = []Mark{{Kind: "cert", Key: "k", At: "2026-11-05T01:00:00Z"}, bob}
	if JudgeC(fb) != l82.Pass {
		t.Error("the fallback with every mark kept and one added is not a PASS")
	}
	fb.MarksAtZero["data-t-broker-0"] = []Mark{{Kind: "cert", Key: "k", At: "2026-11-05T01:00:00Z"}}
	if JudgeC(fb) != l82.Fail {
		t.Error("the fallback with a mark lost is not a FAIL")
	}
	fb = good()
	fb.Fallback = true
	fb.AtZero["data-t-port49d-0:/v/data/l89-sentinel"] = h1
	if JudgeC(fb) != l82.Fail {
		t.Error("the fallback compares the sentinel's hash no more")
	}
	for name, mod := range map[string]func(*C){
		// three etcd volumes and one of port49's: the count is high enough, a port49 volume is missing
		"a port49 volume with no restore, others' volumes in its place": func(c *C) {
			delete(c.Volumes, "t-port49d-1/data")
			c.Volumes["etcd-1/data"], c.Volumes["etcd-2/data"] = "Completed", "Completed"
		},
		"a failed volume restore":     func(c *C) { c.Volumes["t-broker-1/data"] = "Failed" },
		"no volumes asked for":        func(c *C) { c.Want = nil },
		"a restore not Completed":     func(c *C) { c.RestorePhase = "PartiallyFailed" },
		"a different CA":              func(c *C) { c.FingerprintAfter = "cd" },
		"no CA read":                  func(c *C) { c.FingerprintBefore, c.FingerprintAfter = "", "" },
		"marks.json changed":          func(c *C) { c.AtZero["data-t-broker-0:/v/state/marks.json"] = h2 },
		"marks.json absent after":     func(c *C) { c.AtZero["data-t-broker-0:/v/state/marks.json"] = "" },
		"a sentinel not read at zero": func(c *C) { delete(c.AtZero, "data-t-port49d-0:/v/data/l89-sentinel") },
		"nothing recorded before":     func(c *C) { c.Before, c.AtZero = map[string]string{}, map[string]string{} },
		"absent before and after": func(c *C) {
			c.Before["data-t-port49d-0:/v/data/l89-sentinel"], c.AtZero["data-t-port49d-0:/v/data/l89-sentinel"] = "", ""
		},
		"a broker started a fresh copy": func(c *C) { c.FreshCopy = true },
		// I1r4: a lab that revoked nothing has no mark to lose, so the restore proves nothing about marks
		"no mark recorded before":       func(c *C) { c.MarksBefore = map[string][]Mark{"data-t-broker-0": nil} },
		"no broker's marks read before": func(c *C) { c.MarksBefore = nil },
		"a mark lost, the hash equal":   func(c *C) { c.MarksAtZero["data-t-broker-0"] = nil },
		"a mark's time changed at zero": func(c *C) {
			c.MarksAtZero["data-t-broker-0"] = []Mark{{Kind: bob.Kind, Key: bob.Key, At: "2026-11-05T02:00:00Z"}}
		},
	} {
		c := good()
		mod(&c)
		if JudgeC(c) != l82.Fail {
			t.Errorf("%s is not a FAIL", name)
		}
	}
}

func TestParseVolumesReadsTheREADMEsCheck(t *testing.T) {
	out := "Completed\nPHASE       POD           VOLUME\nCompleted   t-broker-0    data\nFailed      t-port49d-1   data\n"
	phase, vols := ParseVolumes(out)
	if phase != "Completed" || len(vols) != 2 || vols["t-broker-0/data"] != "Completed" || vols["t-port49d-1/data"] != "Failed" {
		t.Errorf("ParseVolumes = %q, %v", phase, vols)
	}
	// no pod volume restore at all: kubectl's own line on stderr, which the harness reads with stdout
	phase, vols = ParseVolumes("Completed\nNo resources found in velero namespace.\n")
	if phase != "Completed" || len(vols) != 0 {
		t.Errorf("an empty list: %q, %v", phase, vols)
	}
	if phase, _ := ParseVolumes(""); phase != "" {
		t.Errorf("no output has the phase %q", phase)
	}
}

func TestParseHashesKeysEachFileByClaim(t *testing.T) {
	h := strings.Repeat("0f", 32)
	got := ParseHashes("data-t-broker-0", h+"  /v/state/marks.json\nabsent /v/state/issuing-ca.pem\n")
	if len(got) != 2 || got["data-t-broker-0:/v/state/marks.json"] != h || got["data-t-broker-0:/v/state/issuing-ca.pem"] != "" {
		t.Errorf("ParseHashes = %v", got)
	}
	if got := ParseHashes("x", "not a hash  /v/f\n"); len(got) != 0 {
		t.Errorf("a malformed line is read: %v", got)
	}
	if s := HashScript("/v/a", "/v/b"); !strings.Contains(s, "sha256sum") || !strings.Contains(s, "/v/a /v/b") {
		t.Errorf("HashScript = %q", s)
	}
}

// The README's restore steps as the lab runs them: every command it names for etcd's namespace is the
// lab's one namespace, and no placeholder is left (I1r3: the token delete's wait, logs and delete named
// port49-etcd, which the lab does not have).
func TestStepsRunTheVeleroREADMEInTheLabsNamespace(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	steps, err := Steps(string(b), "port49", "t", "l89-backup", "l89-restore-c", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etcdrestore", "tokendelete", "restorezero", "volumes", "revoke", "scaleup", "fallbackrestore", "fallbackzero"} {
		cmd := steps[name]
		if cmd == "" {
			t.Errorf("no %s step", name)
		}
		if strings.Contains(cmd, "port49-etcd") || strings.ContainsAny(cmd, "<>") {
			t.Errorf("%s still names etcd's namespace or a placeholder:\n%s", name, cmd)
		}
	}
	if !strings.Contains(steps["etcdrestore"], "--include-namespaces port49 ") || !strings.Contains(steps["tokendelete"], "-n port49 wait") {
		t.Errorf("the restore or the token delete is not in the lab's namespace:\n%s\n%s", steps["etcdrestore"], steps["tokendelete"])
	}
	if !strings.Contains(steps["volumes"], "podvolumerestores") || !strings.Contains(steps["volumes"], "velero.io/restore-name=l89-restore-c ") {
		t.Errorf("the volume check does not list the named restore's pod volume restores:\n%s", steps["volumes"])
	}
	// m1r4: both restores the check can follow are made under the name the check reads
	for _, name := range []string{"restorezero", "fallbackrestore"} {
		if !strings.Contains(steps[name], "velero restore create l89-restore-c --from-backup l89-backup") {
			t.Errorf("%s does not name its restore:\n%s", name, steps[name])
		}
	}
	if !strings.Contains(steps["fallbackzero"], "--replicas=0") || !strings.Contains(steps["fallbackzero"], "--for=delete") {
		t.Errorf("the fallback's scale to 0 does not wait for the pods to go:\n%s", steps["fallbackzero"])
	}
	if _, err := Steps(string(b), "other", "t", "l89-backup", "r", 2, 2); err == nil {
		t.Error("a namespace the README's port49 commands do not name is accepted")
	}
}

func TestSubstAndLabModifier(t *testing.T) {
	if got, err := Subst("a <x> <x> b", map[string]string{"<x>": "1"}); err != nil || got != "a 1 1 b" {
		t.Errorf("Subst: %q, %v", got, err)
	}
	if _, err := Subst("a b", map[string]string{"<x>": "1"}); err == nil {
		t.Error("Subst accepts a placeholder the command lacks")
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", "restore-scale-zero.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := LabModifier(string(b), "t")
	if err != nil || !strings.Contains(got, `resourceNameRegex: "^t-(broker|port49d)$"`) {
		t.Fatalf("LabModifier: %q, %v", got, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("the lab modifier is not YAML: %v", err)
	}
	if _, err := LabModifier("version: v1\n", "t"); err == nil {
		t.Error("LabModifier accepts a file without the line it rewrites")
	}
}
