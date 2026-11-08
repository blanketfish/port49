package l89

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

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
	return unlinked(string(b))
}

// a Markdown link reads as its text, so a lab ID linked to the docs site's register still says what it said
var markdownLink = regexp.MustCompile(`\[([^\]\n]+)\]\([^)\s]+\)`)

func unlinked(s string) string { return markdownLink.ReplaceAllString(s, "$1") }

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
	return unlinked(string(b))
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

// m1r5c, I1r5d: a setup failure's reason survives the job log's filter (which drops a line with a
// credential word in it) and Results' Leak, so the row and the log line both say why the cell stopped. Only
// the harness's own names are let past, through an allowlist; a credential word anywhere else drops its
// line, and a word followed by : or = and a value always does.
func TestReasonKeepsASetupFailureReadable(t *testing.T) {
	filter := regexp.MustCompile(`(?i)password|token|secret|eyJ`)
	// the real path (m2r5d): r.kubectl hands KubectlFailure kubectl's own stderr, unfiltered
	got := KubectlFailure("kubectl -n port49 get secret port49-etcd-root", errors.New("exit status 1"),
		"Error from server (NotFound): secrets \"port49-etcd-root\" not found\n")
	if filter.MatchString(got) || Leak(got) != "" {
		t.Errorf("the reason would be dropped or refused: %q", got)
	}
	for _, want := range []string{"exit status 1", "(NotFound)", "<word>s \"port49-etcd-root\" not found", "get <word> port49-etcd-root", " / "} {
		if !strings.Contains(got, want) {
			t.Errorf("the reason %q lacks %q", got, want)
		}
	}
	if got := Reason("reading restore-unspent.yaml: no such file"); got != "reading restore-unspent.yaml: no such file" {
		t.Errorf("Reason = %q", got)
	}
	// the review's probe (I1r5d): a key and its value, a word outside the allowlist, the run's own key.
	// Every value is generated here, new each run, so no credential-shaped literal is in the source.
	gen := func(n int) string {
		v, err := Random(n)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	access, value, short := gen(10), gen(10), gen(3) // access: 20 hex, as the store's key, under Scrub's run length
	for _, in := range []string{
		"password: " + short,
		"aws_secret_access_key = " + value,
		"aws_secret_access_key=" + value,
		"\"token\": \"" + short + "\"",
		"the client secret was refused",
		"access key " + access + " refused",
		"bearer eyJ" + short,
	} {
		got := ReasonWith("the store refused the harness\n"+in, access)
		if strings.Contains(got, short) || strings.Contains(got, value) || strings.Contains(got, access) ||
			strings.Contains(got, "<word>") || filter.MatchString(got) {
			t.Errorf("ReasonWith(%q) = %q", in, got)
		}
		if got != "the store refused the harness" {
			t.Errorf("ReasonWith(%q) = %q, want the other line alone", in, got)
		}
	}
	// a name on the allowlist followed by a value is still a key and its value
	if got := Reason("secret port49-etcd-root: " + short); strings.Contains(got, short) {
		t.Errorf("an allowlisted name's value is kept: %q", got)
	}
	if got := Reason("a value " + strings.Repeat("Ab3", 12)); !strings.Contains(got, "<LONG>") || strings.Contains(got, "Ab3Ab3") {
		t.Errorf("a long run is kept: %q", got)
	}
	for _, pem := range []string{"-----BEGIN PRIVATE KEY-----", "AB12cd==\n-----END PRIVATE KEY-----", "an RSA PRIVATE KEY"} {
		if got := Reason(pem); !strings.HasPrefix(got, "withheld") {
			t.Errorf("a PEM fragment is kept: %q", got)
		}
	}
	if got := Reason(strings.Repeat("x ", 400)); len(got) > 410 {
		t.Errorf("a long reason is %d bytes", len(got))
	}
	// a step's name prefixes its errors, so none may hold a word the filter drops
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	steps, err := Steps(string(b), "port49", "t", "l89-backup", "l89-restore-c", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	for name := range steps {
		if filter.MatchString(name) {
			t.Errorf("the step %q is named with a word the job log's filter drops", name)
		}
	}
	for name := range StepBounds {
		if filter.MatchString(name) {
			t.Errorf("the bound %q is named with a word the job log's filter drops", name)
		}
	}
}

func TestFailedCommandIsTheTrapsLineScrubbed(t *testing.T) {
	out := "some output\nl89-failed: kubectl -n port49 wait --for=condition=complete job/restore-unspent --timeout=3m\nError: timed out\n"
	// the token delete's own lines hold a word Results refuses: the row shows it masked, and stays writable
	got := FailedCommand(out)
	// --for=condition=complete is 24 key characters, so Scrub shortens it
	if got != "kubectl -n port49 wait <LONG> job/restore-unspent --timeout=3m" {
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
	if got := FailedCommand("l89-failed: curl --password x\n"); !strings.HasPrefix(got, "withheld") {
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

// A README step that does not end is stopped at its bound, the processes it started too (round 3's run
// hung in a step until the 55m deadline), and the output says which command was running.
func TestRunBoundedStopsAStepAndWhatItStarted(t *testing.T) {
	start := time.Now()
	// a child holding the output pipe open: killing bash alone would leave CombinedOutput waiting on it
	out, timedOut, err := RunBounded(t.TempDir(), nil, StepScript("echo first\nsleep 30 | cat\necho never\n"), time.Second)
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the bounded step took %v", took)
	}
	if !timedOut || err == nil {
		t.Errorf("a step past its bound: timedOut %v, err %v", timedOut, err)
	}
	if got := RunningCommand(out); got != "sleep 30" && got != "cat" {
		t.Errorf("RunningCommand = %q; output %q", got, out)
	}
	out, timedOut, err = RunBounded(t.TempDir(), nil, StepScript("echo ok\n"), 10*time.Second)
	if timedOut || err != nil || !strings.Contains(out, "ok") {
		t.Errorf("a step that ends: %q, %v, %v", out, timedOut, err)
	}
	// the volume check's output, read with its trap lines, parses as the command printed it
	out, _, err = RunBounded(t.TempDir(), nil, StepScript("echo Completed\necho 'PHASE POD VOLUME'\necho 'Completed t-broker-0 data'\n"), 10*time.Second)
	if err != nil || !strings.Contains(out, "l89-running: ") {
		t.Fatalf("the trap lines: %q, %v", out, err)
	}
	if phase, vols := ParseVolumes(StepOutput(out)); phase != "Completed" || vols["t-broker-0/data"] != "Completed" {
		t.Errorf("ParseVolumes after StepOutput = %q, %v", phase, vols)
	}
	_, timedOut, err = RunBounded(t.TempDir(), nil, StepScript("false\n"), 10*time.Second)
	if timedOut || err == nil {
		t.Errorf("a failing step: timedOut %v, err %v", timedOut, err)
	}
}

func TestBudgetKeepsTheCellsInsideTheTestsDeadline(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	b := Budget{TestEnd: now.Add(30 * time.Minute), Reserve: 4 * time.Minute}
	// the cell's own cap
	if end, ok := b.Cell(now, 15*time.Minute, 6*time.Minute); !ok || !end.Equal(now.Add(15*time.Minute)) {
		t.Errorf("Cell = %v, %v", end, ok)
	}
	// the test's deadline less the reserve comes first
	if end, ok := b.Cell(now.Add(14*time.Minute), 15*time.Minute, 6*time.Minute); !ok || !end.Equal(now.Add(26*time.Minute)) {
		t.Errorf("Cell near the deadline = %v, %v", end, ok)
	}
	// too little left to start
	if _, ok := b.Cell(now.Add(21*time.Minute), 15*time.Minute, 6*time.Minute); ok {
		t.Error("a cell with 5m left and 6m needed starts")
	}
	// no -timeout: only the cap
	if end, ok := (Budget{}).Cell(now, 15*time.Minute, 6*time.Minute); !ok || !end.Equal(now.Add(15*time.Minute)) {
		t.Errorf("no deadline: %v, %v", end, ok)
	}
	end := now.Add(5 * time.Minute)
	if d, capped := Bound(now, end, 8*time.Minute); d != 5*time.Minute || !capped {
		t.Errorf("Bound past the cell's end = %v, %v", d, capped)
	}
	if d, capped := Bound(now, end, 3*time.Minute); d != 3*time.Minute || capped {
		t.Errorf("Bound inside the cell = %v, %v", d, capped)
	}
	if d, _ := Bound(now.Add(10*time.Minute), end, 3*time.Minute); d != 0 {
		t.Errorf("Bound after the cell's end = %v", d)
	}
}

// The cells' caps, the bring-up and the reserve fit the test timeout, so the guard's kill, which writes
// NOT RUN for the cell it stops, is the exception and not the end of every slow run. The timeout is the
// one make lab-l89 passes, and CI's job for l89 leaves room for the builds before it.
func TestTheCellCapsFitTheTestTimeout(t *testing.T) {
	var sum time.Duration
	for _, id := range Order {
		cap, need := CellCap(id)
		if cap <= 0 || need <= 0 || need > cap {
			t.Errorf("cell %s: cap %v, need %v", id, cap, need)
		}
		sum += cap
	}
	if total := BringUp + sum + ReserveAtEnd; total > TestTimeout {
		t.Errorf("the bring-up, the cells' caps and the reserve are %v, over the %v timeout", total, TestTimeout)
	}
	mk, err := os.ReadFile(filepath.Join("..", "..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "-run '^TestL89$$' -count=1 -v -timeout " + fmt.Sprintf("%dm", int(TestTimeout.Minutes())); !strings.Contains(string(mk), want) {
		t.Errorf("make lab-l89 does not run with %q", want)
	}
	wf, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "lab-kind.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var job struct {
		Jobs map[string]struct {
			Timeout string `yaml:"timeout-minutes"`
		}
	}
	if err := yaml.Unmarshal(wf, &job); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, j := range job.Jobs {
		if j.Timeout == "${{ matrix.cell == 'l89' && 100 || 60 }}" {
			found = true
		}
	}
	if !found || 100*time.Minute < TestTimeout+10*time.Minute {
		t.Errorf("no job gives l89 100 minutes (the test's %v and the builds before it): %+v", TestTimeout, job.Jobs)
	}
}

// I1r5b: a step's own bound is a backstop for a hang, never shorter than the README's own --timeouts in
// it (with a minute's slack): the scale-up's two 10m rollouts were bounded at 10m, a false FAIL.
func TestEachStepsBoundCoversItsREADMETimeouts(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	steps, err := Steps(string(b), "port49", "t", "l89-backup", "l89-restore-c", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	for name, cmd := range steps {
		if name == "etcdrestore" { // never run whole in the lab: its restore is folded, its wait is etcdwait
			continue
		}
		bound, ok := StepBounds[name]
		if !ok {
			t.Errorf("step %s has no bound", name)
			continue
		}
		sum, err := READMETimeouts(cmd)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bound < sum+BoundSlack {
			t.Errorf("step %s is bounded at %v, under its README timeouts %v plus %v", name, bound, sum, BoundSlack)
		}
	}
	if got, _ := READMETimeouts(steps["scaleup"]); got != 20*time.Minute {
		t.Errorf("the scale-up's README timeouts sum to %v, want 20m", got)
	}
	if !strings.Contains(steps["etcdwait"], "wait --for=condition=Ready") || strings.Contains(steps["etcdwait"], "velero") {
		t.Errorf("etcdwait is not step 1's wait alone: %q", steps["etcdwait"])
	}
	if _, err := READMETimeouts("kubectl wait --timeout=soon"); err == nil {
		t.Error("a --timeout that is not a duration is accepted")
	}
}

// I1r5b: a restore --wait that does not end is the README's outcome only when its cause is seen: a pod
// volume restore not yet ended whose pod is gone (the suspected mechanism of c). Anything else is the
// runner's slowness, NOT RUN.
func TestHangCauseIsMeasuredOnlyForAVolumeRestoreWaitingOnAMissingPod(t *testing.T) {
	out := "phase InProgress\npvr New t-broker-0 data\npvr Completed etcd-0 data\npvr InProgress t-port49d-0 data\npod etcd-0\npod t-port49d-0\n"
	pvrs, pods, phase := ParseHang(out)
	if phase != "InProgress" || len(pvrs) != 3 || !pods["etcd-0"] || pods["t-broker-0"] {
		t.Fatalf("ParseHang = %v, %v, %q", pvrs, pods, phase)
	}
	measured, rows := HangCause(pvrs, pods)
	if !measured {
		t.Error("a New pod volume restore whose pod is gone is not measured")
	}
	joined := fmt.Sprint(rows)
	if !strings.Contains(joined, "t-broker-0/data") || !strings.Contains(joined, "New; pod t-broker-0 absent") || !strings.Contains(joined, "InProgress; pod t-port49d-0 present") {
		t.Errorf("rows = %v", rows)
	}
	if strings.Contains(joined, "etcd-0") {
		t.Errorf("an ended pod volume restore is a row: %v", rows)
	}
	// progressing on a pod that is there: slow, not the README
	pvrs, pods, _ = ParseHang("phase InProgress\npvr InProgress t-broker-0 data\npod t-broker-0\n")
	if m, _ := HangCause(pvrs, pods); m {
		t.Error("a progressing pod volume restore on a present pod is measured")
	}
	// ended, failed or canceled, on pods that are gone: the wait can end, so the hang is not theirs
	pvrs, pods, _ = ParseHang("pvr Failed t-broker-0 data\npvr Canceled t-broker-1 data\npvr Completed t-port49d-0 data\n")
	if m, rows := HangCause(pvrs, pods); m || len(rows) != 1 {
		t.Errorf("ended pod volume restores: %v, %v", m, rows)
	}
	// none at all: nothing seen, so nothing measured
	if m, rows := HangCause(nil, map[string]bool{}); m || len(rows) != 1 {
		t.Errorf("no pod volume restore: %v, %v", m, rows)
	}
	// a phase not yet set is not ended
	pvrs, pods, _ = ParseHang("pvr  t-broker-1 data\n")
	if m, _ := HangCause(pvrs, pods); !m || pvrs[0].Phase != "New" {
		t.Errorf("an unset phase: %v, %v", m, pvrs)
	}
	if s := HangProbe("port49", "l89-restore-c"); !strings.Contains(s, "velero.io/restore-name=l89-restore-c") || !strings.Contains(s, "-n port49 get pods") {
		t.Errorf("HangProbe = %q", s)
	}
}

// The guard's kill (the deadline 45s away) writes the results too: the cell it stopped is NOT RUN with a
// row saying why, and the cells already judged keep their verdicts.
func TestStoppedMarksTheRunningCellNotRun(t *testing.T) {
	cells := []l82.Cell{{ID: "a", Verdict: l82.Pass}, {ID: "b", Verdict: l82.Pass}, {ID: "c", Verdict: l82.Fail, Rows: []l82.Row{{Case: "x", Observation: "y"}}}, {ID: "d"}}
	got := Stopped(cells, "c", "the test's deadline was 45s away")
	if got[0].Verdict != l82.Pass || got[2].Verdict != "" || len(got[2].Rows) != 2 || !strings.Contains(got[2].Rows[1].Observation, "deadline") {
		t.Errorf("Stopped = %+v", got)
	}
	if cells[2].Verdict != l82.Fail || len(cells[2].Rows) != 1 {
		t.Error("Stopped changed the cells it was given")
	}
	out, err := Results(Env{}, got)
	if err != nil || !strings.Contains(out, "stopped") {
		t.Errorf("the stopped run's results: %v\n%s", err, out)
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
// placeholder is a README placeholder left unfilled, <release> or <backup> (a shell's >&2 is not one).
var placeholder = regexp.MustCompile(`<[a-z0-9-]+>`)

func TestStepsRunTheVeleroREADMEInTheLabsNamespace(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	steps, err := Steps(string(b), "port49", "t", "l89-backup", "l89-restore-c", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etcdrestore", "deletejob", "restorezero", "volumes", "revoke", "scaleup", "restore", "scalezero"} {
		cmd := steps[name]
		if cmd == "" {
			t.Errorf("no %s step", name)
		}
		if strings.Contains(cmd, "port49-etcd") || placeholder.MatchString(cmd) {
			t.Errorf("%s still names etcd's namespace or a placeholder:\n%s", name, cmd)
		}
	}
	if !strings.Contains(steps["etcdrestore"], "--include-namespaces port49 ") || !strings.Contains(steps["deletejob"], "-n port49 get job/"+DeleteJob) {
		t.Errorf("the restore or the token delete is not in the lab's namespace:\n%s\n%s", steps["etcdrestore"], steps["deletejob"])
	}
	if !strings.Contains(steps["volumes"], "podvolumerestores") || !strings.Contains(steps["volumes"], "velero.io/restore-name=l89-restore-c ") {
		t.Errorf("the volume check does not list the named restore's pod volume restores:\n%s", steps["volumes"])
	}
	// m1r4: both restores the check can follow are made under the name the check reads
	for _, name := range []string{"restorezero", "restore"} {
		if !strings.Contains(steps[name], "velero restore create l89-restore-c --from-backup l89-backup") {
			t.Errorf("%s does not name its restore:\n%s", name, steps[name])
		}
	}
	if !strings.Contains(steps["scalezero"], "--replicas=0") || !strings.Contains(steps["scalezero"], "--for=delete") {
		t.Errorf("the scale to 0 does not wait for the pods to go:\n%s", steps["scalezero"])
	}
	// m2r6: an HPA restored with the release could add a port49d pod with no backup while the pods run
	if !strings.Contains(steps["restore"], "--exclude-resources horizontalpodautoscalers.autoscaling") {
		t.Errorf("the README's restore brings back the HPA:\n%s", steps["restore"])
	}
	if strings.Contains(steps["restore"], "resource-modifier") || !strings.Contains(steps["restorezero"], "--resource-modifier-configmap restore-scale-zero") {
		t.Errorf("the README's restore holds a resource modifier, or (c)'s lacks it:\n%s\n%s", steps["restore"], steps["restorezero"])
	}
	if strings.Contains(steps["restorezero"], "\\\\") || !strings.Contains(steps["restorezero"], "port49 \\\n  --resource-modifier") {
		t.Errorf("(c)'s restore does not continue its line with one backslash:\n%s", steps["restorezero"])
	}
	if _, err := Steps(string(b), "other", "t", "l89-backup", "r", 2, 2); err == nil {
		t.Error("a namespace the README's port49 commands do not name is accepted")
	}
}

// Run 42058930263: (d)'s delete Job failed, and the job log's filter dropped every line about it (its
// name held a credential word). The Job's name holds none now, it retries the members' health as
// etcd-init does, and a failure is recorded as rows (JobRows).
func TestTheDeleteJobIsReadableAndWaitsForEtcd(t *testing.T) {
	filter := regexp.MustCompile(`(?i)password|token|secret|eyJ`)
	root := filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero")
	b, err := os.ReadFile(filepath.Join(root, DeleteJobFile))
	if err != nil {
		t.Fatal(err)
	}
	type container struct {
		Name    string
		Image   string
		Command []string
	}
	var job struct {
		Metadata struct{ Name string }
		Spec     struct {
			BackoffLimit int `yaml:"backoffLimit"`
			Template     struct {
				Spec struct {
					InitContainers []container `yaml:"initContainers"`
					Containers     []container
				}
			}
		}
	}
	if err := yaml.Unmarshal(b, &job); err != nil {
		t.Fatal(err)
	}
	if job.Metadata.Name != DeleteJob || filter.MatchString(DeleteJob) || filter.MatchString(DeleteJobFile) {
		t.Errorf("the Job is %q (file %s), want %q with no word the filter drops", job.Metadata.Name, DeleteJobFile, DeleteJob)
	}
	// no package fetched at restore time: etcdctl from etcd's own image, the digest the chart's etcd runs,
	// one etcdctl call per container (the image has no shell), the health check first, then the deletes
	sts, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "etcd", "statefulset.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	etcdImage := regexp.MustCompile(`image: (\S+@sha256:[0-9a-f]{64})`).FindStringSubmatch(string(sts))
	if etcdImage == nil {
		t.Fatal("the etcd StatefulSet names no image by digest")
	}
	if strings.Contains(string(b), "apk ") || strings.Contains(string(b), "alpine") {
		t.Error("the Job still installs a package at run time")
	}
	all := append(append([]container(nil), job.Spec.Template.Spec.InitContainers...), job.Spec.Template.Spec.Containers...)
	var calls []string
	for _, c := range all {
		if filter.MatchString(c.Name) {
			t.Errorf("the container %q is named with a word the filter drops", c.Name)
		}
		if c.Image != etcdImage[1] {
			t.Errorf("the container %s runs %q, want etcd's own %q", c.Name, c.Image, etcdImage[1])
		}
		if len(c.Command) == 0 || c.Command[0] != "etcdctl" {
			t.Errorf("the container %s runs %q, want one etcdctl call", c.Name, c.Command)
		}
		calls = append(calls, strings.Join(c.Command, " "))
	}
	// m1r8: no all-three `endpoint health` gate: one member down after the restore failed it every try,
	// while the deletes need only quorum and each fails on its own without it
	want := []string{"etcdctl del --prefix $(PREFIX)v1/t/", "etcdctl del $(PREFIX)v1/meta/judged", "etcdctl del $(PREFIX)v1/meta/judged_bundle"}
	if len(calls) != len(want) {
		t.Fatalf("the Job's calls are %q, want %q", calls, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(calls[i], w) {
			t.Errorf("call %d is %q, want %q", i, calls[i], w)
		}
	}
	if job.Spec.BackoffLimit < 3 {
		t.Errorf("backoffLimit %d: a member still electing after the restore gets too few tries", job.Spec.BackoffLimit)
	}
	if _, err := os.Stat(filepath.Join(root, "restore-token-delete.yaml")); !os.IsNotExist(err) {
		t.Errorf("the old file is still shipped: %v", err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "restore-token-delete") || !strings.Contains(string(doc), "job/"+DeleteJob) {
		t.Error("the README does not run the renamed Job")
	}
	// step 2 ends on the Job's own outcome, shows its log either way, and stops on a failure
	step, err := Command(string(doc), "deletejob")
	if err != nil {
		t.Fatal(err)
	}
	logs := strings.Index(step, "logs job/"+DeleteJob+" --all-containers || true")
	failed := strings.Index(step, "*Failed*")
	stop := strings.Index(step, "do not go on to step 3")
	if logs < 0 || failed < 0 || stop < 0 || logs > stop || strings.Contains(step, "wait --for=condition=complete") {
		t.Errorf("step 2 does not end on Complete or Failed, show the log, and stop on a failure:\n%s", step)
	}
	// m3r8 and m1r8: the text names one container's log, and says one unhealthy member is fine
	for _, want := range []string{"logs job/" + DeleteJob + " -c unspent", "one member"} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("step 2's text does not say %q", want)
		}
	}
	if StepBounds["deletejob"] < 5*time.Minute {
		t.Errorf("step 2's bound %v is under its own 4m loop plus a minute", StepBounds["deletejob"])
	}

	// the rows of a failed delete Job, from JobProbe's output: the conditions, each pod, its last lines
	access := func() string {
		v, err := Random(10)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}()
	out := "cond Failed=True BackoffLimitExceeded\ncond Complete=False\n" +
		"pod restore-unspent-abcde Failed 1\npod restore-unspent-fghij Failed 1\n" +
		"log {\"level\":\"warn\",\"msg\":\"retrying of unary invoker failed\",\"target\":\"etcd-endpoints\"}\n" +
		"log https://etcd-1.etcd.port49.svc:2379 is unhealthy: failed to commit proposal: context deadline exceeded\n" +
		"log password: " + access + "\n" +
		"log the key " + access + " was refused\n" +
		"log Error: unhealthy cluster\n"
	rows := JobRows(out, access)
	joined := fmt.Sprint(rows)
	for _, want := range []string{"Failed=True BackoffLimitExceeded", "Complete=False", "restore-unspent-abcde", "Failed, exit 1", "is unhealthy", "Error: unhealthy cluster"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the rows lack %q: %v", want, rows)
		}
	}
	if strings.Contains(joined, access) || filter.MatchString(joined) {
		t.Errorf("the rows hold a value of the run's or a filtered word: %v", rows)
	}
	for _, r := range rows {
		if Leak(r.Case) != "" || Leak(r.Observation) != "" {
			t.Errorf("Results would refuse the row %v", r)
		}
	}
	if rows := JobRows("", access); len(rows) == 0 || !strings.Contains(fmt.Sprint(rows), "none") {
		t.Errorf("an empty probe gives %v", rows)
	}
	if p := JobProbe("port49", DeleteJob); !strings.Contains(p, "get job "+DeleteJob) || !strings.Contains(p, "job-name="+DeleteJob) || !strings.Contains(p, "--tail=") || !strings.Contains(p, "--all-containers") {
		t.Errorf("JobProbe = %q", p)
	}
}

// m1r7: etcd's own fixed auth errors hold a word the filter drops; they are etcd's strings and carry no
// value, so they stay readable, and a value after them still drops the line.
func TestEtcdsAuthErrorsAreReadable(t *testing.T) {
	filter := regexp.MustCompile(`(?i)password|token|secret|eyJ`)
	v, err := Random(6)
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"Error: etcdserver: authentication failed, invalid user ID or password":                              "authentication failed, invalid user ID or <word>",
		`{"level":"warn","error":"rpc error: code = InvalidArgument desc = etcdserver: invalid auth token"}`: "etcdserver: invalid auth <word>",
		"Error: etcdserver: user name is empty":                                                              "user name is empty",
	} {
		got := Reason(in)
		if !strings.Contains(got, want) || filter.MatchString(got) || Leak(got) != "" {
			t.Errorf("Reason(%q) = %q, want it to keep %q", in, got, want)
		}
	}
	for _, in := range []string{
		"invalid user ID or password " + v,
		"invalid user ID or password: " + v,
		"etcdserver: invalid auth token " + v,
		`{"error":"etcdserver: invalid auth token","token":"` + v + `"}`,
	} {
		if got := Reason("the Job stopped\n" + in); got != "the Job stopped" {
			t.Errorf("Reason(%q) = %q, want the other line alone", in, got)
		}
	}
}

// m1r5e: an allowed Secret name keeps its line only in kubectl's own error shapes or the harness's
// command line; anything else that names one is dropped, so data after the name cannot pass.
func TestAnAllowedSecretNameKeepsOnlyKubectlsErrorShapes(t *testing.T) {
	v, err := Random(6)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		"secret/port49-etcd-root data " + v,
		"secrets port49-etcd-root tls.key " + v,
	} {
		if got := Reason("the harness stopped\n" + in); got != "the harness stopped" {
			t.Errorf("Reason(%q) = %q, want the other line alone", in, got)
		}
	}
	for in, want := range map[string]string{
		`Error from server (NotFound): secrets "port49-etcd-root" not found`:                      `<word>s "port49-etcd-root" not found`,
		`Error from server (Forbidden): secrets "port49-etcd-root" is forbidden: User cannot get`: `is forbidden`,
		`Error from server (AlreadyExists): secrets "port49-etcd-root" already exists`:            `already exists`,
		"kubectl -n port49 get secret port49-etcd-root":                                           "get <word> port49-etcd-root",
	} {
		if got := Reason(in); !strings.Contains(got, want) {
			t.Errorf("Reason(%q) = %q, want it to keep %q", in, got, want)
		}
	}
}

// I1r7: a GitOps controller re-creates what the restore leaves out and reverts the scale to 0, so the
// README suspends it first and resumes it after the scale-up; m2r6: the chart's own command brings the
// HPA back, exactly.
func TestTheREADMESuspendsGitOpsAndBringsTheHPABack(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := unlinked(string(b))
	first := strings.Index(doc, "kubectl delete namespace port49 port49-etcd")
	for _, want := range []string{"argocd app set <app> --sync-policy none", "flux suspend helmrelease <name> -n <namespace>",
		"flux suspend kustomization <name> -n <namespace>", "admit a revoked principal",
		// I1r8: a parent app turns a child's sync back on; resume restores the policy that was noted
		"parent", "ApplicationSet", "argocd app get <app> -o json", ".spec.syncPolicy.automated",
		// m1r9, m2r9: said to be unmeasured; the app that syncs the ApplicationSet is suspended first
		"not measured in port49's lab (L89 runs no GitOps controller)", "syncs the ApplicationSet itself",
		"check your Argo CD version supports `ignoreApplicationDifferences`"} {
		if at := strings.Index(doc, want); at < 0 || at > first {
			t.Errorf("the README does not say %q before the first command", want)
		}
	}
	scaleup := strings.Index(doc, "<!-- l89:scaleup:end -->")
	for _, want := range []string{"flux resume helmrelease <name> -n <namespace>", "flux resume kustomization <name> -n <namespace>",
		`argocd app patch <app> --type merge -p '{"spec":{"syncPolicy":{"automated":<noted JSON>}}}'`, "unmeasured, as above", "helm upgrade <release> <chart> --version <version> -n port49 --reuse-values"} {
		if at := strings.Index(doc, want); at < scaleup {
			t.Errorf("the README does not say %q after step 9", want)
		}
	}
	if strings.Contains(doc, "--self-heal --auto-prune") {
		t.Error("step 11 still restores the sync policy by flags, losing allowEmpty and enabled")
	}
	if strings.Contains(doc, "Re-apply the chart") || strings.Contains(doc, "re-applying the chart") {
		t.Error("the README still says to re-apply the chart without the command")
	}
}

// Run 42053716808: L89 (c) measured the restore at 0 replicas hanging (InProgress past 8m, every pod
// volume restore New, its pod absent), so the README restores with the pods running, then scales to 0,
// and says how to recover from the old order; the resource modifier is only (c)'s input now.
func TestTheREADMEsOrderRestoresWithThePodsRunning(t *testing.T) {
	root := filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero")
	b, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := unlinked(string(b))
	for _, gone := range []string{"--resource-modifier-configmap", "fallback order", "l89:restorezero", "l89:fallback"} {
		if strings.Contains(doc, gone) {
			t.Errorf("the README still holds %q", gone)
		}
	}
	for _, want := range []string{"L89 cell (c), run 42053716808", "restore-scale-zero"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the README does not say %q (the measured hang, and the file an operator may have used)", want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "restore-scale-zero.yaml")); !os.IsNotExist(err) {
		t.Errorf("restore-scale-zero.yaml is still shipped: %v", err)
	}
	// the main order, by its markers: the token delete, the restore with the pods running, the check, the
	// scale to 0, the revocations, the scale-up
	last := -1
	for _, m := range []string{"etcdrestore", "deletejob", "restore", "volumes", "scalezero", "revoke", "scaleup", "recover"} {
		at := strings.Index(doc, "<!-- l89:"+m+":begin -->")
		if at < 0 || at < last {
			t.Errorf("the marker %s is missing or out of order (%d after %d)", m, at, last)
		}
		last = at
	}
	rec, err := Recover(doc, "l89-restore-c")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rollout restart deployment/velero", "rollout status deployment/velero --timeout=", "velero restore delete l89-restore-c --confirm", "wait --for=delete restore/l89-restore-c --timeout="} {
		if !strings.Contains(rec, want) {
			t.Errorf("the recovery lacks %q:\n%s", want, rec)
		}
	}
	if placeholder.MatchString(rec) {
		t.Errorf("the recovery keeps a placeholder:\n%s", rec)
	}
	sum, err := READMETimeouts(rec)
	if err != nil || StepBounds["recover"] < sum+BoundSlack {
		t.Errorf("the recovery's bound %v does not cover its timeouts %v (%v)", StepBounds["recover"], sum, err)
	}
	if _, err := Recover("no markers\n", "x"); err == nil {
		t.Error("a README without the recovery is accepted")
	}
}

// Run 42047911635: (c) and (d) stopped as a setup failure in 3s, because the harness refused the shipped
// delete Job for still naming port49-etcd, which it does as the Secret port49-etcd-root, one the lab
// creates in its own namespace. Only the namespace and the service names move.
func TestLabDeleteJobMovesOnlyTheNamespace(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "velero", DeleteJobFile))
	if err != nil {
		t.Fatal(err)
	}
	got, err := LabDeleteJob(string(b), "port49")
	if err != nil {
		t.Fatalf("the shipped delete Job: %v", err)
	}
	for _, want := range []string{"namespace: port49\n", "etcd-0.etcd.port49.svc:2379", "secretName: port49-etcd-root"} {
		if !strings.Contains(got, want) {
			t.Errorf("the lab's delete Job lacks %q", want)
		}
	}
	if strings.Contains(got, "port49-etcd.svc") || strings.Contains(got, "namespace: port49-etcd") {
		t.Error("the lab's delete Job still points at port49-etcd")
	}
	if _, err := LabDeleteJob(string(b)+"# kubectl -n port49-etcd get pods\n", "port49"); err == nil {
		t.Error("a port49-etcd the rewrite does not move is accepted")
	}
}

func TestSubstAndLabModifier(t *testing.T) {
	if got, err := Subst("a <x> <x> b", map[string]string{"<x>": "1"}); err != nil || got != "a 1 1 b" {
		t.Errorf("Subst: %q, %v", got, err)
	}
	if _, err := Subst("a b", map[string]string{"<x>": "1"}); err == nil {
		t.Error("Subst accepts a placeholder the command lacks")
	}
	b, err := os.ReadFile(filepath.Join("testdata", "restore-scale-zero.yaml"))
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

// m3r5d: a step stopped by its bound already says so; the deferred row must not relabel it a setup failure.
func TestNotMeasuredRowedSeesEveryHarnessRow(t *testing.T) {
	for _, rows := range [][]l82.Row{
		{{Case: "README step 5 (the scale-up): did not end within the harness's own bound of 22m0s, not a measurement", Observation: "it was in: kubectl"}},
		{{Case: "the harness's wait for the restore", Observation: "did not end within 5m0s: not a measurement"}},
		{{Case: "the harness's own setup failed: not a measurement", Observation: "exit status 1"}},
	} {
		if !NotMeasuredRowed(rows) {
			t.Errorf("%v is not seen", rows)
		}
	}
	if NotMeasuredRowed([]l82.Row{{Case: "the restore's phase", Observation: "Completed"}}) {
		t.Error("a measured row is taken for a harness row")
	}
}

// Run 42064402328: L89 (c) is the check of the README's warning that a restore at 0 replicas hangs, so
// the measured hang (a pod volume restore not ended, its pod absent) is its PASS, and the same hang in
// (d), the README's order, is a FAIL. A hang whose cause is not seen is neither: NOT RUN.
func TestAHangIsAPassOnlyWhereTheREADMESaysItHangs(t *testing.T) {
	for _, c := range []struct {
		expect, measured bool
		want             string
	}{
		{true, true, l82.Pass},
		{false, true, l82.Fail},
		{true, false, ""},
		{false, false, ""},
	} {
		if got := HangVerdict(c.expect, c.measured); got != c.want {
			t.Errorf("HangVerdict(expect %v, measured %v) = %q, want %q", c.expect, c.measured, got, c.want)
		}
	}
	if got := title("c"); !strings.Contains(got, "the README's warning") || !strings.Contains(got, "hangs") {
		t.Errorf("(c)'s title is %q, want the README's warning that the restore hangs", got)
	}
}

// m1r11: a restore at 0 replicas that ended proves the README's warning wrong only where the lab's
// modifier did apply (both StatefulSets at 0); where it did not, nothing was measured. The FAIL names the
// restore's phase and each pod volume restore's, PartiallyFailed and Failed among them.
func TestAZeroReplicaRestoreThatEndedIsAFailOnlyAtZero(t *testing.T) {
	pvrs := []PVR{{"Completed", "t-broker-0", "data"}, {"Failed", "t-port49d-0", "data"}}
	v, rows := ZeroRestoreEnded("0 0", "PartiallyFailed", pvrs)
	joined := fmt.Sprint(rows)
	if v != l82.Fail {
		t.Errorf("an ended restore at 0 replicas is %q, want FAIL", v)
	}
	for _, want := range []string{"PartiallyFailed", "t-broker-0/data", "Completed", "t-port49d-0/data", "Failed", "0 0", "the README's warning that it hangs is wrong"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the rows lack %q: %v", want, rows)
		}
	}
	v, rows = ZeroRestoreEnded("2 2", "Completed", nil)
	if v != "" || !strings.Contains(fmt.Sprint(rows), "not a measurement") || !strings.Contains(fmt.Sprint(rows), "2 2") {
		t.Errorf("a restore whose modifier did not apply is %q, %v; want NOT RUN with a row", v, rows)
	}
	if !NotMeasuredRowed(rows) {
		t.Error("the NOT RUN row is not seen as one, so the generic setup row would be added")
	}
}
