package l89

import (
	"os"
	"path/filepath"
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
	if strings.Count(out, "NOT RUN") != 2 {
		t.Errorf("one cell never run should read NOT RUN twice (the table and its heading):\n%s", out)
	}
	if _, err := Results(Env{}, []l82.Cell{{ID: "c"}}); err == nil {
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
	good := A{Ready: true, FingerprintBefore: "ab", FingerprintAfter: "ab"}
	if JudgeA(good) != l82.Pass {
		t.Error("a ready restore with the same CA is not a PASS")
	}
	for name, a := range map[string]A{
		"not ready":       {Ready: false, FingerprintBefore: "ab", FingerprintAfter: "ab"},
		"a fence refusal": {Ready: true, FenceRefusal: true, FingerprintBefore: "ab", FingerprintAfter: "ab"},
		"a different CA":  {Ready: true, FingerprintBefore: "ab", FingerprintAfter: "cd"},
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
	if err != nil || strings.Contains(c, "\n\n") || !strings.Contains(c, `user = "`+id+":"+secret+`"`) {
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
	a.LogBefore = ""
	if JudgeA(a) != l82.Pass {
		t.Error("a broker that printed none before falls back to the file's")
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
