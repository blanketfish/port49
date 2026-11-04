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
			Template struct {
				IncludedNamespaces       []string `yaml:"includedNamespaces"`
				DefaultVolumesToFsBackup bool     `yaml:"defaultVolumesToFsBackup"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	text := example(t, "schedule.yaml")
	if err := yaml.Unmarshal([]byte(text), &sch); err != nil {
		t.Fatal(err)
	}
	if sch.Kind != "Schedule" {
		t.Errorf("kind %q", sch.Kind)
	}
	if !sch.Spec.Template.DefaultVolumesToFsBackup {
		t.Error("the Schedule does not back volumes up by file system (defaultVolumesToFsBackup: true)")
	}
	if len(sch.Spec.Template.IncludedNamespaces) != 1 {
		t.Errorf("includedNamespaces %v", sch.Spec.Template.IncludedNamespaces)
	}
	// the chart's PVC labels, as the StatefulSets' selectors give them, named for both components
	for _, c := range []string{"component=broker", "component=port49d"} {
		if !strings.Contains(text, "app.kubernetes.io/name=port49") || !strings.Contains(text, c) {
			t.Errorf("the example does not name the %s volumes' label selector", c)
		}
	}
	for _, want := range []string{"issuing-ca.key", "PRIVATE key"} {
		if !strings.Contains(text, want) {
			t.Errorf("the example does not say that the backup holds %q", want)
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
		"the well-known default":                         "default is well\n   known",
	} {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Errorf("the README does not state %s (%q)", what, want)
		}
	}
	if strings.Contains(readme, "--from-literal") || strings.Contains(readme, "static-passw0rd") {
		t.Error("the README puts a password on a command line or names the default as a value")
	}
}
