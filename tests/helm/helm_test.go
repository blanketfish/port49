//go:build helm

package helm

// The same checks as chart_gorender_test.go, on the output of the pinned `helm template`. UNVERIFIED
// until helm runs: nothing in this file has been executed. It fails, never skips, when the pinned
// binary is absent (make helm-test builds it).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func helmBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("HELM_BIN")
	if bin == "" {
		t.Fatal("HELM_BIN is not set: run make helm-test, which fetches the pinned helm")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("helm is absent at %s: run make helm-test", bin)
	}
	return bin
}

func helmRender(t *testing.T, valuesFiles ...string) []doc {
	t.Helper()
	docs, out, err := helmTemplate(t, valuesFiles...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return docs
}

func helmTemplate(t *testing.T, valuesFiles ...string) ([]doc, string, error) {
	t.Helper()
	args := []string{"template", "t", chartDir, "--namespace", "port49"}
	for _, f := range valuesFiles {
		args = append(args, "-f", f)
	}
	out, err := exec.Command(helmBin(t), args...).CombinedOutput()
	if err != nil {
		return nil, string(out), err
	}
	return decodeDocs(t, "helm template", out), string(out), nil
}

func TestChartChecksOnHelm(t *testing.T) {
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) { c.fn(t, helmRender) })
	}
	t.Run("NoSecretInAnEnvironmentAndNoSubPath", func(t *testing.T) { checkNoEnvSecretNoSubPath(t, helmRender) })
}

func TestHelmLintIsClean(t *testing.T) {
	out, err := exec.Command(helmBin(t), "lint", chartDir, "--strict", "-f", filepath.Join(chartDir, "ci", "values.yaml")).CombinedOutput()
	if err != nil {
		t.Fatalf("helm lint: %v\n%s", err, out)
	}
}

// The schema is helm's to enforce; each of these must be refused at template time.
func TestTheSchemaRefusesWhatTheChartCannotRun(t *testing.T) {
	dir := t.TempDir()
	ci := filepath.Join(chartDir, "ci", "values.yaml")
	for name, body := range map[string]string{
		"one etcd member":                     "etcd: {endpoints: [\"https://etcd-0:2379\"]}\n",
		"a repeated member":                   "etcd: {endpoints: [\"https://a:2379\", \"https://a:2379\", \"https://b:2379\"]}\n",
		"a plain http member":                 "etcd: {endpoints: [\"http://a:2379\", \"https://b:2379\", \"https://c:2379\"]}\n",
		"an empty keys secret":                "keys: {existingSecret: \"\"}\n",
		"tls without a secret":                "tlsListener: {enabled: true}\n",
		"a nonsense type":                     "service: {type: Bogus}\n",
		"an enrollments backup with no claim": "backup: {enrollments: {enabled: true}}\n",
	} {
		f := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yaml")
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, out, err := helmTemplate(t, ci, f); err == nil {
			t.Errorf("%s: helm template succeeded\n%s", name, out)
		}
	}
	if _, out, err := helmTemplate(t); err == nil {
		t.Errorf("no values at all: helm template succeeded\n%s", out)
	}
}

func TestAGracePeriodShorterThanThePreStopAndTheDrainIsRefused(t *testing.T) {
	vals := baseValues(t, "port49d: {preStopSeconds: 40, terminationGracePeriodSeconds: 60}\n")
	_, out, err := helmTemplate(t, vals...)
	if err == nil || !strings.Contains(out, "terminationGracePeriodSeconds 60 must be at least port49d.preStopSeconds 40 plus 30") {
		t.Errorf("a grace period that cannot hold the sleep and the drain was rendered: %v\n%s", err, out)
	}
	if _, out, err := helmTemplate(t, baseValues(t, "port49d: {preStopSeconds: 30, terminationGracePeriodSeconds: 60}\n")...); err != nil {
		t.Errorf("the boundary (30 + 30) is refused: %v\n%s", err, out)
	}
}
