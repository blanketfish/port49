package versions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func tree(t *testing.T, py, galaxy, chart, app string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, PyPIFile, "[project]\nname = \"port49\"\nversion = \""+py+"\"\n")
	write(t, root, GalaxyFile, "namespace: port49\nname: client\nversion: "+galaxy+"\n")
	if chart != "" {
		write(t, root, ChartFile, "apiVersion: v2\nname: port49\nversion: "+chart+"\nappVersion: \""+app+"\"\n")
	}
	return root
}

func TestReadFindsEachVersion(t *testing.T) {
	v, err := Read(tree(t, "0.1.0", "0.1.0", "0.1.0", "0.1.0"))
	if err != nil || v != (Versions{"0.1.0", "0.1.0", "0.1.0", "0.1.0"}) {
		t.Fatalf("%+v, %v", v, err)
	}
}

func TestTheChartIsOptionalUntilItExists(t *testing.T) {
	v, err := Read(tree(t, "0.1.0", "0.1.0", "", ""))
	if err != nil || v.Chart != "" || v.ChartApp != "" || v.PyPI != "0.1.0" {
		t.Fatalf("%+v, %v", v, err)
	}
	if got := Check(v, ""); len(got) != 0 {
		t.Errorf("no tag, no chart: %v", got)
	}
}

func TestAMissingPyprojectIsAnError(t *testing.T) {
	root := tree(t, "0.1.0", "0.1.0", "", "")
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(PyPIFile))); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root); err == nil || !strings.Contains(err.Error(), "pyproject") {
		t.Fatalf("got %v", err)
	}
}

func TestVersionsDisagreeingIsAFinding(t *testing.T) {
	got := Check(Versions{PyPI: "0.1.0", Galaxy: "0.2.0", Chart: "0.1.0", ChartApp: "0.1.0"}, "")
	if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), GalaxyFile) {
		t.Fatalf("got %v", got)
	}
	if got := Check(Versions{PyPI: "0.1.0", Galaxy: "0.1.0", Chart: "0.1.0", ChartApp: "0.1.0"}, ""); len(got) != 0 {
		t.Fatalf("agreeing: %v", got)
	}
}

func TestATagMustEqualEveryVersion(t *testing.T) {
	same := Versions{"0.1.0", "0.1.0", "0.1.0", "0.1.0"}
	if got := Check(same, "v0.1.0"); len(got) != 0 {
		t.Fatalf("v0.1.0 against 0.1.0: %v", got)
	}
	got := Check(same, "v0.2.0")
	if len(got) != 4 {
		t.Fatalf("v0.2.0: %d findings: %v", len(got), got)
	}
	for _, file := range []string{PyPIFile, GalaxyFile, ChartFile} {
		if !strings.Contains(strings.Join(got, "\n"), file) {
			t.Errorf("no finding names %s: %v", file, got)
		}
	}
}

func TestATagNeedsEveryValuePresent(t *testing.T) {
	got := Check(Versions{PyPI: "0.1.0", Galaxy: "0.1.0"}, "v0.1.0")
	if len(got) != 2 || !strings.Contains(strings.Join(got, "\n"), ChartFile) {
		t.Fatalf("got %v", got)
	}
}

func TestAPreReleaseTagIsNormalisedForPyPI(t *testing.T) {
	v := Versions{PyPI: "0.1.0rc1", Galaxy: "0.1.0-rc1", Chart: "0.1.0-rc1", ChartApp: "0.1.0-rc1"}
	if got := Check(v, "v0.1.0-rc1"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	v.PyPI = "0.1.0-rc1" // not PEP 440 normalised: pyproject must carry 0.1.0rc1
	if got := Check(v, "v0.1.0-rc1"); len(got) != 1 || !strings.Contains(got[0], PyPIFile) {
		t.Fatalf("an unnormalised pyproject: %v", got)
	}
}
