package kind_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/kind/kindtest"
	"gopkg.in/yaml.v3"
)

func read(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{kindtest.Root()}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestKindConfigIsPinnedAndHasTwoZones(t *testing.T) {
	var cfg struct {
		Nodes []struct {
			Role   string            `yaml:"role"`
			Image  string            `yaml:"image"`
			Labels map[string]string `yaml:"labels"`
			Ports  any               `yaml:"extraPortMappings"`
		} `yaml:"nodes"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "tests", "kind", "kind.yaml")), &cfg); err != nil {
		t.Fatal(err)
	}
	pinned := regexp.MustCompile(`^kindest/node:v[0-9.]+@sha256:[0-9a-f]{64}$`)
	zones := map[string]int{}
	for _, n := range cfg.Nodes {
		if !pinned.MatchString(n.Image) {
			t.Errorf("a %s node's image %q is not pinned by digest", n.Role, n.Image)
		}
		if n.Ports != nil {
			t.Error("kind.yaml publishes ports: the device dials the node address")
		}
		if n.Role == "worker" {
			zones[n.Labels["topology.kubernetes.io/zone"]]++
		}
	}
	if len(cfg.Nodes) != 3 || zones["a"] != 1 || zones["b"] != 1 {
		t.Errorf("want a control plane and workers in zones a and b: %d nodes, zones %v", len(cfg.Nodes), zones)
	}
}

func TestMakefilePinsKindAndKubectlBySHA256(t *testing.T) {
	mk := read(t, "Makefile")
	for _, v := range []string{"KIND_SHA256_LINUX_AMD64", "KUBECTL_SHA256_LINUX_AMD64"} {
		if !regexp.MustCompile(`(?m)^` + v + ` = [0-9a-f]{64}$`).MatchString(mk) {
			t.Errorf("%s is not a 64 hex digit pin", v)
		}
	}
	for _, want := range []string{"sha256sum -c -", "bin/kind-v$(KIND_VERSION)", "bin/kubectl-$(KUBECTL_VERSION)", "kind-smoke: image"} {
		if !strings.Contains(mk, want) {
			t.Errorf("the Makefile lacks %q", want)
		}
	}
}

// A Secret is made from a file, never a literal; a failure never prints one.
func TestSmokeMakesSecretsFromFilesOnly(t *testing.T) {
	if strings.Contains(read(t, "tests", "kind", "smoke_test.go"), "--from-literal") {
		t.Error("smoke_test.go names --from-literal")
	}
}

// The post-renderer is a test tool: nothing the chart ships names it.
func TestThePostRendererIsNotInTheChart(t *testing.T) {
	err := filepath.WalkDir(filepath.Join(kindtest.Root(), "deploy", "helm"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "oldroot") || strings.Contains(string(b), "post-renderer") {
			t.Errorf("%s names the test-only post-renderer", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
