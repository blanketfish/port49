package ci

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Plan 13, Task 10: compose reports health and restarts nothing on it, so its probes may show
// readiness. Each runs its own binary's healthcheck subcommand with --ready.
func TestComposeHealthchecksPassReady(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "deploy", "compose", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Services map[string]struct {
			Healthcheck *struct {
				Test []string `yaml:"test"`
			} `yaml:"healthcheck"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"port49d": "/usr/local/bin/port49d", "port49-broker": "/usr/local/bin/port49-broker"}
	for svc := range want {
		s, ok := c.Services[svc]
		if !ok || s.Healthcheck == nil {
			t.Errorf("service %s has no healthcheck", svc)
		}
	}
	checked := 0
	for svc, s := range c.Services {
		if s.Healthcheck == nil {
			continue
		}
		checked++
		bin, ok := want[svc]
		if !ok {
			t.Errorf("service %s has a healthcheck this test does not know the binary of", svc)
			continue
		}
		test := s.Healthcheck.Test
		if len(test) < 4 || test[0] != "CMD" || test[1] != bin || test[2] != "healthcheck" {
			t.Errorf("%s: healthcheck.test is %v, want CMD %s healthcheck ...", svc, test, bin)
			continue
		}
		ready := false
		for _, a := range test[3:] {
			if a == "--ready" {
				ready = true
			}
			if a == "--live" {
				t.Errorf("%s: healthcheck passes --live, which does not exist", svc)
			}
		}
		if !ready {
			t.Errorf("%s: healthcheck.test %v does not pass --ready", svc, test)
		}
	}
	if checked == 0 {
		t.Error("no service has a healthcheck")
	}
}
