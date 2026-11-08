package ci

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/healthcheck"
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
				Test    []string `yaml:"test"`
				Timeout string   `yaml:"timeout"`
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
		// The probe must give up before compose does, so a hung metrics port shows the probe's own line.
		if d, err := time.ParseDuration(s.Healthcheck.Timeout); err != nil || d <= healthcheck.Timeout {
			t.Errorf("%s: healthcheck.timeout %q must be a duration greater than the probe's own %s", svc,
				s.Healthcheck.Timeout, healthcheck.Timeout)
		}
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
