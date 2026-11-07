//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// L65's driver builds port49.Agent from the tree's library. d97c52c6 removed
// its socket parameter, and the driver kept passing it: every L65 cell on
// 2026-11-06 failed with a TypeError before it reached a device.
func TestL65DriverPassesOnlyParametersAgentTakes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "clients", "python", "src", "port49", "client.py"))
	if err != nil {
		t.Fatal(err)
	}
	sig := regexp.MustCompile(`(?s)class Agent:.*?def __init__\(self([^)]*)\)`).FindStringSubmatch(string(b))
	if sig == nil {
		t.Fatal("Agent.__init__ not found in client.py")
	}
	var params []string
	for _, p := range strings.Split(sig[1], ",") {
		if name, _, _ := strings.Cut(strings.TrimSpace(p), "="); name != "" {
			params = append(params, name)
		}
	}
	if !slices.Contains(params, "port49") {
		t.Fatalf("read Agent parameters %v", params)
	}
	call := regexp.MustCompile(`port49\.Agent\(([^)]*)\)`).FindStringSubmatch(l64DriverScript)
	if call == nil {
		t.Fatal("the driver builds no port49.Agent")
	}
	for _, kw := range regexp.MustCompile(`([a-z_0-9]+)=`).FindAllStringSubmatch(call[1], -1) {
		if !slices.Contains(params, kw[1]) {
			t.Errorf("the driver passes %s= to port49.Agent, which takes %v", kw[1], params)
		}
	}
}

// The library finds a non-default agent through PORT49_TEST_AGENT_SOCKET
// alone, which its CLI children inherit (d97c52c6).
func TestL65PythonEnvPointsTheCLIAtTheRunsAgent(t *testing.T) {
	e := &l64Env{home: "/w/home", sock: "/w/a/agent.sock", cfgPath: "/w/ssh_config", node: "leaf1"}
	if !slices.Contains(e.pythonEnv(), "PORT49_TEST_AGENT_SOCKET=/w/a/agent.sock") {
		t.Error("the driver's env does not name the run's agent socket")
	}
}
