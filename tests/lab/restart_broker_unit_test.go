//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// docker logs -f ends with the container it followed, and a restarted broker is a new process whose
// records nobody reads unless the log is followed again. The OIDC end to end restarts the broker
// after init-issuer and then waits on its revoke records in broker.log; with no second follower
// every wait ran out (the 2026-11-05 run). restartBroker restarts and follows again from before
// the restart, appending to the same files.
func TestRestartBrokerFollowsTheNewProcessAgain(t *testing.T) {
	bin, calls := t.TempDir(), filepath.Join(t.TempDir(), "calls")
	script := "#!/bin/sh\necho \"$@\" >> " + calls + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	dir := t.TempDir()
	c := &composeStack{dir: dir, local: dir, config: dir, logPath: filepath.Join(dir, "compose.log"),
		brokerLog: filepath.Join(dir, "broker.log"), brokerErr: filepath.Join(dir, "broker.err")}
	if _, err := c.restartBroker(); err != nil {
		t.Fatal(err)
	}
	// the follower is a started process: wait for the fake docker to record its call
	var raw []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if raw, _ = os.ReadFile(calls); strings.Count(string(raw), "\n") >= 2 {
			break
		}
	}
	c.stopFollowers()
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var restart, logs = -1, -1
	for i, l := range lines {
		switch {
		case strings.Contains(l, " restart port49-broker"):
			restart = i
		case strings.HasPrefix(l, "logs -f --since ") && strings.HasSuffix(l, " "+composeProject+"-port49-broker-1"):
			logs = i
		}
	}
	if restart < 0 || logs < 0 || logs < restart {
		t.Fatalf("the broker's log is not followed again after its restart: %q", lines)
	}
	if strings.Contains(lines[logs], "--since 0s") {
		t.Errorf("the second follower starts at 0s, after the restarted broker's first lines: %q", lines[logs])
	}
}
