//go:build lab

package lab

import (
	"github.com/rhwendt/port49/internal/policy"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The lab's compose files name in-container paths and the lab's keys by
// environment, with the device key in port49d's env alone, and an extra
// device at the stack's gateway so a rewritten source is recorded, not
// refused (L39).
func TestComposeLabFilesNameTheContainersPaths(t *testing.T) {
	// Relative to the package: `root` is empty under `make lab-unit`.
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files, err := composeLabFiles(read("port49d-lab.yaml"), read(filepath.Join("slice", "broker.yaml")),
		read(filepath.Join("slice", "policy.yaml")), read("inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The slice's broker listens on its container's loopback (127.0.0.1:8449);
	// published through 127.0.0.1:8449:8443 that is unreachable, so the
	// compose broker listens on every address of its container, on 8443.
	if b := files["port49-broker.yaml"]; !strings.Contains(b, `listen: ":8443"`) || strings.Contains(b, "127.0.0.1:8449") {
		t.Errorf("port49-broker.yaml does not listen on :8443 in its container:\n%s", b)
	}
	d := files["port49d.yaml"]
	for _, want := range []string{`listen: ":49"`, "/etc/port49/policy.yaml", "/etc/port49/inventory.yaml",
		"https://etcd-1:2379", "/etc/port49/etcd/port49d-key.pem"} {
		if !strings.Contains(d, want) {
			t.Errorf("port49d.yaml lacks %q:\n%s", want, d)
		}
	}
	if strings.Contains(files["port49-broker.yaml"], "PORT49_KEY_LAB") {
		t.Errorf("port49-broker.yaml names the device key's secret:\n%s", files["port49-broker.yaml"])
	}
	if !strings.Contains(files["inventory.yaml"], composeGateway) {
		t.Errorf("inventory.yaml lists no device at the gateway %s", composeGateway)
	}
	// The health checks are the daemon's alone (decision 37), and the context
	// cache is off in the lab: L41 measures nothing about it.
	if !strings.Contains(d, "health: {interval: 1s, close_after: 5, open_after: 3}") {
		t.Errorf("port49d.yaml names no health checks:\n%s", d)
	}
	if strings.Contains(files["port49-broker.yaml"], "health:") {
		t.Errorf("port49-broker.yaml names health checks:\n%s", files["port49-broker.yaml"])
	}
	for _, name := range []string{"port49d.yaml", "port49-broker.yaml"} {
		if strings.Contains(files[name], "context_cache") {
			t.Errorf("%s names a context cache:\n%s", name, files[name])
		}
	}
	requireDaemonPolicy(t, files)
	// Secrets are files, as the product's compose has them (decision 54 ruling 2): no environment
	// reference is left in a config or the policy, and each file ref has its source in local/.
	for _, name := range []string{"port49d.yaml", "port49-broker.yaml", "policy.yaml"} {
		if strings.Contains(files[name], "secret_ref: env:") {
			t.Errorf("%s still names a secret by environment, which the compose stack does not pass:\n%s", name, files[name])
		}
	}
	for _, want := range []string{"secrets/port49d-encryption.key", "secrets/broker-encryption.key", "keys/lab_key_v1"} {
		if files[want] == "" {
			t.Errorf("no source file %s for setup to place", want)
		}
	}
	if !strings.Contains(files["policy.yaml"], "file:"+composeDeviceKeyPath) ||
		!strings.Contains(files["port49d.yaml"], "file:"+composeEncKeyPath) ||
		!strings.Contains(files["port49-broker.yaml"], "file:"+composeEncKeyPath) {
		t.Errorf("a file reference is missing")
	}
}

// The dark bound under the health checks (decision 37): close_after ×
// interval + call_timeout, with 5s for the 250ms poll and the process.
func TestHealthDarkBound(t *testing.T) {
	if got, want := healthDarkBound(time.Second, 500*time.Millisecond, 5), 10500*time.Millisecond; got != want {
		t.Fatalf("healthDarkBound = %s, want %s", got, want)
	}
}

// The userland proxy's mode is read from the processes serving the
// published port: a docker-proxy for 172.100.100.1:49 is "on".
func TestProxyModeReadsTheProcessList(t *testing.T) {
	on := "1234 /usr/bin/docker-proxy -proto tcp -host-ip 172.100.100.1 -host-port 49 -container-ip 172.30.49.5 -container-port 49\n"
	if proxyModeOf(on) != "on" || proxyModeOf("1 /sbin/init\n") != "off" {
		t.Fatal(proxyModeOf(on), proxyModeOf("1 /sbin/init\n"))
	}
}

// The readiness failure carries each service's state and exit code in one structured line, and
// nothing else of ps's output.
func TestComposeStatesKeepsOnlyServiceStateAndExitCode(t *testing.T) {
	got := composeStates("time=x level=warn msg=\"a warning\"\nport49-broker=exited/1\nport49d=running/0\netcd-1=running/0\n")
	if want := "port49-broker=exited/1 port49d=running/0 etcd-1=running/0"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestComposeExitNamesTheExitCodeOrThatItDidNotRun(t *testing.T) {
	if got := composeExit(exec.Command("sh", "-c", "exit 3").Run()); got != "exit 3" {
		t.Errorf("got %q", got)
	}
	if got := composeExit(exec.Command("/nonexistent/port49-test").Run()); got != "did not run" {
		t.Errorf("got %q", got)
	}
}

// placeComposeSecrets writes the secret files setup places from local/, at the paths the moved configs name
// under dir (etc for /etc/port49, run for /run/port49), so a loader that reads them finds them.
func placeComposeSecrets(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for src, dst := range map[string]string{"secrets/broker-encryption.key": "etc/secrets/encryption.key",
		"keys/lab_key_v1": "run/keys/lab_key_v1"} {
		path := filepath.Join(dir, dst)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(files[src]), 0o400); err != nil {
			t.Fatal(err)
		}
	}
}

// Only a line that begins with a daemon's own prefix is quoted, whole and cut to 200 characters.
func TestDaemonLineQuotesOnlyTheDaemonsOwnFirstLine(t *testing.T) {
	logs := "2026/10/31 library chatter\nport49-broker: config: the first thing it said\nport49-broker: a second line\n"
	if got := daemonLine(logs); got != "port49-broker: config: the first thing it said" {
		t.Errorf("got %q", got)
	}
	if got := daemonLine("something else\nnot port49d: inside\n"); got != "" {
		t.Errorf("a line without the prefix was quoted: %q", got)
	}
	if got := daemonLine("port49d: " + strings.Repeat("x", 500)); len(got) > 200 {
		t.Errorf("a line of %d characters", len(got))
	}
}

// envRef is a secret reference by environment variable in any key of a config or policy.
var envRef = regexp.MustCompile(`(?m)^[^#\n]*secret_ref: env:\S+`)

// requireDaemonPolicy is the check port49d and the broker make of the compose policy at start: it
// parses and declares its keys: block (decision 53 ruling 3), and holds the lab key set the
// inventory's key group names, read from the file placeComposeSecrets writes.
func requireDaemonPolicy(t *testing.T, files map[string]string) {
	t.Helper()
	p, err := policy.Parse([]byte(files["policy.yaml"]), policy.Env{})
	if err != nil {
		t.Fatalf("the compose policy does not parse: %v", err)
	}
	if !p.KeysDeclared() {
		t.Fatalf("the compose policy declares no keys: block, which port49d and the broker refuse at start:\n%s", files["policy.yaml"])
	}
	for name, body := range files {
		if strings.HasSuffix(name, ".yaml") && envRef.MatchString(body) {
			t.Fatalf("%s still names a secret by environment (%s), which the compose stack passes no environment for",
				name, envRef.FindString(body))
		}
	}
	if !strings.Contains(files["policy.yaml"], "lab_key:") || !strings.Contains(files["policy.yaml"], "file:"+composeDeviceKeyPath) {
		t.Fatalf("the compose policy holds no lab_key set read from %s:\n%s", composeDeviceKeyPath, files["policy.yaml"])
	}
}

// A bind password or a client secret named by environment is found as a key's would be.
func TestEnvRefFindsEverySecretRefKey(t *testing.T) {
	for _, line := range []string{"  current: {id: c1, secret_ref: env:X}", "      password_secret_ref: env:LAB_X",
		"  client_secret_ref: env:Y"} {
		if !envRef.MatchString(line) {
			t.Errorf("%q is not found", line)
		}
	}
	if envRef.MatchString("# secret_ref: env:X\n  current: {secret_ref: file:/a}") {
		t.Error("a comment or a file ref was found")
	}
}

// A daemon's exit is named by a tag from a fixed list, so a line the filter hides (it says "password")
// still gives the run its cause without quoting the line.
func TestCrashTagsNameTheCauseFromAFixedList(t *testing.T) {
	for logs, want := range map[string]string{
		"port49-broker: crypt: the directory store (x) was last written by a process whose current key is \"c9\", which this configuration does not hold": "directory_key_window",
		"port49-broker: directory store: reading its key window: boom":                                                                                    "directory_key_window",
		"port49-broker: session store: reading its cluster id: boom":                                                                                      "two_stores_check",
		"port49-broker: issuing CA record differs from the one on disk":                                                                                   "issuer_record",
		"port49-broker: broker listener on :8443: address in use":                                                                                         "listener",
		"port49d: policy.file /etc/port49/policy.yaml: the policy declares no keys: block":                                                                "policy",
		"port49-broker: something nobody listed":                                                                                                          "unlisted",
		"port49-broker: issuance: issuing-ca.pem is missing\nport49-broker: directory store: reading its key window: boom\nchatter":                       "directory_key_window",
		"library chatter only": "",
	} {
		if got := crashTag(logs); got != want {
			t.Errorf("%q: tag %q, want %q", logs, got, want)
		}
	}
}
