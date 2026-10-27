//go:build lab

package lab

import (
	"os"
	"path/filepath"
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
		"https://etcd-1:2379", "/etc/port49/etcd/port49d-key.pem", "/run/port49/port49d.sock"} {
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
	if strings.Contains(files["port49-broker.env"], "PORT49_KEY_LAB") || !strings.Contains(files["port49d.env"], "PORT49_KEY_LAB=") {
		t.Errorf("the device key is not port49d's alone")
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
