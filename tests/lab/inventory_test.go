//go:build lab

package lab

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

const (
	inventoryAddr        = "127.0.0.1:18443"
	inventoryMetricsAddr = "127.0.0.1:19050"
)

// labInventory is port49-inventory as the lab runs it (plan 6b Task 19): on
// the host, its file source a private copy the test edits, the lab inventory
// PKI, and a signing key `port49 inventory keygen` wrote for this run.
type labInventory struct {
	cmd                      *exec.Cmd
	dir, source, policy, pki string
	pubFile, errPath         string
	done                     chan struct{}
}

// startInventory starts the service with source as its file source's
// content and a copy of policyPath as its policy. It refuses to start beside
// a service this run does not own. The service syncs at start, so it is
// ready — /readyz 200 — once it has published bundle 1.
func (l *lab) startInventory(t *testing.T, source, policyPath string) *labInventory {
	t.Helper()
	if c, err := net.DialTimeout("tcp", inventoryAddr, 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("something already listens on %s, most likely a port49-inventory left by an interrupted run; "+
			"stop it: pkill -f bin/port49-inventory", inventoryAddr)
	}
	logs := filepath.Join(root, "tests", "lab", "logs")
	li := &labInventory{dir: filepath.Join(logs, "inventory-"+l.p.name), pki: filepath.Join(logs, "inventory-pki"),
		errPath: filepath.Join(logs, "port49-inventory-"+l.p.name+".log"), done: make(chan struct{})}
	if err := os.RemoveAll(li.dir); err != nil {
		t.Fatal(err)
	}
	// 0755 whatever the umask: the file source is read behind the fence,
	// which refuses a group-writable directory (spec §5.1.3).
	for _, d := range []string{li.dir, filepath.Join(li.dir, "src")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := testpki.WriteInventoryLab(li.pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(li.dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	// Its output names the files and the key_id, never the key; it is
	// printed only on a failure.
	if out, err := exec.Command(filepath.Join(root, "bin", "port49"), "inventory", "keygen", "--dir", keys).CombinedOutput(); err != nil {
		t.Fatalf("port49 inventory keygen (run `make build` first): %v: %s", err, out)
	}
	li.pubFile = filepath.Join(keys, "signing.pub")
	li.source, li.policy = filepath.Join(li.dir, "src", "inventory.yaml"), filepath.Join(li.dir, "policy.yaml")
	li.writeSource(t, source)
	li.writePolicy(t, policyPath)
	cfg := filepath.Join(li.dir, "port49-inventory.yaml")
	body := fmt.Sprintf(`listen: %s
metrics_listen: %s
tls_cert_file: %s/%s
tls_key_file: %s/%s
client_ca_file: %s/%s
readers: [%q]
syncers: ["user:alice@slice.port49.test"]
signing_key_file: %s/signing.key
policy_file: %s
state_dir: %s/state
sync: [{name: lab_file, type: file, path: %s}]
`, inventoryAddr, inventoryMetricsAddr, li.pki, testpki.InvServerCert, li.pki, testpki.InvServerKey, li.pki,
		testpki.InvCA, testpki.InvDaemonID, keys, li.policy, li.dir, li.source)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	errFile, err := os.Create(li.errPath)
	if err != nil {
		t.Fatal(err)
	}
	li.cmd = exec.Command(filepath.Join(root, "bin", "port49-inventory"), "-config", cfg)
	li.cmd.Dir, li.cmd.Stdout, li.cmd.Stderr = root, errFile, errFile
	if err := li.cmd.Start(); err != nil {
		errFile.Close()
		t.Fatal(err)
	}
	go func() { li.cmd.Wait(); errFile.Close(); close(li.done) }()
	t.Cleanup(li.stop)
	probe := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if resp, err := probe.Get("http://" + inventoryMetricsAddr + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("l29: port49-inventory ready on %s (log %s)", inventoryAddr, li.errPath)
				return li
			}
		}
		select {
		case <-li.done:
			raw, _ := os.ReadFile(li.errPath)
			t.Fatalf("port49-inventory exited during startup:\n%s", raw)
		default:
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(li.errPath)
			t.Fatalf("port49-inventory not ready in 30s:\n%s", raw)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// writeSource writes the file source as a deployment would: 0644 under a
// 0755 directory, which the fence passes.
func (li *labInventory) writeSource(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(li.source, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (li *labInventory) writePolicy(t *testing.T, from string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(li.policy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// inventorySyncWait bounds `port49 inventory sync` here. A file-source sync
// is instant; the tool's own wait (6m, past sync_timeout) is for real sources.
const inventorySyncWait = 2 * time.Minute

// sync runs `port49 inventory sync` as the operator and returns its output,
// with the exit status appended when it failed. Nothing in it is a secret:
// the tool prints the bundle, its changes and the service's reasons.
func (li *labInventory) sync(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), inventorySyncWait)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), "inventory", "sync",
		"--service", "https://"+inventoryAddr, "--ca", filepath.Join(li.pki, testpki.InvCA),
		"--cert", filepath.Join(li.pki, testpki.InvOperatorCert),
		"--key", filepath.Join(li.pki, testpki.InvOperatorKey)).CombinedOutput()
	if err != nil {
		out = append(out, fmt.Sprintf("(exit: %v)\n", err)...)
	}
	t.Logf("l29: port49 inventory sync: %s", firstLine(string(out)))
	return string(out)
}

func (li *labInventory) stop() {
	if li.cmd == nil || li.cmd.Process == nil {
		return
	}
	li.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-li.done:
	case <-time.After(10 * time.Second):
		li.cmd.Process.Kill()
		<-li.done
	}
	li.cmd = nil
}

// labSourceFrom is labSource over the real lab inventory.
func labSourceFrom(t *testing.T) string {
	t.Helper()
	return labSource(labInventoryText(t))
}

func labInventoryText(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// privateDir is tests/lab/logs/<name>, created afresh with mode 0700: port49d
// reads broker.policy_file behind the write fence, which refuses a file in a
// directory anyone else could write, and tests/lab/logs is 0775 under the
// usual desktop umask (privatePolicy).
func privateDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "logs", name)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// serviceConfig is the lab's port49d.yaml with its inventory from li: the
// inventory_file line removed, a second key lab_key2 (the rotation key) for
// the re-key phase, the slice's broker block on policy, and inventory.service.
// policy must be in a directory privateDir made. port49d's state_dir is
// removed first, so each start is a cold start from the service.
func (l *lab) serviceConfig(t *testing.T, li *labInventory, policy string) string {
	t.Helper()
	base, err := l.configPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORT49_L28_NEW_KEY", labcreds.RotationKey)
	body := regexp.MustCompile(`(?m)^inventory_file: .*\n`).ReplaceAllString(string(raw), "")
	if !strings.Contains(body, l28Anchor) {
		t.Fatalf("%s has no standing lab_key block", base)
	}
	body = strings.Replace(body, l28Anchor, l28Anchor+"  lab_key2:\n    current: {version: 1, secret_env: PORT49_L28_NEW_KEY}\n", 1)
	pki := filepath.Join(root, "tests", "lab", "logs", "slice-pki")
	if err := testpki.WriteLab(pki, "alice@slice.port49.test", time.Now()); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "tests", "lab", "logs", "port49d-state-"+l.p.name)
	if err := os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}
	body += fmt.Sprintf(`broker:
  listen: "127.0.0.1:8449"
  tls_cert_file: %[1]s/%[2]s
  tls_key_file: %[1]s/%[3]s
  client_ca_file: %[1]s/%[4]s
  policy_file: %[5]s
  policy_watch_interval: 1s
inventory:
  service:
    url: https://%[6]s
    ca_file: %[7]s/%[8]s
    tls_cert_file: %[7]s/%[9]s
    tls_key_file: %[7]s/%[10]s
    verify_key_files: [%[11]s]
    poll_interval: 5s
    state_dir: %[12]s
`, pki, testpki.LabServerCert, testpki.LabServerKey, testpki.LabCA, policy, inventoryAddr, li.pki, testpki.InvCA,
		testpki.InvDaemonCert, testpki.InvDaemonKey, li.pubFile, state)
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-lab-"+l.p.name+"-service.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// errMark is the current end of port49d's stderr log, for waitForLine: the
// log is appended across restarts, so a wait reads only what follows a mark.
func (l *lab) errMark() int64 {
	fi, err := os.Stat(l.errPath)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// waitForLine polls port49d's stderr log, from offset from, for a line
// containing want, and returns when it appeared. At within it gives up and
// returns false: the caller records "not observed", which fails the run.
func (l *lab) waitForLine(t *testing.T, from int64, want string, within time.Duration) (time.Time, bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if raw, err := os.ReadFile(l.errPath); err == nil && int64(len(raw)) >= from &&
			strings.Contains(string(raw[from:]), want) {
			return time.Now(), true
		}
		if !time.Now().Before(deadline) {
			t.Logf("l29: port49d did not say %q within %s", want, within)
			return time.Time{}, false
		}
		time.Sleep(250 * time.Millisecond)
	}
}
