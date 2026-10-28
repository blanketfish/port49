package port49d

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startDaemonOn runs port49d on the config at cfgPath until the returned stop
// is called, and returns the broker's address; out is the stderr it writes.
func startDaemonOn(t *testing.T, cfgPath string, out *syncBuffer) (addr string, stop func()) {
	t.Helper()
	n := strings.Count(out.String(), "port49d: broker listening on ")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not return")
		}
	}
	t.Cleanup(stop)
	waitForCount(t, out, "port49d: broker listening on ", n+1)
	all := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindAllStringSubmatch(out.String(), -1)
	return all[len(all)-1][1], stop
}

// port49d revoke --offline writes the mark into broker.revocations_file, and
// the next start refuses the principal's mint with credential_revoked. --list
// names the mark and its origin while it stands, and --lift takes it out
// (spec §12; plan 12b Task 3e).
func TestOfflineRevokeOnPort49d(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, io.Discard
	b := brokerConfig(t, minimalPolicy).Broker
	pki := filepath.Dir(b.ClientCAFile)
	cfgPath := writeRunConfig(t, b)
	const alice = "user:alice@example.com"
	offline := func(args ...string) (int, string, string) {
		var log, say bytes.Buffer
		code := offlineRevokeDaemon(append([]string{"--offline", "--config", cfgPath}, args...), &log, &say)
		return code, log.String(), say.String()
	}

	if code, _, say := offline("--list"); code != 0 || !strings.Contains(say, "no revocation is in force") {
		t.Fatalf("an empty list: exit %d: %s", code, say)
	}
	code, log, say := offline("--principal", alice)
	if code != 0 || !strings.Contains(say, "revoked "+alice) || !strings.Contains(say, "broker.revocations_file") {
		t.Fatalf("revoke: exit %d: %s", code, say)
	}
	if !strings.Contains(log, `"event":"revoke"`) {
		t.Errorf("the decision log (stdout of the command) holds no revoke record: %s", log)
	}
	// The file holds the mark, its origin the uid that ran the command.
	raw, err := os.ReadFile(b.RevocationsFile)
	if err != nil || !strings.Contains(string(raw), alice) || !strings.Contains(string(raw), `"origin": "offline uid `) {
		t.Fatalf("the revocations file after the mark (%v): %s", err, raw)
	}
	if code, _, say := offline("--list"); code != 0 || !strings.Contains(say, "principal "+alice+" since ") ||
		!strings.Contains(say, "(offline uid ") {
		t.Fatalf("the list: exit %d: %s", code, say)
	}

	// A start loads it before it serves: alice's mint is refused.
	addr, stop := startDaemonOn(t, cfgPath, &out)
	status, body, err := postAsAlice(pki, addr)
	if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice's mint with the mark standing: %d %q %v", status, body, err)
	}
	stop()

	// The lift removes it.
	if code, _, say := offline("--principal", alice, "--lift"); code != 0 || !strings.Contains(say, "lifted") {
		t.Fatalf("lift: exit %d: %s", code, say)
	}
	if code, _, say := offline("--list"); code != 0 || !strings.Contains(say, "no revocation is in force") {
		t.Fatalf("the list after the lift: exit %d: %s", code, say)
	}
	addr, _ = startDaemonOn(t, cfgPath, &out)
	if status, body, err := postAsAlice(pki, addr); err != nil || status != http.StatusOK {
		t.Fatalf("alice's mint after the lift: %d %q %v", status, body, err)
	}
}

// It refuses a port49d that answers /readyz on its metrics listener, saying
// where the live revocation goes, and writes nothing.
func TestOfflineRevokeOnPort49dRefusesARunningDaemon(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, io.Discard
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	listen := regexp.MustCompile(`(?m)^metrics_listen: .*$`)
	if !listen.Match(raw) {
		t.Fatal("the fixture has no metrics_listen")
	}
	if err := os.WriteFile(cfgPath, listen.ReplaceAll(raw, []byte("metrics_listen: \"127.0.0.1:"+strconv.Itoa(port)+"\"")), 0o600); err != nil {
		t.Fatal(err)
	}
	var log, say bytes.Buffer
	args := []string{"--offline", "--config", cfgPath, "--principal", "user:alice@example.com"}
	startDaemonOn(t, cfgPath, &out)
	before, _ := os.ReadFile(b.RevocationsFile)
	if code := offlineRevokeDaemon(args, &log, &say); code != 1 ||
		!strings.Contains(say.String(), "something answers /readyz on 127.0.0.1:"+strconv.Itoa(port)) ||
		!strings.Contains(say.String(), "use port49 revoke") {
		t.Fatalf("exit %d: %s", code, say.String())
	}
	if after, _ := os.ReadFile(b.RevocationsFile); !bytes.Equal(before, after) {
		t.Fatal("a refused revocation changed broker.revocations_file")
	}
	if log.Len() != 0 {
		t.Fatal("a refused revocation wrote a decision record")
	}
}

// A port49d with no broker: block holds no revocations: it refuses and names
// port49-broker revoke --offline.
func TestOfflineRevokeOnPort49dWithNoBrokerNamesTheBrokersTool(t *testing.T) {
	daemonCfg, _ := etcdSplit(t) // a split daemon: policy:, no broker:
	for _, args := range [][]string{{"--principal", "user:alice@example.com"}, {"--list"}} {
		var log, say bytes.Buffer
		if code := offlineRevokeDaemon(append([]string{"--offline", "--config", daemonCfg}, args...), &log, &say); code != 1 ||
			!strings.Contains(say.String(), "no broker: block") || !strings.Contains(say.String(), "port49-broker revoke --offline") {
			t.Errorf("%v: exit %d: %s", args, code, say.String())
		}
	}
}

// port49-broker revoke --offline --list prints each mark in force with its
// origin, read from etcd on the broker's identity with no broker running.
func TestOfflineListOnTheBroker(t *testing.T) {
	f := splitFleet(t)
	var log, say bytes.Buffer
	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--list"}, &log, &say); code != 0 ||
		!strings.Contains(say.String(), "no revocation is in force") {
		t.Fatalf("an empty list: exit %d: %s", code, say.String())
	}
	for _, args := range [][]string{
		{"--principal", "user:alice@example.com"},
		{"--cert-issuer", "CN=Corp CA,O=Example", "--cert-serial", "3f9a01"},
	} {
		say.Reset()
		if code := offlineRevoke(append([]string{"--offline", "--config", f.broker}, args...), &log, &say); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, say.String())
		}
	}
	say.Reset()
	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--list"}, &log, &say); code != 0 {
		t.Fatalf("the list: exit %d: %s", code, say.String())
	}
	var lines []string // the store's start line (its certificate's validity) is said before the marks
	for _, l := range strings.Split(strings.TrimSpace(say.String()), "\n") {
		if strings.Contains(l, " since ") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("the list holds %d lines, want 2:\n%s", len(lines), say.String())
	}
	for _, l := range lines {
		if !strings.Contains(l, " since ") || !strings.Contains(l, "(offline uid ") {
			t.Errorf("a mark with no time or origin: %q", l)
		}
	}
	if !strings.Contains(say.String(), "principal user:alice@example.com since ") ||
		!strings.Contains(say.String(), `certificate issuer="CN=Corp CA,O=Example" serial=3f9a01 since `) {
		t.Errorf("the list does not name both marks:\n%s", say.String())
	}
	// --list takes nothing else.
	say.Reset()
	if code := offlineRevoke([]string{"--offline", "--list", "--lift"}, &log, &say); code != 2 {
		t.Errorf("--list --lift: exit %d: %s", code, say.String())
	}
}
