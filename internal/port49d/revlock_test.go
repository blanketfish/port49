package port49d

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// withMetricsPort sets metrics_listen in the config at cfgPath to a free
// port, and returns the port.
func withMetricsPort(t *testing.T, cfgPath string) int {
	t.Helper()
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
	return port
}

// The lock is on a sidecar beside the file, mode 0600, held by one process at
// a time, and free again once released.
func TestRevocationsLockIsASidecarOneHolderAtATime(t *testing.T) {
	file := filepath.Join(safeDir(t), "revocations.json")
	release, err := lockRevocations(file)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(file + ".lock")
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the sidecar: %v, %v", st, err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("the lock created the file itself")
	}
	if _, err := lockRevocations(file); err != errRevocationsLocked {
		t.Fatalf("a second holder got: %v", err)
	}
	release()
	again, err := lockRevocations(file)
	if err != nil {
		t.Fatalf("after the release: %v", err)
	}
	again()
	// A lock held across a save: the save renames a new file over the old one,
	// and the sidecar is untouched.
	held, _ := lockRevocations(file)
	defer held()
	if err := os.WriteFile(file+".new", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file+".new", file); err != nil {
		t.Fatal(err)
	}
	if _, err := lockRevocations(file); err != errRevocationsLocked {
		t.Fatalf("a rename of the file freed the lock: %v", err)
	}
}

// An offline revoke refuses while another process holds the lock (a port49d
// that is starting, or running on a config this one cannot see), changes
// nothing, and says what to do.
func TestOfflineRevokeOnPort49dRefusesWhileTheFileIsLocked(t *testing.T) {
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	release, err := lockRevocations(b.RevocationsFile)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	before, _ := os.ReadFile(b.RevocationsFile)
	for _, args := range [][]string{{"--principal", "user:alice@example.com"}, {"--list"}} {
		var log, say bytes.Buffer
		code := offlineRevokeDaemon(append([]string{"--offline", "--config", cfgPath}, args...), &log, &say)
		if code != 1 || !strings.Contains(say.String(), "is locked: a port49d is running or starting on it") ||
			!strings.Contains(say.String(), "revoke through the API") || !strings.Contains(say.String(), "nothing was changed") {
			t.Fatalf("%v: exit %d: %s", args, code, say.String())
		}
		if log.Len() != 0 {
			t.Fatalf("%v: a refused command wrote a decision record", args)
		}
	}
	if after, _ := os.ReadFile(b.RevocationsFile); !bytes.Equal(before, after) {
		t.Fatal("a refused revocation changed broker.revocations_file")
	}
}

// A port49d whose /readyz answers 503, as one still starting does, is refused
// too: any answer on the metrics listener is a port49d.
func TestOfflineRevokeOnPort49dRefusesAStartingDaemon(t *testing.T) {
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	port := withMetricsPort(t, cfgPath)
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	defer srv.Close()
	var log, say bytes.Buffer
	code := offlineRevokeDaemon([]string{"--offline", "--config", cfgPath, "--principal", "user:alice@example.com"}, &log, &say)
	if code != 1 || !strings.Contains(say.String(), "something answers /readyz on 127.0.0.1:"+strconv.Itoa(port)) {
		t.Fatalf("exit %d: %s", code, say.String())
	}
}

// signalWriter is a decision log whose first write blocks until released: the
// offline command is then held between taking its lock and finishing.
type signalWriter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (w *signalWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return len(p), nil
}

// A port49d that starts while an offline revoke is mid-run does not load the
// file until the command is done, so it loads the mark and its next persist
// cannot write it away (plan 12b Task 3e review m-1).
func TestADaemonStartingDuringAnOfflineRevokeKeepsTheMark(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, io.Discard
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	w := &signalWriter{entered: make(chan struct{}), release: make(chan struct{})}
	var say bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- offlineRevokeDaemon([]string{"--offline", "--config", cfgPath, "--principal", "user:alice@example.com"}, w, &say)
	}()
	select {
	case <-w.entered:
	case <-time.After(20 * time.Second):
		t.Fatal("the offline revoke never reached its decision record")
	}
	started := make(chan struct{})
	go func() {
		defer close(started)
		startDaemonOn(t, cfgPath, &out)
	}()
	time.Sleep(700 * time.Millisecond) // the daemon is at its lock
	if strings.Contains(out.String(), "revocation(s) in force") {
		t.Fatalf("port49d loaded broker.revocations_file while an offline revoke held it:\n%s", out.String())
	}
	close(w.release)
	if code := <-done; code != 0 {
		t.Fatalf("offline exit %d: %s", code, say.String())
	}
	select {
	case <-started:
	case <-time.After(60 * time.Second):
		t.Fatalf("port49d did not start once the offline command finished:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "port49d: broker: 1 revocation(s) in force from") {
		t.Fatalf("port49d started without the mark:\n%s", out.String())
	}
}

// A port49d that waits out the lock wait for a lock nobody lets go of
// exits saying who to look for, rather than serving without the file.
func TestADaemonExitsWhenTheLockIsNeverFreed(t *testing.T) {
	old := revocationsLockWait
	revocationsLockWait = 300 * time.Millisecond
	t.Cleanup(func() { revocationsLockWait = old })
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	release, err := lockRevocations(b.RevocationsFile)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	said, runErr := runExpectingRefusal(t, cfgPath)
	if runErr == nil || !strings.Contains(runErr.Error(), "is locked") || !strings.Contains(runErr.Error(), "port49d revoke --offline") ||
		strings.Contains(said, "listening") {
		t.Fatalf("%v\n%s", runErr, said)
	}
}
