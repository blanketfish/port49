package port49d

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// silentEndpoint is a host:port that accepts TCP and never speaks: a member
// cut off from this process.
func silentEndpoint(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { <-done; c.Close() }()
		}
	}()
	t.Cleanup(func() { close(done); l.Close() })
	return l.Addr().String()
}

// endpointsAre rewrites the directory store's endpoint list in the file at
// path from the one member behind addr to list (each a host:port).
func endpointsAre(t *testing.T, path, addr string, list ...string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := "endpoints: [https://" + addr + "]"
	body := strings.Replace(string(raw), old, "endpoints: [https://"+strings.Join(list, ", https://")+"]", 1)
	if body == string(raw) {
		t.Fatalf("%s has no %q", path, old)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// L74 cell (f)'s shape: one directory member answers and another does not.
// The broker starts live: Open does not wait on the silent member
// (clientv3's RejectOldCluster would fail it, and send a healthy start to
// the snapshot), and no snapshot is served.
func TestABrokerWithOneSilentDirectoryMemberStartsLive(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	var log syncBuffer
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	endpointsAre(t, f.broker, f.dproxy.Addr(), f.dproxy.Addr(), silentEndpoint(t))
	start := time.Now()
	startBroker(t, f.broker, &out, 1)
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("the start took %v", d)
	}
	if strings.Contains(out.String(), "serving from") || strings.Contains(out.String(), "not answering") {
		t.Fatalf("a directory with a live member was treated as down:\n%s", out.String())
	}
}

// When the directory's only endpoint is silent, a broker with a young
// snapshot serves from it (R19) and does not exit.
func TestABrokerWhoseOnlyDirectoryEndpointIsSilentServesTheSnapshot(t *testing.T) {
	var out, log syncBuffer
	e, o, every := stderr, stdout, snapshotEvery
	t.Cleanup(func() { stderr, stdout, snapshotEvery = e, o, every })
	stderr, stdout, snapshotEvery = &out, &log, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stopB := startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	if err := stopB(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	endpointsAre(t, f.broker, f.dproxy.Addr(), silentEndpoint(t))
	startBroker(t, f.broker, &out, 2)
	if want := "port49-broker: directory store: not answering; serving from"; !strings.Contains(out.String(), want) {
		t.Fatalf("no %q:\n%s", want, out.String())
	}
}
