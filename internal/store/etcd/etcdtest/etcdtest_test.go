package etcdtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// A port another process takes between the pick and the bind is the
// machine's race, not the test's, and any retry can lose it too (7d's
// flake: its one retry hit a taken port again). StartCluster tries again
// until clusterRetryFor has passed: here the first two attempts each meet
// a taken port, and the third starts. A failed attempt stops at once, not
// after its other members finish starting and stopping (~10s each before,
// which spent a third of the deadline per loss).
func TestStartClusterRetriesAPortTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	pick, picks := freePort, 0
	var tries []time.Time // when each attempt picked its first port
	freePort = func(t testing.TB) string {
		picks++
		if picks%6 == 1 {
			tries = append(tries, time.Now())
		}
		if picks == 1 || picks == 7 { // the first pick of the first two attempts
			return taken.Addr().String()
		}
		return pick(t)
	}
	defer func() { freePort = pick }()
	c := StartCluster(t)
	if picks < 18 || picks%6 != 0 || len(c.Endpoints) != 3 {
		t.Fatalf("%d ports picked, %d endpoints: the cluster was not tried a third time", picks, len(c.Endpoints))
	}
	for i := range 2 {
		if d := tries[i+1].Sub(tries[i]); d > time.Second {
			t.Errorf("failed attempt %d took %v: it waited on its other members", i+1, d)
		}
	}
}

// Past clusterRetryFor, StartCluster stops and fails the test, naming the
// address: a port that never frees is not waited on forever.
func TestStartClusterGivesUpAtItsDeadline(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	pick, retry := freePort, clusterRetryFor
	freePort = func(t testing.TB) string { return taken.Addr().String() }
	clusterRetryFor = 200 * time.Millisecond
	defer func() { freePort, clusterRetryFor = pick, retry }()
	ft := &fatalT{TB: t}
	func() {
		defer func() { recover() }()
		StartCluster(ft)
	}()
	if !strings.Contains(ft.msg, "address already in use") {
		t.Fatalf("StartCluster did not give up naming the taken port: %q", ft.msg)
	}
}

// fatalT records Fatal's message and stops the call, without failing the
// test that wraps it.
type fatalT struct {
	testing.TB
	msg string
}

func (f *fatalT) Fatal(args ...any) { f.msg = fmt.Sprint(args...); panic(f) }
func (f *fatalT) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	panic(f)
}

// The proxy forwards, a hang stops it answering without closing anything,
// and its cleanup closes every connection through it, so no pipe outlives
// the test that made it (Task 5 review M4).
func TestProxyForwardsHangsAndCloses(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	var c net.Conn
	t.Run("proxy", func(t *testing.T) {
		p := NewProxy(t, echo.Addr().String())
		c, err = net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("forwarded %q: %v", buf, err)
		}
		p.Hang(true)
		if _, err := c.Write([]byte("hung")); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("a hung proxy answered: %v", err)
		}
		c.SetReadDeadline(time.Time{})
		// A drop ends the connection, the chunk held never delivered, and
		// a new connection is forwarded again.
		p.Hang(true)
		if _, err := c.Write([]byte("lost")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		p.Drop()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		// Ended by a FIN or, with "lost" unread at the proxy, a reset.
		if got, err := io.ReadAll(c); len(got) != 0 || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("a dropped connection: %q %v", got, err)
		}
		c.Close()
		if c, err = net.Dial("tcp", p.Addr()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte("pong")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "pong" {
			t.Fatalf("forwarded after a drop %q: %v", buf, err)
		}
		p.Hang(true)
	}) // the subtest's cleanup closes the proxy, still hung
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("the proxy's cleanup left the connection open: %v", err)
	}
	c.Close()
}

// Restore puts a Backup's data back under clients still connected: a key
// written since is gone, and the revision is the backup's again (Ruling
// 18's fleet tests stand on it).
func TestARestoreTakesTheStoreBack(t *testing.T) {
	ctx := context.Background()
	srv := Start(t, Options{})
	cli := srv.Client(t, "root")
	if _, err := cli.Put(ctx, "before", "x"); err != nil {
		t.Fatal(err)
	}
	backup := srv.Backup(t)
	at, err := cli.Get(ctx, "before")
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := cli.Put(ctx, "after", "y"); err != nil {
			t.Fatal(err)
		}
	}
	srv.Restore(t, backup)
	resp, err := cli.Get(ctx, "after")
	if err != nil || len(resp.Kvs) != 0 || resp.Header.Revision != at.Header.Revision {
		t.Fatalf("after a restore: %v at revision %d, the backup's %d: %v", resp.Kvs, resp.Header.Revision,
			at.Header.Revision, err)
	}
}
