package etcdtest

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// A cluster whose first pick of a port is taken before its member binds it
// starts on new ports (pre-flight M29; Task 5 review M3): the first port
// freePort hands out is held by a listener of the test's own.
func TestStartClusterRetriesAPortTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	pick, picks := freePort, 0
	freePort = func(t testing.TB) string {
		picks++
		if picks == 1 {
			return taken.Addr().String()
		}
		return pick(t)
	}
	defer func() { freePort = pick }()
	c := StartCluster(t)
	if picks != 12 || len(c.Endpoints) != 3 {
		t.Fatalf("%d ports picked, %d endpoints: the cluster was not tried again", picks, len(c.Endpoints))
	}
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
	}) // the subtest's cleanup closes the proxy, still hung
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("the proxy's cleanup left the connection open: %v", err)
	}
	c.Close()
}
