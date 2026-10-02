package etcdtest

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

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
