//go:build lab

package lab

import (
	"testing"
	"time"
)

// A stale prompt redraw read as a probe's answer is an empty reply. The
// carve-out and the deny closers count a cell only on a refusal the device
// said, so an empty read fails, never passes (task-3 review I1).
func TestJunosCarveRefused(t *testing.T) {
	p := junosHostProbe
	for _, c := range []struct {
		name string
		run  junosRun
		want bool
	}{
		{"a syntax error", junosRun{outs: map[string]string{p.cmd: "                   ^\r\nsyntax error.\r\n"}}, true},
		{"an unknown command", junosRun{outs: map[string]string{p.cmd: "  ^\r\nunknown command.\r\n"}}, true},
		{"an empty read", junosRun{outs: map[string]string{p.cmd: ""}}, false},
		{"a bare prompt", junosRun{outs: map[string]string{p.cmd: "\r\nalice06@srx1> "}}, false},
		{"not typed", junosRun{outs: map[string]string{}}, false},
		{"not observed", junosRun{outs: map[string]string{p.cmd: "syntax error."}, unobserved: []string{p.cmd}}, false},
	} {
		if got := junosCarveRefused(c.run, p); got != c.want {
			t.Errorf("%s: junosCarveRefused = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestJunosCloserRefused(t *testing.T) {
	for _, c := range []struct {
		said string
		want bool
	}{
		{"prompt back: ^ unknown command. alice10@srx1>", true},
		{"prompt back: ", false},
		{"prompt back: (the device returned no output at all: zero bytes on the channel)", false},
		{"closed the session", false},
		{"", false},
	} {
		if got := junosCloserRefused(c.said); got != c.want {
			t.Errorf("junosCloserRefused(%q) = %v, want %v", c.said, got, c.want)
		}
	}
}

func TestJunosIdleVerdict(t *testing.T) {
	const timer = "alice11@srx1> Warning: session will be closed in 10 seconds if there is no activity / " +
		"Idle timeout exceeded: closing session"
	for _, c := range []struct {
		name    string
		elapsed time.Duration
		said    string
		ok      bool
	}{
		{"the timer at 60 s", 60 * time.Second, timer, true},
		{"too soon", 10 * time.Second, timer, false},
		{"too late", 3 * time.Minute, timer, false},
		{"no message", 60 * time.Second, "alice11@srx1> ", false},
		{"an empty tail", 60 * time.Second, "", false},
	} {
		if err := junosIdleVerdict(c.elapsed, c.said); (err == nil) != c.ok {
			t.Errorf("%s: junosIdleVerdict = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// junosSettle returns once the device has been quiet for a second.
func TestJunosSettleQuiet(t *testing.T) {
	c := &cliConn{out: &syncBuf{}}
	c.out.Write([]byte("alice01@srx1> "))
	start := time.Now()
	if err := junosSettle(c); err != nil {
		t.Fatalf("junosSettle on a quiet channel: %v", err)
	}
	if d := time.Since(start); d < time.Second || d > 5*time.Second {
		t.Errorf("junosSettle took %s, want about a second of quiet", d)
	}
}
