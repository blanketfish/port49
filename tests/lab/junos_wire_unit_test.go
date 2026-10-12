//go:build lab

package lab

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeCLI is a Junos CLI that answers each line written to it from script:
// the first string at once, the second after 400 ms (inside junosSettle's
// quiet-second window), as a page that arrives after an early prompt match.
func fakeCLI(script func(line string) (now, later string)) *cliConn {
	out := &syncBuf{}
	return &cliConn{name: "fake CLI", out: out, in: writerFunc(func(p []byte) {
		now, later := script(strings.TrimSpace(string(p)))
		out.Write([]byte(now))
		if later != "" {
			time.AfterFunc(400*time.Millisecond, func() { out.Write([]byte(later)) })
		}
	})}
}

type writerFunc func(p []byte)

func (f writerFunc) Write(p []byte) (int, error) { f(p); return len(p), nil }

// TestJunosProbeRefusesALatePage: a page that arrives after the prompt matched,
// whether during the settle or after the (yes) answer, is INVALID, as one in
// the first window is; a clean output is returned whole (review I4).
func TestJunosProbeRefusesALatePage(t *testing.T) {
	const prompt = "\r\nalice@srx1> "
	for _, c := range []struct {
		name    string
		script  func(line string) (string, string)
		invalid bool
	}{
		{"clean", func(line string) (string, string) { return line + "\r\nHostname: srx1" + prompt, "" }, false},
		{"page in the first window", func(line string) (string, string) {
			return line + "\r\nlog line\r\n---(more 18%)---" + prompt, ""
		}, true},
		{"page after the prompt matched, during the settle", func(line string) (string, string) {
			return line + "\r\nlog line" + prompt, "\r\n---(more 18%)---"
		}, true},
		{"page after the (yes) answer", func(line string) (string, string) {
			if line == "yes" {
				return "yes\r\ndone" + prompt, "\r\n---(more)---"
			}
			return line + "\r\nProceed? (yes) ", ""
		}, true},
	} {
		out, err := (&lab{}).junosProbe(fakeCLI(c.script), junosProbe{cmd: "show x"})
		if got := err != nil && strings.HasPrefix(err.Error(), "INVALID: show x paged"); got != c.invalid {
			t.Errorf("%s: INVALID %v (err %v), want %v", c.name, got, err, c.invalid)
		}
		if !c.invalid && (err != nil || !strings.Contains(out, "Hostname: srx1")) {
			t.Errorf("%s: %q, %v", c.name, out, err)
		}
	}
}

func TestJunosPagedErr(t *testing.T) {
	if err := junosPagedErr("show log", "a\n---(more)---"); err == nil || !strings.HasPrefix(err.Error(), "INVALID: show log paged") {
		t.Errorf("a paged window: %v", err)
	}
	if err := junosPagedErr("show log", "a\nalice@srx1> "); err != nil {
		t.Errorf("a clean window: %v", err)
	}
}

// TestLoginMeasured runs without a device: only an opened session, or the
// malformed deny's login refused by the device, is a measurement.
func TestLoginMeasured(t *testing.T) {
	rejected := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain")
	timeout := errors.New(`none of ["> "] appeared on the SSH CLI as alice11 within 1m30s; what it said was:`)
	run := func(err error) junosRun {
		if err == nil {
			return junosRun{}
		}
		return junosRun{loginErr: oneLine(err.Error()), loginRefused: isAuthRejection(err)}
	}
	for _, c := range []struct {
		variant string
		err     error
		want    bool
	}{
		{"deny malformed", nil, true},
		{"deny malformed", rejected, true},
		{"deny malformed", timeout, false},
		{"narrow", nil, true},
		{"narrow", rejected, false},
		{"narrow", timeout, false},
	} {
		if got := loginMeasured(c.variant, run(c.err)); got != c.want {
			t.Errorf("loginMeasured(%q, %v) = %v, want %v", c.variant, c.err, got, c.want)
		}
	}
}

// TestJunosCfgVerdict: the deny reaches configuration mode only where the
// same class without it ran the statement and, under it, ran the sibling.
func TestJunosCfgVerdict(t *testing.T) {
	ran := "\n[edit]\nalice@srx1# "
	refused := "set system\n                  ^\nsyntax error.\n\n[edit]\nalice@srx1# "
	session := func(host, sibling string, auth string) junosRun {
		return junosRun{auth: auth, outs: map[string]string{
			"configure":                         "Entering configuration mode\n\n[edit]\nalice@srx1# ",
			"set system host-name " + junosHost: host,
			"set system services netconf ssh":   sibling,
		}}
	}
	listed := "Deny regular expression: (^set system host-name( .*)?$)"
	for _, c := range []struct {
		name          string
		control, deny junosRun
		want          string
	}{
		{"reached", session(ran, ran, ""), session(refused, ran, listed), "reached"},
		{"not reached", session(ran, ran, ""), session(ran, ran, listed), "not reached"},
		{"class cannot modify [system]", session(refused, refused, ""), session(refused, refused, listed), "not isolated"},
		{"deny refuses the sibling too", session(ran, ran, ""), session(refused, refused, listed), "not isolated"},
		{"deny not listed", session(ran, ran, ""), session(refused, ran, "Deny regular expression: none"), "not isolated"},
		{"no session", session(ran, ran, ""), junosRun{loginErr: "x"}, "not isolated"},
	} {
		if got := junosCfgVerdict(c.control, c.deny); !strings.HasPrefix(got, c.want+":") {
			t.Errorf("%s: junosCfgVerdict = %q, want %q", c.name, got, c.want)
		}
	}
}
