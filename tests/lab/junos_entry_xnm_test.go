//go:build lab

package lab

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestL26cEntryXnm measures JUNOScript over the device's xnm-ssh service (TCP
// 3220) under the same three classes as TestL26cEntryNetconf (W, V, C). It is
// its own test, with its own token pool and note, so that nothing about
// xnm-ssh can invalidate the NETCONF cells L26c rests on. It feeds check-config's
// services gate (G2): xnm-ssh may leave set 1.2.0's failing list only when W
// is refused and the control got a result. Any other outcome, including a
// refused `set system services xnm-ssh`, writes no note and leaves it failing.

var xnmProbes = []string{"xnm-ssh", "xnm-ssh: get-software-information"}

const xnmRPCKey = "xnm-ssh: get-software-information"

// junosTryConfigure is junosConfigureAdmin that reports a refused line or a
// failed commit instead of failing the test: the candidate is rolled back
// (`rollback 0`) so the refused line cannot ride into a later commit, and
// port49d is put back on the lab config either way.
func (l *lab) junosTryConfigure(t *testing.T, lines []string) (string, error) {
	t.Helper()
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("could not stop port49d before opening an admin CLI: %v", err)
	}
	restart := func() {
		if l.splitActive {
			return
		}
		base, err := l.configPath()
		if err != nil {
			t.Fatalf("recovering this platform's standing config: %v", err)
		}
		if err := l.startDaemonWith(base, true); err != nil {
			t.Fatalf("restarting port49d after the admin CLI: %v", err)
		}
	}
	c, err := l.junosCLI(breakglassUser, breakglassPassword)
	if err != nil {
		restart()
		t.Fatalf("no admin CLI (port49d was stopped for this, so the device should have taken the "+
			"local password): %v", err)
	}
	out, ferr := junosConfigure(c, lines...)
	if ferr != nil {
		c.sendExpect("rollback 0", junosPer, junosCfgPrompt, junosOpPrompt)
		c.sendExpect("exit", junosPer, junosOpPrompt)
		ferr = fmt.Errorf("applying %v: %v\n%s", lines, ferr, hideKeys(out))
	}
	c.Close()
	restart()
	return out, ferr
}

// poolSecrets are the values no note may hold: every minted token and the
// break-glass password.
func (l *lab) poolSecrets() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	secrets := []string{breakglassPassword}
	for _, s := range l.seeds {
		secrets = append(secrets, s.Login, s.Enable)
	}
	return secrets
}

// entryResult is l.result after a leak check of the claim and the
// observation against the token pool: on a hit the test fails and no note is
// written. The matched value is never printed.
func (l *lab) entryResult(t *testing.T, entry, claim, observation string) {
	t.Helper()
	if err := leakIn(claim+"\n"+observation, l.poolSecrets()); err != nil {
		t.Fatalf("%s: the note is withheld: %v", entry, err)
	}
	l.result(t, entry, claim, observation)
}

// xnmHelloCell reads what the xnm-ssh service sent first: the JUNOScript
// greeting (hello), a refusal, or nothing readable (not observed).
func xnmHelloCell(out string) string {
	greeted := strings.Contains(out, "<junoscript")
	refused := containsAny(strings.ToLower(out), junosL26cRefusal)
	switch {
	case greeted && !refused:
		return "hello"
	case refused && !greeted:
		return "refused"
	}
	return "not observed"
}

// xnmFirstCell is the greeting cell: silence on a channel still open is not
// observed, never a refusal; a channel the device closed after port49d
// permitted the session is refused.
func xnmFirstCell(greeting string, closed, permitted bool) string {
	cell := xnmHelloCell(greeting)
	if cell == "not observed" && closed && permitted {
		return "refused"
	}
	return cell
}

// xnmRPCCell reads the reply to get-software-information: result (the host
// name), refused (a JUNOScript <xnm:error>, a NETCONF-style <rpc-error>, or the
// session closed with no reply), or not observed (a hang, or nothing readable).
func xnmRPCCell(reply string, closed bool) string {
	switch {
	case strings.Contains(reply, "<host-name>"):
		return "result"
	case strings.Contains(reply, "<xnm:error"):
		return "refused"
	case strings.Contains(reply, "<rpc-error>") && netconfSeverityError.MatchString(reply):
		return "refused"
	case closed && !strings.Contains(reply, "</rpc-reply>"):
		return "refused"
	}
	return "not observed"
}

// xnmGate is what W's xnm-ssh cells mean for set 1.2.0's services list (G2).
// "closed" only where W was refused at the greeting or at the RPC and the
// control got a result; "reached" where W got a result, or a greeting with no
// refusal after it; "" otherwise. Both "reached" and "" leave xnm-ssh failing.
func xnmGate(readings map[string]string, controlRPC string) string {
	hello, rpc := readings["W xnm-ssh"], readings["W "+xnmRPCKey]
	switch {
	case rpc == "reached":
		return "reached"
	case controlRPC != "result":
		return ""
	case rpc == "deny" || hello == "deny":
		return "closed"
	case hello == "reached":
		return "reached"
	}
	return ""
}

// xnmGateWord is what xnmGate's verdict means for set 1.2.0's services list.
func xnmGateWord(gate string) string {
	switch gate {
	case "closed":
		return "closed by the junoscript deny; `xnm-ssh` may leave set 1.2.0's failing list"
	case "reached":
		return "reached past the junoscript deny; `xnm-ssh` stays on set 1.2.0's failing list"
	}
	return "not measured; `xnm-ssh` stays on set 1.2.0's failing list (fails closed)"
}

// xnmOut collects a JUNOScript session's output as it arrives, so a reader
// can wait for a marker with a deadline (ssh.Session has no read deadline).
type xnmOut struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (o *xnmOut) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *xnmOut) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func (o *xnmOut) isClosed() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed
}

func (o *xnmOut) markClosed() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
}

// wait returns the output once it holds one of want (compared in lower case),
// the channel has closed, or d has passed.
func (o *xnmOut) wait(d time.Duration, want ...string) string {
	deadline := time.Now().Add(d)
	for {
		got := o.String()
		if containsAny(strings.ToLower(got), want) || o.isClosed() || time.Now().After(deadline) {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// xnmClientHello opens a JUNOScript session: the XML declaration and the
// <junoscript> element the client answers the device's greeting with.
const xnmClientHello = `<?xml version="1.0" encoding="us-ascii"?>` + "\n" +
	`<junoscript version="1.0" hostname="p49-lab" release="1.0">` + "\n"

// entryXnm opens a JUNOScript session over the device's xnm-ssh service
// (TCP 3220) with the next token: the SSH connection rides break-glass's
// direct-tcpip channel to 127.0.0.1:3220 inside the VM, as REST's does, so
// no port needs forwarding through vrnetlab. It reads the device's greeting,
// sends the client's and `get-software-information`, and records hello,
// refused or the result. The tunnel is break-glass's; the session is the
// class's token.
func (l *lab) entryXnm(t *testing.T, r l26cRun) {
	t.Helper()
	const key = "xnm-ssh"
	tunnel, err := l.dialHostPort(breakglassUser, breakglassPassword, l.p.addr+":22", 60*time.Second)
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", "the tunnel's login: "+oneLine(err.Error())
		return
	}
	defer tunnel.Close()
	off := l.mark()
	user, secret := l.nextLogin(t)
	nc, err := tunnel.Dial("tcp", "127.0.0.1:3220")
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", "the tunnel to 3220: "+oneLine(err.Error())
		return
	}
	cfg := labSSHConfig(user, secret)
	cfg.Timeout = 60 * time.Second
	sc, chans, reqs, err := ssh.NewClientConn(nc, "127.0.0.1:3220", cfg)
	if err != nil {
		nc.Close()
		cell := "not observed"
		switch {
		case isAuthRejection(err):
			cell = "login refused"
		case sessionPermitted(l.drainRecords(off, 10*time.Second)):
			cell = "refused"
		}
		r.cells[key], r.outs[key] = cell, oneLine(err.Error())
		return
	}
	c := ssh.NewClient(sc, chans, reqs)
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", oneLine(err.Error())
		return
	}
	defer s.Close()
	stdin, err := s.StdinPipe()
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", oneLine(err.Error())
		return
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", oneLine(err.Error())
		return
	}
	var out xnmOut
	go func() {
		io.Copy(&out, stdout)
		out.markClosed()
	}()
	if err := s.Shell(); err != nil {
		r.cells[key], r.outs[key] = "not observed", oneLine(err.Error())
		return
	}
	greeting := out.wait(45*time.Second, append([]string{"<junoscript"}, junosL26cRefusal...)...)
	r.outs[key] = firstLines(greeting, 8)
	closed := out.isClosed()
	r.cells[key] = xnmFirstCell(greeting, closed, closed && sessionPermitted(l.drainRecords(off, 10*time.Second)))
	if r.cells[key] != "hello" {
		return
	}
	fmt.Fprint(stdin, xnmClientHello+"<rpc><get-software-information/></rpc>\n")
	reply := strings.TrimPrefix(out.wait(60*time.Second, "</rpc-reply>", "<xnm:error"), greeting)
	r.outs[xnmRPCKey], r.cells[xnmRPCKey] = firstLines(reply, 12), xnmRPCCell(reply, out.isClosed())
	fmt.Fprint(stdin, "</junoscript>\n")
}

func TestL26cEntryXnm(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26c-xnm")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosEntryClass)
		defer l.junosConfigureAdmin(t, junosEntryDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		// xnm-ssh may be refused by the image: that is "not measured", not a
		// failure, and the service stays on the failing list.
		xnmCommit, err := l.junosTryConfigure(t, []string{"set system services xnm-ssh"})
		if err != nil {
			t.Skipf("xnm-ssh not measured (the image refused `set system services xnm-ssh`; no note is "+
				"written and the service stays on the failing list): %v", err)
		}
		defer l.junosConfigureAdmin(t, []string{"delete system services xnm-ssh"})

		runs := map[string]l26cRun{}
		for _, v := range junosEntryVariants {
			r := newL26cRun()
			runs[v.name] = r
			// The reply for the token's session: port49d restarted with it, no
			// CLI login spent (the session below is the only one).
			cfg, err := l.derivedConfigCmd("junos-"+l16Slug("xnm "+v.name), v.attrs, "", "")
			if err == nil {
				err = l.restart(cfg)
			}
			if err != nil {
				t.Fatalf("%s: port49d with %s: %v", v.name, v.attrs, err)
			}
			l.entryXnm(t, r)
		}
		readings, unisolated := entryVerdict(runs, []string{"W", "V"}, "C", []string{xnmRPCKey}, xnmProbes)
		if len(unisolated) > 0 {
			t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
		}
		var b strings.Builder
		fmt.Fprintf(&b, "The classes were committed: %s. `xnm-ssh`: %s.\n\n```\n%s\n```\n\n", commitWord(commit),
			commitWord(xnmCommit), strings.Join(junosEntryClass, "\n"))
		entryTables(&b, runs, readings, junosEntryVariants, xnmProbes)
		fmt.Fprintf(&b, "\n### Gates (plan 9b1)\n\n- G2, `xnm-ssh`: under W the greeting reads %s and the RPC %s: %s.\n",
			cellOr(runs["W"], "xnm-ssh"), cellOr(runs["W"], xnmRPCKey),
			xnmGateWord(xnmGate(readings, runs["C"].cells[xnmRPCKey])))
		l.entryResult(t, "L26c-xnm", "Whether `deny-commands \"junoscript\"` beside a deny of `show configuration` "+
			"refuses JUNOScript over the `xnm-ssh` service (TCP 3220, reached through a break-glass tunnel), at the "+
			"greeting or at the RPC; against the same reply less the junoscript deny and a control with the same "+
			"bits and no deny (spec §15 L26c; plan 9b1 Task 3; G2).", b.String())
	})
}
