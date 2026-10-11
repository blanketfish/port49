//go:build lab

package lab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
	"golang.org/x/crypto/ssh"
)

// TestL26cEntryNetconf and TestL26cEntryScripts measure the ways into an RPC
// that `deny-commands "junoscript"` was not yet measured against (spec §15
// L26c; plan 9b1 Task 3), each against a control with the same bits:
//   - W: view and view-configuration, and the rendered deny of `show
//     configuration` and `junoscript`, the reply set 1.2.0 sends;
//   - V: the same with no junoscript deny, set 1.1.0's capability shape: the
//     hole the operator saw on SRX hardware, reproduced (L26c-operator);
//   - C: the same bits and no deny, the positive control.
// Vw, view alone and no deny, reads `scp` only.

var junosEntryClass = []string{
	"set system login class p49-ent-vc permissions view",
	"set system login class p49-ent-vc permissions view-configuration",
	"set system login user p49-ent-vc class p49-ent-vc",
	"set system login class p49-ent-v permissions view",
	"set system login user p49-ent-v class p49-ent-v",
}

var junosEntryDelete = []string{
	"delete system login user p49-ent-vc", "delete system login class p49-ent-vc",
	"delete system login user p49-ent-v", "delete system login class p49-ent-v",
}

// entryDenyBoth is port49's rendering of deny `show configuration **` and deny
// `junoscript **` as one alternation (internal/projection ruleERE, denyLead and
// pipeTail).
const entryDenyBoth = `deny-commands=^( *show +configuration( .*)? *(\|.*)?| *junoscript( .*)? *(\|.*)?)$`

var junosEntryVariants = []junosVariant{
	{"W", `["local-user-name=p49-ent-vc", "` + jsonEscape(entryDenyBoth) + `"]`,
		"view view-configuration; deny show configuration and junoscript (set 1.2.0's reply)"},
	{"V", `["local-user-name=p49-ent-vc", "deny-commands=^ *show +configuration( .*)? *(\\|.*)?$"]`,
		"view view-configuration; deny show configuration only (the hole)"},
	{"C", `["local-user-name=p49-ent-vc"]`, "view view-configuration; no deny (the control)"},
}

// jsonEscape is s as a JSON string's body: the reply is a JSON list.
func jsonEscape(s string) string { return strings.ReplaceAll(s, `\`, `\\`) }

// entryVerdict reads each deny class's cell against the control: "deny"
// where the class was refused and the control reached the probe; "runs
// nowhere" where the control was refused too; "reached" where the class
// reached it; "not observed" where the class's token was refused or its cell
// was not observed, which says nothing about the deny. unisolated lists each
// canonical probe the control did not reach: the run cannot say the deny
// closed it, and the run fails.
func entryVerdict(runs map[string]l26cRun, deny []string, control string, canonical, probes []string) (
	map[string]string, []string) {
	readings := map[string]string{}
	var unisolated []string
	reached := func(c string) bool {
		return l26cReached(c) || c == "ran" || c == "file read" || strings.HasPrefix(c, "version")
	}
	for _, p := range probes {
		cc := runs[control].cells[p]
		if slices.Contains(canonical, p) && !reached(cc) {
			unisolated = append(unisolated, fmt.Sprintf("%s: the control %s", p, cellOr(runs[control], p)))
		}
		for _, cls := range deny {
			cell, ok := runs[cls].cells[p]
			if !ok {
				continue
			}
			switch {
			case reached(cell):
				readings[cls+" "+p] = "reached"
			case cell == "login refused" || cell == "not observed":
				readings[cls+" "+p] = "not observed"
			case reached(cc):
				readings[cls+" "+p] = "deny"
			default:
				readings[cls+" "+p] = "runs nowhere"
			}
		}
	}
	return readings, unisolated
}

// entryProbes are TestL26cEntryNetconf's cells, in table order.
var entryProbes = []string{"show configuration system host-name", "entry: xml-mode netconf need-trailer",
	"xml-mode netconf need-trailer: get-configuration", "port 830", "port 830: get-configuration",
	"port 22 subsystem", "port 22 subsystem: get-configuration", "exec channel", "exec channel: get-configuration"}

// entryCanonical are the probes the control must reach, or the run is INVALID:
// every way in the L26c claim names, so none closes the row unmeasured. If the
// exec channel cannot be made to reach under C after a harness fix, STOP and
// report: the claim is then narrowed, never closed past it.
var entryCanonical = []string{"show configuration system host-name", "entry: xml-mode netconf need-trailer",
	"port 830", "port 22 subsystem", "exec channel"}

const getConfigHost = "<get-configuration><configuration><system><host-name/></system></configuration></get-configuration>"

// entryNetconf dials NETCONF on port with the next token and asks for the
// host name from the configuration. A channel the device closes after
// port49d permitted the session is "refused".
func (l *lab) entryNetconf(t *testing.T, r l26cRun, key, port string) {
	t.Helper()
	off := l.mark()
	user, secret := l.nextLogin(t)
	n, hello, err := l.netconfDialPort(user, secret, port)
	if err != nil {
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
	defer n.Close()
	r.cells[key], r.outs[key] = "hello", firstLines(hello, 5)
	reply, err := n.rpc(1, getConfigHost)
	r.outs[key+": get-configuration"] = firstLines(reply, 10)
	r.cells[key+": get-configuration"] = l26cRPCCell(reply, "<host-name>")
	if err != nil {
		r.cells[key+": get-configuration"] = "not observed"
	}
}

// entryExec runs `xml-mode netconf need-trailer` as an SSH exec command with
// the next token. Stdin stays open: the client hello goes in once the device
// has greeted, the get-configuration RPC once the hello is read, and the close
// last (execDrive). A stdin at EOF can end the command before it greets, which
// reads as a refusal that never happened.
func (l *lab) entryExec(t *testing.T, r l26cRun) {
	t.Helper()
	user, secret := l.nextLogin(t)
	const key = "exec channel"
	c, err := l.dialHostPort(user, secret, l.p.addr+":22", 60*time.Second)
	if err != nil {
		r.cells[key], r.outs[key] = "login refused", oneLine(err.Error())
		return
	}
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
	var out xnmOut
	s.Stdout, s.Stderr = &out, &out
	done := make(chan error, 1)
	go func() {
		err := s.Run("xml-mode netconf need-trailer")
		out.markClosed()
		done <- err
	}()
	go execDrive(stdin, &out, 60*time.Second)
	exited := true
	select {
	case err = <-done:
	case <-time.After(150 * time.Second):
		exited = false
		err = fmt.Errorf("no exit within 150s")
	}
	got := out.String()
	r.outs[key] = firstLines(got, 12)
	r.cells[key] = execCell(got, exited)
	if r.cells[key] == "hello" {
		r.cells[key+": get-configuration"] = l26cRPCCell(got, "<host-name>")
	}
	if err != nil && r.cells[key] == "not observed" {
		r.outs[key] += "\n" + oneLine(err.Error())
	}
}

// execDrive speaks the client side of the exec channel in turn: it waits up to
// d for the device's </hello> (or the command's exit), sends the client hello
// and the RPC, waits up to d for </rpc-reply> (or the exit), then sends
// close-session and closes stdin. Writes after an exit fail and are ignored.
func execDrive(stdin io.WriteCloser, out *xnmOut, d time.Duration) {
	defer stdin.Close()
	out.wait(d, "</hello>")
	io.WriteString(stdin, junosL26cClientHello+"\n")
	io.WriteString(stdin, "<rpc>"+getConfigHost+"</rpc>]]>]]>\n")
	out.wait(d, "</rpc-reply>")
	io.WriteString(stdin, "<rpc><close-session/></rpc>]]>]]>\n")
}

// execCell reads the exec channel: hello where the device greeted; refused
// only where the command exited and printed a refusal; otherwise not
// observed. A silent exit is not a refusal (a permitted session whose command
// ended early looks the same), and a hang has not shown the deny either.
func execCell(got string, exited bool) string {
	switch {
	case strings.Contains(got, "</hello>"):
		return "hello"
	case exited && containsAny(strings.ToLower(got), junosL26cRefusal):
		return "refused"
	}
	return "not observed"
}

func TestL26cEntryNetconf(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26c-entries")
		defer stop()
		commit := l.junosConfigureAdmin(t, append(slices.Clone(junosEntryClass), "set system services netconf ssh"))
		defer l.junosConfigureAdmin(t, junosEntryDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		runs := map[string]l26cRun{}
		for _, v := range junosEntryVariants {
			r := newL26cRun()
			runs[v.name] = r
			// One CLI session: the deny on the CLI, then xml-mode, which ends it.
			c, run, _ := l.junosLogin(t, "entry "+v.name, v.attrs)
			if c == nil {
				t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
			}
			r.outs["show cli authorization"] = run.auth
			o, err := l26cSend(c, "show configuration system host-name")
			r.outs["show configuration system host-name"] = firstLines(o, 6)
			r.cells["show configuration system host-name"] = l26cCLICell(o, junosHostProbe.evidence)
			if err != nil {
				r.cells["show configuration system host-name"] = "not observed"
			}
			entryXMLMode(c, r)
			c.Close()
			l.entryNetconf(t, r, "port 830", "830")
			l.entryNetconf(t, r, "port 22 subsystem", "22")
			l.entryExec(t, r)
		}
		for _, p := range entryProbes {
			for _, name := range []string{"W", "V", "C"} {
				if runs[name].cells[p] == "not observed" {
					t.Errorf("not observed: %s in %s", p, name)
				}
			}
		}
		readings, unisolated := entryVerdict(runs, []string{"W", "V"}, "C", entryCanonical, entryProbes)
		if len(unisolated) > 0 {
			entryLogControl(t, runs["C"], unisolated)
			t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
		}
		for _, p := range []string{"port 22 subsystem", "exec channel"} {
			if readings["W "+p] == "reached" {
				t.Errorf("STOP: under the junoscript deny W reached %s, which the deny does not close: report to "+
					"the controller before Task 4 (decision 44 ruling 1 rests on it)", p)
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "The classes were committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit),
			strings.Join(junosEntryClass, "\n"))
		entryTables(&b, runs, readings, junosEntryVariants, entryProbes)
		l.entryResult(t, "L26c-entries", "Whether `deny-commands \"junoscript\"`, sent by TACACS+ beside a deny of `show "+
			"configuration` under `view view-configuration`, refuses NETCONF as an SSH subsystem on port 22 and "+
			"over the SSH exec channel (`xml-mode netconf need-trailer`), as it refuses `xml-mode` from the CLI and "+
			"port 830; with the same reply less the junoscript deny (the hole) and a control with the same bits and "+
			"no deny (spec §15 L26c; plan 9b1 Task 3, cell a).", b.String())
	})
}

// entryXMLMode types the CLI entry, and where a hello comes back sends the
// client hello and the get-configuration RPC.
func entryXMLMode(c *cliConn, r l26cRun) {
	const key = "entry: xml-mode netconf need-trailer"
	from := len(c.out.String())
	if err := c.send("xml-mode netconf need-trailer"); err != nil {
		r.cells[key] = "not observed"
		return
	}
	out, err := c.expectFrom(from, junosPer, "</hello>", junosOpPrompt)
	r.outs[key], r.cells[key] = out, l26cEntryCell(out)
	if err != nil {
		r.cells[key] = "not observed"
	}
	if r.cells[key] != "hello" {
		return
	}
	const k = "xml-mode netconf need-trailer: get-configuration"
	fmt.Fprint(c.in, junosL26cClientHello+"\n")
	from = len(c.out.String())
	fmt.Fprint(c.in, "<rpc>"+getConfigHost+"</rpc>]]>]]>\n")
	reply, err := c.expectFrom(from, 60*time.Second, "</rpc-reply>")
	r.outs[k], r.cells[k] = firstLines(reply, 12), l26cRPCCell(reply, "<host-name>")
	if err != nil {
		r.cells[k] = "not observed"
	}
}

// entryTables writes the cells, the verdicts, and each class's raw outputs.
func entryTables(b *strings.Builder, runs map[string]l26cRun, readings map[string]string, vs []junosVariant,
	probes []string) {
	b.WriteString("| class | reply | why |\n|---|---|---|\n")
	for _, v := range vs {
		fmt.Fprintf(b, "| %s | `%s` | %s |\n", v.name, tableCell(v.attrs), v.why)
	}
	names := make([]string, 0, len(vs))
	for _, v := range vs {
		names = append(names, v.name)
	}
	fmt.Fprintf(b, "\n| probe | %s |\n|---|%s\n", strings.Join(names, " | "), strings.Repeat("---|", len(names)))
	for _, p := range probes {
		cells := make([]string, len(names))
		for i, n := range names {
			cells[i] = cellOr(runs[n], p)
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(p), strings.Join(cells, " | "))
	}
	b.WriteString("\n### Verdict against the control\n\n| probe | W | V |\n|---|---|---|\n")
	for _, p := range probes {
		fmt.Fprintf(b, "| %s | %s | %s |\n", tableCell(p), jsdOrDash(readings["W "+p]), jsdOrDash(readings["V "+p]))
	}
	for _, n := range names {
		fmt.Fprintf(b, "\n### %s\n", n)
		keys := make([]string, 0, len(runs[n].outs))
		for k := range runs[n].outs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			fmt.Fprintf(b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(runs[n].outs[k], 20))
		}
	}
}

// junosEntryOpScript asks for the software information and the configuration's
// host name through jcs:invoke, and prints a marker for each that came back.
var junosEntryOpScript = []string{
	`version 1.0;`,
	`ns junos = "http://xml.juniper.net/junos/*/junos";`,
	`ns xnm = "http://xml.juniper.net/xnm/1.1/xnm";`,
	`ns jcs = "http://xml.juniper.net/junos/commit-scripts/1.0";`,
	`match / {`,
	`    <op-script-results> {`,
	`        var $v = jcs:invoke("get-software-information");`,
	`        <output> "P49OP-VERSION " _ $v//host-name;`,
	`        var $rpc = <get-configuration> { <configuration> { <system>; } }`,
	`        var $g = jcs:invoke($rpc);`,
	`        <output> "P49OP-CONFIG " _ count($g//host-name);`,
	`    }`,
	`}`,
}

const junosEntryOpPath = "/var/tmp/p49-entry-op.slax"

// opScriptCell reads what `op url` printed.
func opScriptCell(out string) string {
	switch {
	case strings.Contains(out, "P49OP-VERSION") && strings.Contains(out, "P49OP-CONFIG 1"):
		return "version and configuration"
	case strings.Contains(out, "P49OP-VERSION"):
		return "version only"
	case strings.TrimSpace(out) == "":
		return "not observed"
	}
	return "refused"
}

// scpCell is what an scp read of a file came to: bytes received, or why not.
func scpCell(n int64, err error) string {
	if err == nil && n > 0 {
		return "file read"
	}
	return "refused"
}

// entryScp reads path over the scp protocol (`scp -f`) with the next token.
func (l *lab) entryScp(t *testing.T, r l26cRun, path string) {
	t.Helper()
	const key = "scp /config/juniper.conf.gz"
	user, secret := l.nextLogin(t)
	c, err := l.dialHostPort(user, secret, l.p.addr+":22", 60*time.Second)
	if err != nil {
		r.cells[key], r.outs[key] = scpCell(0, err), oneLine(err.Error())
		return
	}
	defer c.Close()
	n, err := scpRead(c, path)
	r.cells[key] = scpCell(n, err)
	r.outs[key] = fmt.Sprintf("%d bytes; err %v", n, err)
}

// scpRead is the sink side of scp's protocol: ack, read the C line, ack, read
// the file, ack.
func scpRead(c *ssh.Client, path string) (int64, error) {
	s, err := c.NewSession()
	if err != nil {
		return 0, err
	}
	defer s.Close()
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	var stderr bytes.Buffer
	s.Stderr = &stderr
	if err := s.Start("scp -f " + path); err != nil {
		return 0, err
	}
	in.Write([]byte{0})
	var line []byte
	buf := make([]byte, 1)
	for {
		if _, err := out.Read(buf); err != nil {
			return 0, fmt.Errorf("scp: %v %s", err, oneLine(stderr.String()))
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	var mode string
	var size int64
	var name string
	if _, err := fmt.Sscanf(string(line), "C%s %d %s", &mode, &size, &name); err != nil {
		return 0, fmt.Errorf("scp: %q %s", line, oneLine(stderr.String()))
	}
	in.Write([]byte{0})
	n, err := io.CopyN(io.Discard, out, size)
	in.Write([]byte{0})
	return n, err
}

// entryREST asks the REST API for the configuration's host name, through an
// SSH connection's direct-tcpip channel to 127.0.0.1:3000 inside the VM (so no
// port needs forwarding through vrnetlab), with a token as basic auth. The
// tunnel is break-glass's: who carries the TCP stream says nothing about the
// request, and a token spent on it is one fewer for the cells. The request is
// the class's token, since REST authenticates each request (L15).
func (l *lab) entryREST(t *testing.T, r l26cRun) {
	t.Helper()
	const key = "rest: get-configuration"
	tunnel, err := l.dialHostPort(breakglassUser, breakglassPassword, l.p.addr+":22", 60*time.Second)
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", "the tunnel's login: "+oneLine(err.Error())
		return
	}
	defer tunnel.Close()
	user, secret := l.nextLogin(t)
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return tunnel.Dial("tcp", "127.0.0.1:3000")
		}}}
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:3000/rpc", strings.NewReader(getConfigHost))
	req.Header.Set("Content-Type", "application/xml")
	req.SetBasicAuth(user, secret)
	resp, err := hc.Do(req)
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", oneLine(err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	r.outs[key] = fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, firstLines(string(body), 10))
	switch {
	case resp.StatusCode == http.StatusOK && strings.Contains(string(body), "<host-name>"):
		r.cells[key] = "result"
	case resp.StatusCode == http.StatusUnauthorized && isTokenRejected(string(body)):
		r.cells[key] = "login refused"
	default:
		r.cells[key] = "refused"
	}
}

// isTokenRejected reports a 401 whose body says the credential was refused,
// which says nothing about the deny.
func isTokenRejected(body string) bool {
	return strings.Contains(strings.ToLower(body), "authentication")
}

var scriptProbes = []string{"op url: script", "rest: get-configuration", "scp /config/juniper.conf.gz"}

func TestL26cEntryScripts(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26c-scripts")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosEntryClass)
		defer l.junosConfigureAdmin(t, junosEntryDelete)
		// REST is its own commit. The plan requires it (REST was taken on both
		// images, 2026-09-30), so a refusal stops the run; the candidate is
		// rolled back first, or the cleanup commits would carry the bad line.
		restCommit, err := l.junosTryConfigure(t, []string{"set system services rest http port 3000"})
		if err != nil {
			t.Fatalf("INVALID: REST could not be enabled, so nothing below it was measured: %v", err)
		}
		defer l.junosConfigureAdmin(t, []string{"delete system services rest"})
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		// The op script, over break-glass.
		bg, err := l.junosCLI(breakglassUser, breakglassPassword)
		if err != nil {
			t.Fatalf("INVALID: no break-glass CLI: %v", err)
		}
		if _, err := bg.sendExpect("start shell sh", junosPer, "$ ", "% "); err != nil {
			t.Fatalf("INVALID: start shell: %v", err)
		}
		quoted := make([]string, len(junosEntryOpScript))
		for i, ln := range junosEntryOpScript {
			quoted[i] = "'" + ln + "'"
		}
		bg.sendExpect("printf '%s\\n' "+strings.Join(quoted, " ")+" > "+junosEntryOpPath, junosPer, "$ ", "% ")
		bg.sendExpect("exit", junosPer, junosOpPrompt)
		bg.Close()
		// scp's harness control: break-glass reads the file, or a "refused"
		// in every class could be scpRead's own fault.
		if bgc, err := l.dialHostPort(breakglassUser, breakglassPassword, l.p.addr+":22", 60*time.Second); err != nil {
			t.Fatalf("INVALID: no break-glass SSH for scp's control: %v", err)
		} else {
			n, err := scpRead(bgc, "/config/juniper.conf.gz")
			bgc.Close()
			if scpCell(n, err) != "file read" {
				t.Fatalf("INVALID: break-glass could not scp /config/juniper.conf.gz (%d bytes, %v): the harness "+
					"cannot read a file, so no class's refusal says anything", n, err)
			}
		}

		runs := map[string]l26cRun{}
		classes := append(slices.Clone(junosEntryVariants),
			junosVariant{"Vw", `["local-user-name=p49-ent-v"]`, "view alone; no deny (scp only)"})
		for _, v := range classes {
			r := newL26cRun()
			runs[v.name] = r
			if v.name != "Vw" {
				c, run, _ := l.junosLogin(t, "scripts "+v.name, v.attrs)
				if c == nil {
					t.Fatalf("INVALID: %s: the session did not open: %s", v.name, run.loginErr)
				}
				o, err := l26cSend(c, "op url "+junosEntryOpPath)
				r.outs["op url: script"], r.cells["op url: script"] = firstLines(o, 12), opScriptCell(o)
				if err != nil {
					r.cells["op url: script"] = "not observed"
				}
				c.Close()
				l.entryREST(t, r)
			} else {
				// The login sets port49d's reply for the scp token after it.
				c, run, _ := l.junosLogin(t, "scripts Vw", v.attrs)
				if c == nil {
					t.Fatalf("INVALID: Vw: the session did not open: %s", run.loginErr)
				}
				c.Close()
			}
			l.entryScp(t, r, "/config/juniper.conf.gz")
		}
		canonical := []string{"op url: script", "rest: get-configuration"}
		readings, unisolated := entryVerdict(runs, []string{"W", "V", "Vw"}, "C", canonical, scriptProbes)
		if len(unisolated) > 0 {
			entryLogControl(t, runs["C"], unisolated)
			t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
		}
		// G1 is decided by data alone (controller ruling 4): W's op cell is a
		// deny or a reach, or nothing is written.
		if v := readings["W op url: script"]; v != "deny" && v != "reached" {
			t.Fatalf("INVALID: W's op url cell reads %q, so G1 is undecided; no note is written", v)
		}
		if runs["Vw"].cells["scp /config/juniper.conf.gz"] == "file read" {
			t.Errorf("STOP: a class with `view` alone read the configuration file over scp: report to the controller")
		}
		var b strings.Builder
		fmt.Fprintf(&b, "The classes were committed: %s. REST: %s.\n\nThe op script, at `%s`:\n\n```\n%s\n```\n\n",
			commitWord(commit), commitWord(restCommit), junosEntryOpPath, strings.Join(junosEntryOpScript, "\n"))
		entryTables(&b, runs, readings, classes, scriptProbes)
		fmt.Fprintf(&b, "\n### Gates (plan 9b1)\n\n- G1, `op`: under W the script printed %s: %s.\n- G2, `rest`: under "+
			"W %s: %s.\n", runs["W"].cells["op url: script"], gateWord(readings["W op url: script"], "op"),
			runs["W"].cells["rest: get-configuration"], gateWord(readings["W rest: get-configuration"], "rest"))
		l.entryResult(t, "L26c-scripts", "Whether `deny-commands \"junoscript\"` beside a deny of `show configuration` "+
			"also refuses an `op url` script's `jcs:invoke` RPCs and REST's `/rpc`, and what `scp` of "+
			"`/config/juniper.conf.gz` reads under each class; against the same reply less the junoscript deny and a "+
			"control with the same bits and no deny (spec §15 L26c; plan 9b1 Task 3, cells b and e).", b.String())
	})
}

// gateWord is what a W verdict means for set 1.2.0's lists.
func gateWord(verdict, entry string) string {
	switch verdict {
	case "deny":
		return "closed by the junoscript deny; `" + entry + "` stays off set 1.2.0's list"
	case "reached":
		return "reached past the junoscript deny; `" + entry + "` goes on set 1.2.0's list"
	}
	return "not measured; `" + entry + "` is handled as reached (fails closed)"
}

// entryLogControl logs the raw output of each control cell that failed to
// reach, through RedactNote and the leak check, so an INVALID run can be read.
func entryLogControl(t *testing.T, control l26cRun, unisolated []string) {
	t.Helper()
	for _, u := range unisolated {
		p, _, _ := strings.Cut(u, ": the control")
		out := labcreds.RedactNote(control.outs[p])
		if err := leakIn(out, poolSecrets()); err != nil {
			t.Logf("control %s: output withheld: %v", p, err)
			continue
		}
		t.Logf("control %s (%s) output:\n%s", p, control.cells[p], out)
	}
}
