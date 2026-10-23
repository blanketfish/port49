//go:build lab

package lab

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The device-debug arm of TestQualify (post-11b fix PR, task 8): with
// PORT49_LAB_DEVICE_DEBUG=1 the platform's own TACACS+ debug is on around
// tls_token_login and tls_unknown_ca, and only the filtered text and the
// summary are written, to tests/lab/evidence/QUAL-DEBUG-<slug>-<platform>/.
// An armed run is a measurement of its own: it writes no QUAL evidence and no
// QUAL note, so a re-vet's committed evidence is never replaced by a run that
// had debug on. Everything the arm writes passes deviceDebugFilter.Keep (in
// captureDeviceDebug) first; the raw collect text is held in memory only.

// ddArmEnv is the opt-in variable.
const ddArmEnv = "PORT49_LAB_DEVICE_DEBUG"

// ddArmState is what an armed run collects across its cells.
type ddArmState struct {
	files map[string][]byte // <cell>-debug.txt and <cell>-summary.txt
	notes []string          // one line per cell, for the results note
	conns map[string][]l73Conn
	ready int // connections of the readiness probe that ran after debug went on
}

// armed is whether this run is a device-debug run on a platform that has a
// debug profile.
func (q *qualEnv) armed(family string) (string, bool) {
	if os.Getenv(ddArmEnv) != "1" {
		return "", false
	}
	return ddArmPlatform(family)
}

// ddArmRun is the run function captureDeviceDebug drives on the held CLI:
// it types one line and waits for the prompt that line leaves. It counts the
// lines the collect commands returned and keeps a shape sample of them for the
// case where the filter keeps nothing, and returns the raw text to
// captureDeviceDebug alone.
func ddArmRun(c *cliConn, f deviceDebugFilter, platform string, rawLines *int, sample, cmdShapes *[]string) func(string) (string, error) {
	cfgMode := false
	return func(cmd string) (string, error) {
		var wait []string
		wait, cfgMode = ddArmWait(platform, cmd, cfgMode, c.prompt)
		out, err := c.sendExpect(cmd, 180*time.Second, wait...)
		if strings.HasPrefix(cmd, "show log") {
			*rawLines += strings.Count(out, "\n")
			// The shapes of what the filter drops: the lines to decide about.
			var dropped []string
			for _, ln := range strings.Split(out, "\n") {
				if f.Keep(ln) == "" {
					dropped = append(dropped, ln)
				}
			}
			*sample = append(*sample, ddArmSample(strings.Join(dropped, "\n"), 70)...)
		} else {
			// What the enable and disable commands answered, as shapes: the
			// first thing to learn when no debug line comes back.
			for _, sh := range ddArmSample(out, 6) {
				*cmdShapes = append(*cmdShapes, cmd+" => "+sh)
			}
		}
		return out, err
	}
}

// debugCell runs body, a cell of the TLS arm, with the platform's debug on
// when the run is armed, and plain body otherwise. restart brings port49d up
// on the daemon the cell expects and makes the device reach it; it runs in a
// held break-glass session, after debug is turned on (the readiness probes it
// makes are in the log too, and the summary says how many connections they were). post, if any, makes the device reach port49d again once the
// session has ended and port49d is back. The collection runs with port49d stopped, as L80's does.
func (q *qualEnv) debugCell(e *l73Env, cell string, restart, post, body func()) {
	platform, ok := q.armed(e.d.Family)
	if !ok {
		body()
		return
	}
	// post makes the device reach port49d again once the held session ends.
	filter := deviceDebugFilter{Platform: platform, Groups: []string{l73Group}}
	for _, a := range []string{l73Server, q.l.p.addr} {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			q.t.Fatalf("INVALID: lab address %q: %v", a, err)
		}
		filter.Addrs = append(filter.Addrs, addr)
	}
	var (
		kept     deviceDebugKept
		capErr   error
		rawLines int
		sample   []string
		answers  []string
	)
	e.cli(func(c *cliConn) error {
		// Debug goes on first, while port49d is stopped and the session is the
		// local one: with port49d up, the device sends this session's commands
		// to it and they are refused ("this session was not ... by port49").
		kept, capErr = captureDeviceDebug(filter, ddArmRun(c, filter, platform, &rawLines, &sample, &answers), func() error {
			restart()
			body()
			return e.l.stopDaemon()
		})
		return nil
	})
	q.t.Logf("device debug command answers, %s %s (shapes):\n  %s", platform, cell, strings.Join(answers, "\n  "))
	q.login()
	if post != nil {
		post()
	}
	var conns []string
	for _, cn := range q.dd.conns[cell] {
		conns = append(conns, l80ConnLine(cn))
	}
	sum := ddArmSummary(platform, cell, kept, rawLines, conns)
	sum += fmt.Sprintf("readiness probe connections after debug went on, before the cell (in the log, not in the cell's tls connections): %d\n", q.dd.ready)
	if capErr != nil {
		sum += "capture error: " + capErr.Error() + "\n"
	}
	// The shapes the device wrote that the filter drops (never a value) go to
	// the test log, not to evidence, for an implementer to read through the
	// filtered grep.
	q.t.Logf("device debug, shapes of the lines the filter dropped, %s %s (values masked):\n  %s", platform, cell, strings.Join(sample, "\n  "))
	masked := 0
	for _, ln := range strings.Split(string(kept), "\n") {
		if strings.Contains(ln, "<masked>") {
			masked++
		}
	}
	if n := ddArmLineCount(kept); n == 0 || masked*10 >= n*8 {
		sum += "THE FILTER KEPT NOTHING USEFUL: the line shapes are in the test log\n"
	}
	q.dd.files[cell+"-debug.txt"] = []byte(string(kept) + "\n")
	q.dd.files[cell+"-summary.txt"] = []byte(l80Filter(sum))
	q.dd.notes = append(q.dd.notes, fmt.Sprintf("- `%s`: %d device log lines, the filter kept %d, %d tls connection(s).",
		cell, rawLines, ddArmLineCount(kept), len(conns)))
}

// writeDebug is an armed run's whole output, in place of write.
func (q *qualEnv) writeDebug() {
	q.t.Helper()
	secrets := append([]string{breakglassPassword}, q.secrets...)
	if q.e != nil {
		secrets = append(secrets, q.e.allSecrets()...)
	}
	dir := filepath.Join(root, "tests", "lab", "evidence", "QUAL-DEBUG-"+q.slug+"-"+q.l.p.name)
	note := "Device debug around the TLS cells of a re-vet:\n" + strings.Join(q.dd.notes, "\n")
	if bad := qualWriteEvidence(dir, q.dd.files, note, secrets); len(bad) > 0 {
		q.t.Fatalf("INVALID: nothing written:\n  %s", strings.Join(bad, "\n  "))
	}
	if len(q.dd.files) == 0 {
		q.t.Fatal(errors.New("INVALID: an armed run collected no debug"))
	}
	q.t.Logf("wrote %s", dir)
}
