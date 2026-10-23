//go:build lab

package lab

import (
	"fmt"
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
// had debug on. Its results note, tests/lab/results/QUAL-DEBUG-<slug>-<platform>.md,
// is written by the harness from the same run (qualWriteDebug): platform and image
// from the run, each open question answered by a kept debug line or unmeasured.
// Everything the arm writes passes deviceDebugFilter.Keep (in
// captureDeviceDebug) first; the raw collect text is held in memory only.

// ddArmEnv is the opt-in variable.
const ddArmEnv = "PORT49_LAB_DEVICE_DEBUG"

// ddArmState is what an armed run collects across its cells.
type ddArmState struct {
	files map[string][]byte // <cell>-debug.txt and <cell>-summary.txt
	notes []string          // one line per cell, for the results note
	conns map[string][]l73Conn
	ready int // connections of the readiness probe that ran after debug went on
	// profile and cells are what the results note is written from (qualWriteDebug).
	profile string
	cells   []ddNoteCell
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
// lines the collect commands returned (not the echo or the prompt), keeps the
// shapes of the lines the filter drops, and returns the raw text to
// captureDeviceDebug alone.
func ddArmRun(c *cliConn, f deviceDebugFilter, secrets func() []string, platform string, rawLines *int, sample, cmdShapes *[]string) func(string) (string, error) {
	cfgMode := false
	return func(cmd string) (string, error) {
		var wait []string
		wait, cfgMode = ddArmWait(platform, cmd, cfgMode, c.prompt)
		out, err := c.sendExpect(cmd, 180*time.Second, wait...)
		if ddArmIsCollect(platform, cmd) {
			n := ddArmCountLines(out, cmd, wait...)
			*rawLines += n
			*cmdShapes = append(*cmdShapes, fmt.Sprintf("%s => returned %d line(s)", cmd, n))
			// The shapes of what the filter drops: the lines to decide about.
			var dropped []string
			for _, ln := range strings.Split(out, "\n") {
				if !f.keeps(deviceDebugProfiles[platform], ln) {
					dropped = append(dropped, ln)
				}
			}
			for _, sh := range ddArmSample(l73MaskAll(strings.Join(dropped, "\n"), secrets()...), 500) {
				*sample = append(*sample, cmd+" => "+sh)
			}
		} else {
			// What the enable and disable commands answered, as shapes: the
			// first thing to learn when no debug line comes back.
			for _, sh := range ddArmSample(l73MaskAll(out, secrets()...), 6) {
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
// makes are in the log too, and the summary says how many connections they were).
// post, if any, makes the device reach port49d again once the session has ended
// and port49d is back. The collection runs with port49d stopped, as L80's does.
// A Fatal in the body still stops port49d and turns debug off (the deferred
// disable), though that run collects nothing.
func (q *qualEnv) debugCell(e *l73Env, cell string, restart, post, body func()) {
	platform, ok := q.armed(e.d.Family)
	if !ok {
		body()
		return
	}
	drops := &ddDropCounts{}
	filter := deviceDebugFilter{Platform: platform, Secrets: q.ddSecrets, Drops: drops}
	// Junos: count the syslog process tags of what the device returned, to learn
	// which process writes the login path (numbers only).
	var tags *ddTagCounts
	if platform == "junos" {
		tags = &ddTagCounts{}
		filter.Tags = tags
	}
	var (
		kept     deviceDebugKept
		capErr   error
		rawLines int
		sample   []string
		answers  []string
		ran      bool
	)
	e.cli(func(c *cliConn) error {
		// Debug goes on first, while port49d is stopped and the session is the
		// local one: with port49d up, the device sends this session's commands
		// to it and they are refused ("this session was not ... by port49").
		run := ddArmRun(c, filter, q.ddSecrets, platform, &rawLines, &sample, &answers)
		kept, capErr = captureDeviceDebug(filter, run, func() error {
			ran = true
			finished := false
			defer func() {
				if !finished { // a Fatal in the body (Goexit): debug must still go off
					e.l.stopDaemon()
					disableDeviceDebug(deviceDebugCmds[platform], run)
				}
			}()
			restart()
			body()
			finished = true
			return e.l.stopDaemon()
		})
		return nil
	})
	q.t.Logf("device debug command answers, %s %s (shapes):\n  %s", platform, cell, strings.Join(answers, "\n  "))
	if !ran {
		// Debug would not go on (the summary says why): the cell is still
		// played, without it, so the run's other results stand.
		restart()
		body()
	}
	q.login()
	if post != nil {
		post()
	}
	var conns []string
	for _, cn := range q.dd.conns[cell] {
		conns = append(conns, l80ConnLine(cn))
	}
	sum := ddArmSummary(platform, cell, kept, rawLines, conns)
	sum += "lines dropped by rule: " + drops.String() + "\n"
	tagCounts := ""
	if tags != nil {
		tagCounts = tags.String()
		sum += "syslog process tags (counts only): " + tagCounts + "\n"
	}
	sum += fmt.Sprintf("readiness probe connections after debug went on, before the cell (in the log, not in the cell's tls connections): %d\n", q.dd.ready)
	if capErr != nil {
		sum += "capture error: " + capErr.Error() + "\n"
	}
	// The shapes the device wrote that the filter drops (never a value) go to
	// the test log, not to evidence, for an implementer to read through the
	// filtered grep.
	q.t.Logf("device debug, shapes of the lines the filter dropped, %s %s (closed alphabet):\n  %s", platform, cell, strings.Join(sample, "\n  "))
	if ddArmLineCount(kept) == 0 {
		sum += "THE FILTER KEPT NOTHING USEFUL: the line shapes are in the test log\n"
	}
	q.dd.profile = platform
	q.dd.cells = append(q.dd.cells, ddNoteCell{Cell: cell, Kept: kept, RawLines: rawLines, Shapes: sample, TLSConns: conns,
		Ready: q.dd.ready, CaptureErr: capErr != nil, Drops: *drops, Tags: tagCounts})
	q.dd.files[cell+"-debug.txt"] = []byte(string(kept) + "\n")
	q.dd.files[cell+"-summary.txt"] = []byte(l80Filter(sum))
	q.dd.notes = append(q.dd.notes, fmt.Sprintf("- `%s`: %d device log lines, the filter kept %d, %d tls connection(s).",
		cell, rawLines, ddArmLineCount(kept), len(conns)))
}

// ddSecrets is every credential this run used, for the leak gate on what the
// arm writes and logs.
func (q *qualEnv) ddSecrets() []string {
	var fromEnv []string
	if q.e != nil {
		fromEnv = q.e.allSecrets()
	}
	return ddKnownSecrets([]string{breakglassPassword}, q.secrets, fromEnv)
}

// ddArmCheck stops a run that has debug asked for and cannot give it, before
// any lab work and before anything under evidence/ is touched.
func (q *qualEnv) ddArmCheck() {
	q.t.Helper()
	d, ok := l73Dialects[q.l.p.name]
	if !ok || d.HelpOnly || !optInPlatforms[q.l.p.sel] {
		q.t.Fatalf("INVALID: %s=1, but %s has no TLS cells to put debug around", ddArmEnv, q.l.p.sel)
	}
	if _, ok := ddArmPlatform(d.Family); !ok {
		q.t.Fatalf("INVALID: %s=1, but %s has no device-debug profile (NX-OS has its own arm, L80)", ddArmEnv, q.l.p.sel)
	}
}

// writeDebug is an armed run's whole output, in place of write.
func (q *qualEnv) writeDebug() {
	q.t.Helper()
	if len(q.dd.files) == 0 {
		q.t.Fatal("INVALID: an armed run collected no debug; the committed evidence is untouched")
	}
	dir := filepath.Join(root, "tests", "lab", "evidence", "QUAL-DEBUG-"+q.slug+"-"+q.l.p.name)
	note := "Device debug around the TLS cells of a re-vet:\n" + strings.Join(q.dd.notes, "\n")
	if bad := qualWriteEvidence(dir, q.dd.files, note, q.ddSecrets()); len(bad) > 0 {
		q.t.Fatalf("INVALID: nothing written:\n  %s", strings.Join(bad, "\n  "))
	}
	q.t.Logf("wrote %s", dir)
	// The results note is written from the same run, never by hand. Platform and
	// image are the run's.
	run := ddNoteRun{Platform: q.l.p.name, Profile: q.dd.profile, Image: q.run.Image, Cells: q.dd.cells}
	err := qualWriteDebug(run, q.ddSecrets(), func(claim, obs string) {
		q.l.result(q.t, "QUAL-DEBUG-"+q.slug, claim, obs)
	})
	if err != nil {
		q.t.Fatalf("%v", err)
	}
}
