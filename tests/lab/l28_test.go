//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// L28 (spec §15): what a device does when port49d cannot validate its key,
// and a rotation end to end. port49d as first built read the body, recorded
// it, held the connection for the per-source backoff and closed it without a
// reply; that stalled every platform (tests/lab/results/L28-held-*.md), so
// it now closes a key miss at once and refuses a source inside its backoff
// at Accept (51fb593). Each phase restarts port49d on the lab config with
// its keys block replaced; the device keeps the lab key throughout until the
// rotation phase gives it the new one.
//
// The `stopped` phase is the control: the same three steps timed the same
// way with port49d not running, the condition every platform falls to local
// on at once (L4). The `expired` phase is v1 as an accept version whose
// retire_after has passed, which port49d refuses as retired from the first
// packet (Task 14).
//
// The rotation is captured apart from the phases, as L28-rotation-*: from
// the device's key change on, its bodies are obfuscated under the new key,
// and the redactor reads a file under one key (labcreds.CaptureKey).
func TestL28KeyMiss(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L28")
		defer stop()
		if os.Getenv("PORT49_L28_NEW_KEY") == "" {
			t.Setenv("PORT49_L28_NEW_KEY", labcreds.RotationKey)
		}
		yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
		var obs strings.Builder
		rev, _ := exec.Command("git", "-C", root, "rev-parse", "--short", "HEAD").Output()
		fmt.Fprintf(&obs, "port49d built from `%s` (`make build`).\n\n%s\n\n", strings.TrimSpace(string(rev)), l28Branch)
		for _, ph := range []struct{ name, keys, expect string }{
			{"stopped", "", ""},
			{"unknown", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n", "no_known_key_matches"},
			{"retired", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n" +
				"    retired: [{version: 1, secret_env: PORT49_LAB_KEY}]\n", "matches_retired"},
			{"expired", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n" +
				"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: " + yesterday + "}]\n", "matches_retired"},
			{"accepted", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n" +
				"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]\n", ""},
		} {
			obs.WriteString(l.l28Phase(t, ph.name, ph.keys, ph.expect))
		}
		// The phases' capture closes before the device's key changes, so it
		// holds the lab key's traffic only.
		phases := l.captureLine(t)
		stop()
		obs.WriteString("Capture of the phases above: " + phases + "\n\n")
		obs.WriteString(l.l28Rotate(t))
		l.result(t, "L28", l28Claim, obs.String())
	})
}

const l28Claim = "What a device does when port49d cannot validate its key (unknown, and retired), and that a " +
	"second accepted version and then the device's own key change carry it through a rotation (spec §15 L28)."

// l28Branch is plan 6a Task 20's branch reading, which every note carries.
const l28Branch = "**Branch H.** port49d as first built held a key miss for the per-source backoff, and that " +
	"stalled a break-glass session on every platform here (`tests/lab/results/L28-held-*.md`); closing it at " +
	"once with a FIN still stalled the C8000V, which waits out its own timeout on a FIN " +
	"(`tests/lab/results/L28-fin-cisco_iosxe.md`). So a first-packet key miss is now struck and closed at once " +
	"with a reset, and any source inside the backoff its last strike earned — a key miss's, and equally a " +
	"`malformed_after_validation`, `not_tacacs` or unadmitted source's — is refused at Accept with a reset for " +
	"that backoff: no record, counted as `port49_connection_events_total{event=\"held_refused\"}`. Each phase " +
	"below compares with the `stopped` phase, the device's local fall-through with nothing listening."

// l28Anchor is the standing config's keys block, which each phase replaces.
const l28Anchor = "  lab_key:\n    current: {version: 1, secret_env: PORT49_LAB_KEY}\n"

func (l *lab) l28Config(t *testing.T, name, keys string) string {
	t.Helper()
	base, err := l.configPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), l28Anchor) {
		t.Fatalf("%s has no standing lab_key block; the key phases cannot be derived", base)
	}
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-lab-"+l.p.name+"-l28-"+name+".yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), l28Anchor, keys, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (l *lab) l28Restart(t *testing.T, cfg string) {
	t.Helper()
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("stopping port49d: %v", err)
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		t.Fatalf("starting port49d on %s: %v", cfg, err)
	}
}

// l28Phase times a break-glass login, three commands in a break-glass
// session, and a token login, under one keys block — or with port49d
// stopped, when keys is "" — and reads what the log recorded for them.
func (l *lab) l28Phase(t *testing.T, name, keys, expect string) string {
	t.Helper()
	// Each phase starts from a device that is asking port49 (l28Live).
	base, err := l.configPath()
	if err != nil {
		t.Fatal(err)
	}
	live := l.l28Live(t, base)
	shown := keys
	if keys == "" {
		if err := l.stopDaemon(); err != nil {
			t.Fatalf("stopping port49d: %v", err)
		}
		shown = "# port49d stopped: nothing listens on 172.100.100.1:49\n"
	} else {
		l.l28Restart(t, l.l28Config(t, name, keys))
	}
	off := l.mark()
	t0 := time.Now()
	cl, bgErr := l.dial(breakglassUser, breakglassPassword, 120*time.Second)
	bgTook := time.Since(t0)
	bg := "logged in"
	if bgErr != nil {
		bg = "refused: " + oneLine(bgErr.Error())
	} else {
		cl.Close()
	}
	t1 := time.Now()
	_, cmdErr := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version", "show version", "show version")
	cmdTook := time.Since(t1)
	cmd := "ran"
	if cmdErr != nil {
		cmd = "not observed: " + oneLine(cmdErr.Error())
	}
	user, secret := l.nextLogin(t)
	t2 := time.Now()
	tc, tokErr := l.dial(user, secret, 120*time.Second)
	tokTook := time.Since(t2)
	tok := "logged in"
	if tokErr != nil {
		tok = "refused: " + oneLine(tokErr.Error())
	} else {
		tc.Close()
	}
	recs := l.drainRecords(off, 10*time.Second)
	diags, versions := map[string]int{}, map[string]int{}
	for _, r := range recs {
		if u := sub(r, "unvalidated"); u != nil {
			typ, _ := u["type"].(float64)
			diags[str(u, "diagnosis")+"/"+l28Types[int(typ)]]++
		}
		if d := sub(r, "device"); d != nil {
			if v, ok := d["key_version"].(float64); ok {
				versions[fmt.Sprintf("v%d", int(v))]++
			}
		}
	}
	if expect != "" && !hasDiag(diags, expect) {
		t.Errorf("phase %s: no %s record reached the log: %v", name, expect, diags)
	}
	return fmt.Sprintf("### Phase: %s\n\n%s\n\n```yaml\n%s```\n\n| step | outcome | took |\n|---|---|---|\n"+
		"| break-glass login | %s | %s |\n| break-glass login plus three `show version` | %s | %s |\n"+
		"| token login (`%s`) | %s | %s |\n\nUnvalidated records by diagnosis/type: %v. Validated records by key "+
		"version: %v.\n\n", name, live, shown, bg, bgTook.Round(10*time.Millisecond), cmd, cmdTook.Round(10*time.Millisecond),
		user, tok, tokTook.Round(10*time.Millisecond), diags, versions)
}

// l28Live restarts port49d on cfg, a config that validates the device's
// key, and probes with a login until one reaches it, so each phase starts
// from a device that is asking port49. On the first IOS-XE run a phase
// began while the device sent port49 nothing and was measured as a skipped
// server; after some phases no probe reaches port49 for about 30 s, and why
// is not established. The line says only what the probes saw.
func (l *lab) l28Live(t *testing.T, cfg string) string {
	t.Helper()
	l.l28Restart(t, cfg)
	t0 := time.Now()
	deadline := t0.Add(150 * time.Second)
	for attempt := 1; ; attempt++ {
		off := l.mark()
		if c, err := l.dial(l4ProbeUser, l4ProbePassword, 30*time.Second); err == nil {
			c.Close()
		}
		recs := l.waitForRecords(off, 15*time.Second, func(rs []map[string]any) bool {
			return redeemFor(rs, l4ProbeUser) != nil
		})
		took := time.Since(t0).Round(time.Second)
		switch {
		case redeemFor(recs, l4ProbeUser) != nil && attempt == 1:
			return fmt.Sprintf("Before this phase, with port49d validating the device's key: the first probe "+
				"login reached port49 (%s).", took)
		case redeemFor(recs, l4ProbeUser) != nil:
			return fmt.Sprintf("Before this phase, with port49d validating the device's key: no probe login "+
				"reached port49 until probe attempt %d; why is not established (%s).", attempt, took)
		case !time.Now().Before(deadline):
			t.Errorf("no probe login reached port49 within %s; the next step would measure a device not "+
				"asking port49", took)
			return fmt.Sprintf("Before this phase: **no probe login reached port49 in %s**.", took)
		}
		time.Sleep(5 * time.Second)
	}
}

// l28Types names an unvalidated record's header type (RFC 8907 §4.1).
var l28Types = map[int]string{1: "authen", 2: "author", 3: "acct"}

// hasDiag reports whether any diagnosis/type key in diags is diagnosis diag.
func hasDiag(diags map[string]int, diag string) bool {
	for k := range diags {
		if k == diag || strings.HasPrefix(k, diag+"/") {
			return true
		}
	}
	return false
}

// l28Rotate gives the device the new key while port49d accepts both, logs in
// with a token, and runs `port49 keys status` over the log.
func (l *lab) l28Rotate(t *testing.T) string {
	t.Helper()
	newKey := os.Getenv("PORT49_L28_NEW_KEY")
	var lines []string
	switch {
	case strings.HasPrefix(l.p.name, "juniper_"):
		l.junosConfigureAdmin(t, []string{"set system tacplus-server 172.100.100.1 secret \"" + newKey + "\""})
	case l.p.name == "cisco_iosxe":
		lines = []string{"tacacs server port49-host", "key 0 " + newKey}
	default:
		lines = []string{"tacacs-server host 172.100.100.1 key 0 " + newKey}
	}
	if lines != nil {
		l.carriedConfigure(t, lines...)
	}
	accepted := l.l28Config(t, "accepted", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n"+
		"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]\n")
	live := l.l28Live(t, accepted)
	stop := l.capture(t, "L28-rotation")
	defer stop()
	off := l.mark()
	user, secret := l.nextLogin(t)
	tc, err := l.dial(user, secret, 120*time.Second)
	tok := "logged in"
	if err != nil {
		tok = "refused: " + oneLine(err.Error())
	} else {
		tc.Close()
	}
	recs := l.drainRecords(off, 10*time.Second)
	v2 := 0
	for _, r := range recs {
		if d := sub(r, "device"); d != nil && d["key_version"] == float64(2) {
			v2++
		}
	}
	if v2 == 0 {
		t.Errorf("rotation: no record carried key_version 2 after the device was given the new key")
	}
	status, err := exec.Command(filepath.Join(root, "bin", "port49"), "keys", "status",
		"--policy", filepath.Join(root, "tests", "lab", "l28", "policy.yaml"),
		"--inventory", filepath.Join(root, "tests", "lab", "inventory-lab.yaml"),
		"--config", accepted, l.logPath).CombinedOutput()
	if err != nil {
		status = append(status, fmt.Sprintf("(exit: %v)\n", err)...)
	}
	return fmt.Sprintf("### Rotation: the device given the new key\n\n%s\n\nToken login (`%s`) after the device's key "+
		"changed, with port49d accepting v1 and v2: %s; %d record(s) carried `key_version` 2.\n\n"+
		"`port49 keys status` over the run's log:\n\n```\n%s```\n\nThis capture is the note's Capture line: "+
		"its bodies are obfuscated under the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`), "+
		"not the lab key.\n", live, user, tok, v2, status)
}
