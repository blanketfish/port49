//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// The vertical slice (plan 3; design §19 step 3): the first login to a real
// device with a credential nobody wrote down. A client certificate opens a
// session with the broker inside port49d (`port49 login`), a token is minted
// over it (`port49 token`), the token logs into the device, and every
// authorization is answered from the blob the mint compiled. A second window
// asks for a second token and gets a fresh one.
//
// vEOS only: the slice renders session attributes for arista_eos alone (plan 3,
// Decided 6), and a login elsewhere would measure plan 5's missing adapter.

const (
	sliceUser      = "slice01"
	sliceEmail     = "alice@slice.port49.test"
	slicePrincipal = "user:" + sliceEmail
	slicePKIDir    = "tests/lab/logs/slice-pki"
	sliceBrokerURL = "https://127.0.0.1:8449"
	sliceDenied    = "show hostname"
)

const sliceClaim = "The vertical slice end to end: an operator's client certificate, validated by the broker " +
	"against one trust anchor, mints a device token over a held mTLS connection (`port49 login`, `port49 token`); " +
	"the token logs into the device; every authorization is answered from the compiled blob the mint wrote; and a " +
	"second `port49 token` mints a fresh token rather than handing back the first."

var agentPID = regexp.MustCompile(`agent pid (\d+)`)

func TestSliceEndToEnd(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "arista_eos" {
			t.Skipf("the slice renders session attributes for arista_eos only (plan 3, Decided 6); %s waits for plan 5", l.p.name)
		}
		port49 := filepath.Join(root, "bin", "port49")
		if _, err := os.Stat(port49); err != nil {
			t.Fatalf("%s is missing: run `make build` before `make lab` (%v)", port49, err)
		}
		pki := filepath.Join(root, slicePKIDir)
		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
			t.Fatal(err)
		}
		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := l.derivedConfig("slice", platformSessionAttributes[l.p.name], string(brokerYAML))
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the broker block, so nothing was measured: %v", err)
		}
		defer func() {
			if err := l.stopDaemon(); err != nil {
				t.Errorf("could not stop the slice daemon: %v", err)
				return
			}
			std, err := l.configPath()
			if err != nil {
				t.Fatalf("derive this platform's daemon config: %v", err)
			}
			if err := l.startDaemonWith(std, true); err != nil {
				t.Fatalf("could not put port49d back on the lab config: %v", err)
			}
		}()

		stop := l.capture(t, "slice")
		defer stop()
		off := l.mark()

		sockDir, err := os.MkdirTemp("", "p49slice")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(sockDir)
		sock := filepath.Join(sockDir, "a", "agent.sock")
		out, err := exec.Command(port49, "login", "--broker", sliceBrokerURL,
			"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
			"--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", sock).CombinedOutput()
		if err != nil {
			t.Fatalf("port49 login: %v\n%s", err, out)
		}
		defer stopSliceAgent(t, string(out))

		tok1 := sliceToken(t, port49, sock)
		outs, err := l.login(sliceUser, tok1, "show version", sliceDenied)
		if err != nil {
			t.Fatalf("SSH login as %s with the broker-minted token failed: %v\nrecords:%s", sliceUser, err, summarize(l.recordsSince(off)))
		}
		// A second window is a second device connection, and it gets a fresh
		// mint (plan 3, Decided 11).
		tok2 := sliceToken(t, port49, sock)
		if tok2 == tok1 {
			t.Fatal("port49 token handed back a token it had already handed out")
		}
		if _, err := l.login(sliceUser, tok2, "show version"); err != nil {
			t.Fatalf("the second window's login failed: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}

		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return len(sliceRecords(rs, "redeem", "token_redeemed")) >= 2 && len(sliceRecords(rs, "authorize_command", "no_permit_dominates_deny")) >= 1
		})
		raw, err := os.ReadFile(l.logPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), tok1) || strings.Contains(string(raw), tok2) {
			t.Fatal("a minted token is in the decision log")
		}
		obs, err := sliceObservation(recs, []string{tok1, tok2}, outs)
		if err != nil {
			t.Fatalf("%v\nrecords:%s", err, summarize(recs))
		}
		l.resultOver(t, "slice", "SSH, with tokens minted by the broker over a held mTLS connection "+
			"(`port49 login`, `port49 token`)", sliceClaim, obs)
	})
}

func sliceToken(t *testing.T, port49, sock string) string {
	t.Helper()
	cmd := exec.Command(port49, "token", "--socket", sock, "leaf1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	tok := strings.TrimSpace(string(out))
	if err != nil || len(tok) != labcreds.TokenLen {
		t.Fatalf("port49 token leaf1: %v, %d characters on stdout; stderr: %s", err, len(tok), stderr.String())
	}
	return tok
}

func stopSliceAgent(t *testing.T, loginOut string) {
	m := agentPID.FindStringSubmatch(loginOut)
	if m == nil {
		t.Errorf("port49 login did not name the agent's pid, so it is still running: %q", loginOut)
		return
	}
	pid, _ := strconv.Atoi(m[1])
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Errorf("stopping the agent (pid %d): %v", pid, err)
	}
}

// sliceRecords are the records of one event and reason about slice01, or about
// the slice's principal for a mint.
func sliceRecords(recs []map[string]any, event, reason string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "event") != event || (reason != "" && str(r, "reason") != reason) {
			continue
		}
		if str(sub(r, "session"), "username") == sliceUser || str(r, "principal") == slicePrincipal {
			out = append(out, r)
		}
	}
	return out
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sliceObservation checks the chain the slice exists to show and renders it.
// Every link is read off a record; a missing link fails the test, because a
// run that did not produce it measured something else.
func sliceObservation(recs []map[string]any, tokens []string, outs []string) (string, error) {
	mints := sliceRecords(recs, "mint", "grants_matched")
	if len(mints) < 2 {
		return "", fmt.Errorf("want two permitted mints for %s, got %d", slicePrincipal, len(mints))
	}
	minted := map[string]bool{}
	for _, m := range mints {
		for _, h := range strs(sub(m, "mint"), "token_sha256") {
			minted[h] = true
		}
	}
	for i, tok := range tokens {
		if !minted[sha(tok)] {
			return "", fmt.Errorf("token %d's hash is on no mint record", i+1)
		}
	}
	hash := str(sub(mints[0], "mint"), "blob")
	var blobBody string
	for _, r := range recs {
		if str(r, "event") == "blob" && str(sub(r, "blob"), "hash") == hash {
			b, _ := json.Marshal(sub(r, "blob")["body"])
			blobBody = string(b)
		}
	}
	if blobBody == "" {
		return "", fmt.Errorf("no blob event carries %s", hash)
	}
	redeems := sliceRecords(recs, "redeem", "token_redeemed")
	if len(redeems) < 2 {
		return "", fmt.Errorf("want two redeems for %s, got %d", sliceUser, len(redeems))
	}
	for _, r := range redeems {
		if str(r, "principal") != slicePrincipal || !minted[str(sub(r, "auth"), "credential_sha256")] {
			return "", fmt.Errorf("a redeem does not join to a mint: %v", r)
		}
	}
	if str(sub(redeems[0], "session"), "ctx_id") != str(sub(redeems[1], "session"), "ctx_id") {
		return "", fmt.Errorf("the second window did not join the first's context")
	}
	denies := sliceRecords(recs, "authorize_command", "no_permit_dominates_deny")
	if len(denies) == 0 {
		return "", fmt.Errorf("no command of %s's was denied no_permit_dominates_deny", sliceUser)
	}
	deny := denies[0]
	if strings.Join(strs(sub(deny, "request"), "vector"), " ") != sliceDenied {
		return "", fmt.Errorf("the denial is of %v, not %q", strs(sub(deny, "request"), "vector"), sliceDenied)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Two `port49 token leaf1` calls over one `port49 login` session minted two different tokens for "+
		"principal `%s`, username `%s`, each on its own `mint` record naming blob `%s`. The `blob` event carried it:\n\n"+
		"```json\n%s\n```\n\n", slicePrincipal, sliceUser, hash, blobBody)
	b.WriteString("Every record for `slice01` in the run, in order (tokens appear as the hash the log carries):\n\n")
	b.WriteString("| event | verdict | reason | ctx_id | port | credential_sha256 / vector |\n|---|---|---|---|---|---|\n")
	for _, r := range recs {
		if str(sub(r, "session"), "username") != sliceUser {
			continue
		}
		detail := str(sub(r, "auth"), "credential_sha256")
		if v := strs(sub(r, "request"), "vector"); len(v) > 0 {
			detail = "`" + strings.Join(v, " ") + "`"
		} else if len(detail) > 12 {
			detail = "`" + detail[:12] + "…`"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | `%s` | `%s` | %s |\n", str(r, "event"), str(r, "verdict"), str(r, "reason"),
			str(sub(r, "session"), "ctx_id"), str(sub(r, "session"), "port"), detail)
	}
	fmt.Fprintf(&b, "\nBoth logins redeemed into ctx_id `%s`: the second window joined the first's context (spec §5.6).\n\n",
		str(sub(redeems[0], "session"), "ctx_id"))
	fmt.Fprintf(&b, "The device's reply to `%s`, which only the blob denies (`tests/lab/slice/policy.yaml`); the "+
		"decision record's server_msg was `%s`:\n\n```\n%s\n```\n", sliceDenied, str(deny, "server_msg"), strings.TrimSpace(orEmpty(outs, 1)))
	return b.String(), nil
}

func orEmpty(outs []string, i int) string {
	if i < len(outs) && strings.TrimSpace(outs[i]) != "" {
		return outs[i]
	}
	return emptyDeviceReply
}
