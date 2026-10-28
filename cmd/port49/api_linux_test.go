//go:build linux

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// The CLI's API commands, through a real agent to a real broker: identity
// says who the session is and until when its connection lasts; explain
// answers from the broker with no policy file; revoke --mine ends the
// caller's own sessions with no mark, so a token mints at once after it;
// revoking another principal, or a key without --mine, without the right is
// refused, exit 1, saying which right and, for a key, the --mine form; a
// key is refused the same.
func TestTheCLIReachesTheAPIThroughTheAgent(t *testing.T) {
	// The test's stdin may be a terminal; the question is
	// TestRevokePrincipalAsksOnATerminal's.
	defer func(tty func() bool) { confirmTTY = tty }(confirmTTY)
	confirmTTY = func() bool { return false }
	l := newLabBroker(t, time.Hour)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, l.flags(t, sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %s %s", code, out.String(), errb.String())
	}
	cli := func(args ...string) (int, string, string) {
		out.Reset()
		errb.Reset()
		code := run(args, &out, &errb)
		return code, out.String(), errb.String()
	}
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	if code, so, se := cli("identity"); code != 0 ||
		!strings.Contains(so, "principal  user:alice@example.com") || !strings.Contains(so, "subject    s") ||
		!strings.Contains(so, "all_devices [r]") || !strings.Contains(so, "api        (none") ||
		!strings.Contains(so, "this connection lasts until") {
		t.Fatalf("identity: %d %q %q", code, so, se)
	}
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	if code, so, se := cli("explain", "--device", "leaf1", "--command", "show version"); code != 0 ||
		!strings.HasPrefix(so, "permit permit_dominates") {
		t.Fatalf("explain: %d %q %q", code, so, se)
	}
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	if code, _, se := cli("explain", "--device", "leaf1", "--subject", "s"); code != 2 ||
		!strings.Contains(se, "--subject") {
		t.Fatalf("explain --subject over the agent: %d %q", code, se)
	}
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	if code, so, se := cli("revoke", "--mine"); code != 0 ||
		!strings.Contains(so, "ended user:alice@example.com's sessions everywhere") {
		t.Fatalf("revoke --mine: %d %q %q", code, so, se)
	}
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	if code, so, se := cli("token", "leaf1"); code != 0 || so == "" {
		t.Fatalf("a token after revoke --mine: %d %q %q", code, so, se)
	}
	// This agent has no touch key, so an admin call is refused before it is
	// sent, saying what to do; the right is another test's (admin_test.go).
	if code, _, se := cli("revoke", "--principal", "user:carol@example.com", "--yes"); code != 1 ||
		!strings.Contains(se, "no touch_key is configured") || !strings.Contains(se, "nothing was sent") ||
		strings.Contains(se, "touch your key") {
		t.Fatalf("an admin call with no touch key: %d %q", code, se)
	}
	if code, _, se := cli("revoke", "--lift", "--device", "leaf1", "--username", "alice"); code != 2 ||
		!strings.Contains(se, "--lift") {
		t.Fatalf("--lift of a key: %d %q", code, se)
	}
}

// --principal asks before it marks someone, on a terminal only, and before
// the key is touched; a no sends nothing, and --yes skips the question
// (pre-flight M11). The socket, in a private directory, has no agent, so a
// request that is sent says so.
func TestRevokePrincipalAsksOnATerminal(t *testing.T) {
	defer func(in io.Reader, tty func() bool) { confirmIn, confirmTTY = in, tty }(confirmIn, confirmTTY)
	confirmTTY = func() bool { return true }
	t.Setenv("PORT49_TEST_AGENT_SOCKET", privateSocket(t))
	args := []string{"revoke", "--principal", "user:bob@example.com"}
	var out, errb bytes.Buffer
	confirmIn = strings.NewReader("n\n")
	if code := run(args, &out, &errb); code != 1 || !strings.Contains(errb.String(), "[y/N]") ||
		!strings.Contains(errb.String(), "nothing was revoked") || strings.Contains(errb.String(), "no agent is running") {
		t.Fatalf("declined: %d %q", code, errb.String())
	}
	errb.Reset()
	confirmIn = strings.NewReader("")
	if code := run(append(args, "--yes"), &out, &errb); code != 1 || strings.Contains(errb.String(), "[y/N]") ||
		!strings.Contains(errb.String(), "no agent is running") {
		t.Fatalf("--yes: %d %q", code, errb.String())
	}
	errb.Reset()
	confirmTTY = func() bool { return false }
	if code := run(args, &out, &errb); code != 1 || strings.Contains(errb.String(), "[y/N]") {
		t.Fatalf("off a terminal: %d %q", code, errb.String())
	}
	confirmTTY = func() bool { return true }
	errb.Reset()
	confirmIn = strings.NewReader("y\n")
	if code := run(args, &out, &errb); code != 1 || !strings.Contains(errb.String(), "[y/N]") ||
		!strings.Contains(errb.String(), "no agent is running") || strings.Contains(errb.String(), "nothing was revoked") {
		t.Fatalf("a yes: %d %q", code, errb.String())
	}
	errb.Reset()
	confirmIn = strings.NewReader("")
	if code := run(args, &out, &errb); code != 1 || !strings.Contains(errb.String(), "[y/N]") ||
		!strings.Contains(errb.String(), "nothing was revoked") || strings.Contains(errb.String(), "no agent is running") {
		t.Fatalf("EOF on a terminal: %d %q", code, errb.String())
	}
}

// --yes belongs to --principal alone: elsewhere it is usage, so an operator
// is not left wondering why the flag did nothing.
func TestRevokeFlagsOutOfPlace(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"revoke", "--mine", "--yes"}, "--yes"},
		{[]string{"revoke", "--device", "leaf1", "--username", "bob", "--yes"}, "--yes"},
		{[]string{"revoke", "--list", "--yes"}, "--yes"},
		{[]string{"revoke", "--list", "--principal", "user:bob@example.com"}, "--list"},
		{[]string{"revoke", "--mine", "--principal", "user:bob@example.com"}, "--mine"},
		{[]string{"revoke"}, "name a principal"},
	} {
		var out, errb bytes.Buffer
		if code := run(tc.args, &out, &errb); code != 2 || !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: %d %q", tc.args, code, errb.String())
		}
	}
}

// /dev/null is a character device but no terminal: a script run with
// </dev/null is not asked, so its revocation is not refused by an EOF.
func TestDevNullIsNotATerminal(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("/dev/null taken for a terminal")
	}
}
