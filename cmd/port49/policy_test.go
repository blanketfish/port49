package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
)

// unmappedLevel declares a level no built-in platform renders: a role landing
// an arista_eos session there quarantines the device. `operator` renders on
// EOS since the owner's ruling of 2026-09-24 (spec §6, decision 23).
const unmappedLevel = "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"

// policyFixture writes a small policy and inventory and returns their paths.
func policyFixture(t *testing.T) (pol, inv string) {
	t.Helper()
	dir := t.TempDir()
	pol = filepath.Join(dir, "policy.yaml")
	inv = filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(pol, []byte(`
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: read_only, privilege: readonly, permit: [show **]}
  - {name: no_reload, deny: [reload **]}
  - {name: admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
  - {name: ops, identity: "user:ops@example.com", username: ops, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [read_only, no_reload]}
  - {subject: ops, scope: all_devices, roles: [admin]}
tests:
  - {subject: noc, device: leaf-01, command: "show version", expect: permit}
  - {subject: noc, device: leaf-01, command: "reload", expect: deny}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return pol, inv
}

// `port49 explain` prints the one reason and the roles that would permit a
// denied command, from the files alone.
func TestExplainPrintsTheDecision(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	code := run([]string{"explain", "--policy", pol, "--inventory", inv, "--subject", "noc", "--device", "leaf-01",
		"--command", "reload now"}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "deny no_rule_matched") || !strings.Contains(out.String(), "permitted by admin") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	code = run([]string{"explain", "--policy", pol, "--inventory", inv, "--principal", "user:ops@example.com",
		"--device", "leaf-01"}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "priv-lvl=15") {
		t.Fatalf("session: code %d\n%s%s", code, out.String(), errb.String())
	}
}

func TestExplainRefusesAnIncompleteAsk(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	if code := run([]string{"explain", "--policy", pol, "--inventory", inv, "--device", "leaf-01"}, &out, &errb); code != 2 {
		t.Fatalf("no subject or principal: code %d", code)
	}
	if code := run([]string{"explain", "--policy", pol, "--subject", "noc", "--device", "leaf-01"}, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "--inventory") {
		t.Fatalf("no inventory: code %d %s", code, errb.String())
	}
}

// A usage error exits 2, so CI tells a misconfigured job from a policy that
// does not load (1): a missing file flag, a stray argument, no subcommand, an
// unknown one, a bad flag.
func TestPolicyToolsExitTwoOnAUsageError(t *testing.T) {
	pol, inv := policyFixture(t)
	for _, args := range [][]string{
		{"policy", "test", "--policy", pol},
		{"policy", "test", "--policy", pol, "--inventory", inv, "extra"},
		{"policy", "test", "--bogus"},
		{"policy"},
		{"policy", "lint"},
		{"access", "review", "--inventory", inv, "--subject", "noc"},
		{"explain", "--policy", pol, "--inventory", inv, "--subject", "noc", "--device", "leaf-01", "extra"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 || out.Len() != 0 {
			t.Errorf("%q: code %d, stdout %q", args, code, out.String())
		}
	}
}

// `port49 policy test` passes a policy whose tests pass, and fails one whose
// test does not, naming it. It says first which platform set the policy
// renders with (spec §8).
func TestPolicyTestIsACIGate(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "platform_set: 1.0.0\n") ||
		!strings.Contains(out.String(), "PASS noc on leaf-01: \"reload\" -> deny no_rule_matched") ||
		!strings.Contains(out.String(), "2 tests, 0 failed; 0 shadowed denies, 0 unacknowledged") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	raw := readFile(t, pol)
	if err := os.WriteFile(pol, []byte(strings.Replace(string(raw), `command: "reload", expect: deny`,
		`command: "reload", expect: permit`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "FAIL noc on leaf-01: \"reload\" -> deny no_rule_matched, want permit") {
		t.Fatalf("code %d\n%s", code, out.String())
	}
}

// A deny a more specific permit beats fails the gate until a policy test
// exercises it (spec §12): the report names the deny, the subject and the
// permit, and the test is the acknowledgment.
func TestPolicyTestFailsAnUnacknowledgedShadow(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	shadowed := strings.Replace(string(raw), "permit: [show **]}", "permit: [show **, reload now]}", 1)
	if err := os.WriteFile(pol, []byte(shadowed), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `shadowed: "reload **" (no_reload) does not bind noc where "reload now" (read_only) is more specific, on arista_eos; no policy test exercises it`) ||
		!strings.Contains(out.String(), "1 shadowed denies, 1 unacknowledged") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	acked := shadowed + "  - {subject: noc, device: leaf-01, command: \"reload now\", expect: permit}\n"
	if err := os.WriteFile(pol, []byte(acked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "a policy test exercises it") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// `port49 policy diff` is the privilege-expansion gate (spec §12): a command
// a deny refused that the new version permits fails it, until a policy test
// in the new version exercises that permit over that deny.
func TestPolicyDiffGatesAnExpansionPastADeny(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := readFile(t, oldPol)
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	expanded := strings.Replace(string(raw), "permit: [show **]}", "permit: [show **, reload now]}", 1)
	if err := os.WriteFile(newPol, []byte(expanded), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `EXPANDS: noc on leaf-01: "reload now" was denied by "reload **" (no_reload), now permitted by "reload now" (read_only)`) ||
		!strings.Contains(out.String(), "1 unacknowledged expansions past a deny") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	acked := expanded + "  - {subject: noc, device: leaf-01, command: \"reload now\", expect: permit}\n"
	if err := os.WriteFile(newPol, []byte(acked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "expands (a policy test exercises it)") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	if code := run([]string{"policy", "diff", "--old", oldPol, "--inventory", inv}, &out, &errb); code != 2 {
		t.Fatalf("no --new: code %d", code)
	}
}

// A mint the broker would refuse permits nothing, so `policy test` fails a
// test that expects permit there and names the mint item error, and `policy
// diff` fails a change that locks a subject out at the mint (spec §12).
func TestPolicyTestAndDiffAnswerAsTheBrokerMints(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := readFile(t, oldPol)
	refused := strings.Replace(string(raw), "{name: read_only, privilege: readonly, permit: [show **]}",
		`{name: read_only, privilege: readonly, permit: [show **], attributes: {arista_eos: ["home-directory*/`+strings.Repeat("h", 227)+`/{principal}"]}}`, 1)
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(newPol, []byte(refused), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `FAIL noc on leaf-01: "show version" -> deny: the broker refuses the mint, attribute_too_long`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "REFUSED: noc on leaf-01: the new version's broker refuses every mint there, attribute_too_long") ||
		!strings.Contains(out.String(), "1 mints newly refused") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	// No test acknowledges a lockout (owner's ruling 2026-09-24): with every
	// test in the new version passing, the refusal still fails the gate.
	allPass := strings.Replace(refused, `command: "show version", expect: permit`, `command: "show version", expect: deny`, 1)
	if err := os.WriteFile(newPol, []byte(allPass), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", newPol, "--inventory", inv}, &out, &errb); code != 0 {
		t.Fatalf("the new version's own tests pass: code %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "1 mints newly refused") {
		t.Fatalf("a refused mint fails whatever the tests say: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A possible shadow a test exercises is a shadow: the test proved the two
// patterns meet.
func TestPolicyTestReportsAPossibleShadowATestProves(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	body := strings.Replace(string(raw), "permit: [show **]}", `permit: [show **, "show /^ver/ detail"]}`, 1)
	body = strings.Replace(body, "deny: [reload **]}", `deny: [reload **, "show /^v/ *"]}`, 1)
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `possibly shadowed: "show /^v/ *" (no_reload) does not bind noc`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	body += "  - {subject: noc, device: leaf-01, command: \"show version detail\", expect: permit}\n"
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `shadowed: "show /^v/ *" (no_reload) does not bind noc where "show /^ver/ detail" (read_only) is more specific, on arista_eos; a policy test exercises it`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A policy that fails a load-time check fails the gate, with the check's
// message, before any test runs: here, a class no platform defines (spec §4).
// A policy that loads with a device quarantined names it (spec §10).
func TestPolicyTestFailsAPolicyThatDoesNotLoad(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	if err := os.WriteFile(pol, []byte(strings.Replace(string(raw), "permit: [show **]", "permit: [interface @uplinks]", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "permit #1: term 2 names a class which no platform defines") || out.Len() != 0 {
		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out.String(), errb.String())
	}
	if err := os.WriteFile(pol, []byte(unmappedLevel+strings.Replace(string(raw), "privilege: readonly", "privilege: unmapped", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "quarantine: leaf-01 (arista_eos): subject \"noc\": level unmapped has no rendering") ||
		!strings.Contains(out.String(), "FAIL noc on leaf-01: \"show version\" -> deny device_quarantined, want permit") {
		t.Fatalf("code %d\n%s", code, out.String())
	}
}

// `port49 policy replay` agrees with a log the engine wrote and fails one
// whose record was edited. The log here is written by the engine directly;
// internal/replay's tests run the daemon's handler.
func TestPolicyReplayFindsAnEditedRecord(t *testing.T) {
	b := engine.Blob{Bundle: "sha256:p", Platform: "arista_eos", Normalize: engine.Normalize{PipeToken: "|"},
		Rules: []engine.Rule{{Verdict: engine.Permit, Rule: "show **", Role: "read_only"}}}
	body, hash, err := engine.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := engine.Decode(hash, body)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := engine.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	raw := []string{"service=shell", "cmd=show", "cmd-arg=version"}
	o := prog.Command(raw)
	var log bytes.Buffer
	sink := decision.NewJSONLines(&log)
	sink.Emit(decision.Record{Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
	sink.Emit(decision.Record{Event: decision.EventAuthorizeCommand, Verdict: decision.VerdictPermit, Reason: o.Reason,
		Device: &decision.Device{Name: "leaf-01", Platform: "arista_eos"}, Request: &decision.Request{Raw: raw},
		Policy: o.Policy(b.Bundle, hash)})
	// Decided before policy ran: counted, not replayed.
	sink.Emit(decision.Record{Event: decision.EventAuthorizeCommand, Verdict: decision.VerdictDeny,
		Reason: decision.StoreUnavailable, Request: &decision.Request{Raw: raw}})
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(path, log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "replay", path}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "replayed 1 records: 1 agree, 0 diverge, 0 unverifiable; 1 not replayed (store_unavailable 1)") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	// A record replay passes over is not an answer to --line.
	out.Reset()
	if code := run([]string{"policy", "replay", "--line", "3", path}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "line 3 authorize_command: not_replayed store_unavailable is decided before policy runs") ||
		!strings.Contains(errb.String(), "line 3 is not an authorization record that consulted a blob") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	edited := strings.Replace(log.String(), `"verdict":"permit","reason":"permit_dominates"`,
		`"verdict":"deny","reason":"no_rule_matched"`, 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "replay", "--line", "2", path}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "line 2 authorize_command: diverge logged deny no_rule_matched, replayed permit permit_dominates") {
		t.Fatalf("code %d\n%s", code, out.String())
	}
}

// `port49 access review` prints every grant row of one subject with the scope
// size, from the files alone.
func TestAccessReviewPrintsTheGrantRows(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	if code := run([]string{"access", "review", "--policy", pol, "--inventory", inv, "--subject", "noc"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	for _, want := range []string{"noc (humans; identity user:noc@example.com)", "SCOPE", "all_devices  no_reload read_only  -",
		"never    1\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if code := run([]string{"access", "review", "--policy", pol, "--inventory", inv, "--subject", "nobody"}, &out, &errb); code != 1 {
		t.Fatalf("an undeclared subject: code %d", code)
	}
	// A group subject, a lapsed row, and a subject with no rows at all.
	body := strings.Replace(string(readFile(t, pol)), "subjects:\n",
		"subjects:\n  - {name: oncall, group: NetOps-OnCall, token_ttl: 60s}\n"+
			"  - {name: idle, identity: \"user:idle@example.com\", username: idle, token_ttl: 60s}\n", 1)
	body = strings.Replace(body, "grants:\n", "grants:\n  - {subject: oncall, scope: all_devices, roles: [read_only], expires: 2020-01-01}\n", 1)
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"access", "review", "--policy", pol, "--inventory", inv, "--subject", "oncall"}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "oncall (humans; group NetOps-OnCall)") ||
		!strings.Contains(out.String(), "2020-01-01T00:00:00Z (expired)") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"access", "review", "--policy", pol, "--inventory", inv, "--subject", "idle"}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "no grant rows: the subject reaches no device") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// `port49 grants remove` prints the policy without the subject, or replaces
// the file with --write, and refuses a result that would not load.
func TestGrantsRemoveOffboardsASubject(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops"}, &out, &errb); code != 0 ||
		strings.Contains(out.String(), "ops@example.com") || !strings.Contains(out.String(), "noc@example.com") ||
		!strings.Contains(errb.String(), "ops: 1 grant row(s), the subject block, and 0 test(s) removed") {
		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out.String(), errb.String())
	}
	before := readFile(t, pol)
	if !strings.Contains(string(before), "ops@example.com") {
		t.Fatal("without --write the file is left alone")
	}
	out.Reset()
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--write"}, &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("--write: code %d %s", code, out.String())
	}
	after := readFile(t, pol)
	if strings.Contains(string(after), "ops@example.com") {
		t.Fatalf("--write replaced nothing:\n%s", after)
	}
	if info, _ := os.Stat(pol); info.Mode().Perm() != 0o600 {
		t.Fatalf("the file's mode changed: %v", info.Mode())
	}
	// noc is the last subject: removing it leaves a policy that declares none,
	// which does not load, so nothing is written.
	errb.Reset()
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--write"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "nothing was written") {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if kept := readFile(t, pol); string(kept) != string(after) {
		t.Fatal("a refused removal must not touch the file")
	}
}

// --write through a symlinked policy path replaces the file the link names,
// not the link, so a checkout behind /etc/port49/policy.yaml is what changes.
func TestGrantsRemoveWritesThroughASymlink(t *testing.T) {
	pol, inv := policyFixture(t)
	link := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.Symlink(pol, link); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", link, "--inventory", inv, "--subject", "ops", "--write"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", info, err)
	}
	if after := readFile(t, pol); strings.Contains(string(after), "ops@example.com") {
		t.Fatalf("the target was not changed:\n%s", after)
	}
}

// A directory sync that fails after the rename leaves the file replaced, and
// the message says so: the operator must not re-run the removal thinking
// nothing happened, only make sure the change is durable.
func TestGrantsRemoveSaysTheFileWasReplacedWhenTheDirSyncFails(t *testing.T) {
	defer func(f func(string) error) { syncDir = f }(syncDir)
	syncDir = func(string) error { return os.ErrPermission }
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--write"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "was replaced, but syncing its directory failed") {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if strings.Contains(string(readFile(t, pol)), "ops@example.com") {
		t.Fatal("the file was not replaced")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// A pull request that was never fully written is not a success.
func TestGrantsRemoveFailsWhenStdoutFails(t *testing.T) {
	pol, inv := policyFixture(t)
	var errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops"}, failingWriter{}, &errb); code != 1 ||
		strings.Contains(errb.String(), "removed") {
		t.Fatalf("code %d %s", code, errb.String())
	}
}

// The offline tools load a policy as port49d does: the inventory, and every
// adapter fact from the policy file itself, so an enable-username the file
// declares refuses the load in CI exactly as it refuses port49d's start.
func TestOfflineToolsReadTheAdaptersFromThePolicyFile(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	if err := os.WriteFile(pol, append([]byte("platforms: {arista_eos: {enable_username: enab}}\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "platforms.arista_eos.enable_username") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// readFile is os.ReadFile that fails the test at the cause.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// What the gate prints besides PASS and FAIL: a lint finding as a `report:`
// line, a caveat under its test as a `note:` line, and a quarantine an expiry
// will bring on as a `quarantine:` line that says when.
func TestPolicyTestPrintsReportsNotesAndScheduledQuarantines(t *testing.T) {
	pol, inv := policyFixture(t)
	body := strings.Replace(string(readFile(t, pol)), "  - {name: admin, privilege: admin, permit: [\"**\"]}\n",
		"  - {name: admin, privilege: admin, permit: [\"**\"]}\n  - {name: op, privilege: unmapped, permit: [show **]}\n", 1)
	body = strings.Replace(body, "  - {subject: ops, scope: all_devices, roles: [admin]}\n",
		"  - {subject: ops, scope: all_devices, roles: [admin], expires: 2099-01-01}\n"+
			"  - {subject: ops, scope: all_devices, roles: [op]}\n", 1)
	body = unmappedLevel + strings.Replace(body, "subjects:\n", "subjects:\n  - {name: gone, identity: \"user:gone@example.com\", username: gone, token_ttl: 60s}\n", 1)
	body += "  - {subject: noc, device: leaf-01, command: \"show version | include x\", expect: permit}\n"
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
	for _, want := range []string{
		`report: grantless_subject: subject "gone" has no grant`,
		"     note: arista_eos applies output modifiers itself",
		"quarantine: leaf-01 (arista_eos): will be quarantined from 2099-01-01T00:00:00.000Z, when grant all_devices [admin] expires",
		"; 1 quarantined, 0 projection refusals\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
	// A quarantine, even one an expiry brings on later, fails the gate
	// (plan 5b pre-flight I10): the daemon serves the rest, CI ships none.
	if code != 1 {
		t.Fatalf("code %d", code)
	}
}

// A session test prints the level and ceiling the subject resolved to, and
// what it wanted when it fails (spec §12, "Policy tests").
func TestPolicyTestPrintsASessionTest(t *testing.T) {
	pol, inv := policyFixture(t)
	body := string(readFile(t, pol)) + "  - {subject: ops, device: leaf-01, level: admin, max_privilege: none}\n" +
		"  - {subject: noc, device: leaf-01, level: admin}\n"
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
	for _, want := range []string{
		"PASS ops on leaf-01: session -> level admin, max_privilege none, priv_lvl 15, enable none\n",
		"FAIL noc on leaf-01: session -> level readonly, max_privilege none, priv_lvl 1, enable none, want level admin\n",
		"4 tests, 1 failed",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
	if code != 1 {
		t.Fatalf("code %d", code)
	}
}

// A level raise fails `port49 policy diff` until a session test in the new
// version asserts the new level there; the lowering back is reported and
// passes (owner's ruling 2026-09-24; spec §12).
func TestPolicyDiffGatesALevelRaise(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := readFile(t, oldPol)
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	raised := strings.Replace(string(raw), "privilege: readonly", "privilege: admin", 1)
	if err := os.WriteFile(newPol, []byte(raised), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "RAISES: noc on leaf-01: level readonly -> admin, max_privilege none -> none, "+
			"priv_lvl 1 -> 15, enable none -> none, reply [\"priv-lvl=1\", \"roles=network-operator\"] -> "+
			"[\"priv-lvl=15\", \"roles=network-admin\"]; no session test asserts it: add {subject: noc, device: leaf-01, "+
			"priv_lvl: 15, level: admin, reply: [\"priv-lvl=15\", \"roles=network-admin\"]}") ||
		!strings.Contains(out.String(), "1 unacknowledged privilege raises") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", newPol, "--new", oldPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "privilege: noc on leaf-01: level admin -> readonly") {
		t.Fatalf("a lowering: code %d\n%s%s", code, out.String(), errb.String())
	}
	if err := os.WriteFile(newPol, []byte(raised+"  - {subject: noc, device: leaf-01, level: admin, priv_lvl: 15, "+
		`reply: ["priv-lvl=15", "roles=network-admin"]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "raises (a session test asserts it): noc on leaf-01: level readonly -> admin") {
		t.Fatalf("acknowledged: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A regex-constrained widening fails `port49 policy diff` until a policy test
// in the new version exercises it (owner's ruling 2026-09-24; spec §12).
func TestPolicyDiffGatesARegexConstrainedWidening(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := readFile(t, oldPol)
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	widened := strings.Replace(string(raw), "permit: [show **]}", `permit: [show **, "copy /^scp:/ *"]}`, 1)
	if err := os.WriteFile(newPol, []byte(widened), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `REGEX-CONSTRAINED: noc on leaf-01: permit "copy /^scp:/ *" (read_only) added; `+
			`the commands it matches are not enumerated (spec §12), and no policy test exercises it`) ||
		!strings.Contains(out.String(), "1 unacknowledged regex-constrained widenings") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	acked := widened + "  - {subject: noc, device: leaf-01, command: \"copy scp://h/f flash:\", expect: permit}\n"
	if err := os.WriteFile(newPol, []byte(acked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `regex-constrained (a policy test exercises it): noc on leaf-01: permit "copy /^scp:/ *"`) {
		t.Fatalf("acknowledged: code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", newPol, "--new", oldPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `regex-constrained: noc on leaf-01: permit "copy /^scp:/ *" (read_only) removed`) {
		t.Fatalf("a narrowing: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A policy with no tests passes `port49 policy test` with a report line
// saying so (owner's ruling 2026-09-24; spec §12).
func TestPolicyTestPassesAPolicyWithNoTestsAndSaysSo(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := string(readFile(t, pol))
	if err := os.WriteFile(pol, []byte(raw[:strings.Index(raw, "tests:\n")]), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "report: no_tests: ") || !strings.Contains(out.String(), "0 tests, 0 failed") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A ceiling raise says what it lets enable do (review M4).
func TestPolicyDiffSaysWhatARaisedCeilingLetsEnableDo(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := strings.Replace(string(readFile(t, oldPol)), "roles: [read_only, no_reload]}",
		"roles: [read_only, no_reload], max_privilege: readonly}", 1)
	for _, tt := range []struct{ enable, want string }{
		{"", "(enable is none, so nothing escalates to the ceiling today; setting enable later would)"},
		{", enable: token", "(enable: token can now escalate the session to the new ceiling)"},
	} {
		capped := strings.Replace(raw, `username: noc, token_ttl: 60s}`, `username: noc, token_ttl: 60s`+tt.enable+`}`, 1)
		if err := os.WriteFile(oldPol, []byte(capped), 0o600); err != nil {
			t.Fatal(err)
		}
		newPol := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(newPol, []byte(strings.Replace(capped, ", max_privilege: readonly}", "}", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
			!strings.Contains(out.String(), "max_privilege: none} "+tt.want) {
			t.Fatalf("enable %q: code %d\n%s%s", tt.enable, code, out.String(), errb.String())
		}
	}
}

// An acknowledge: entry is printed by `policy test`, and by `policy diff`
// beside the change it acknowledges (review I1; spec §12).
func TestPolicyToolsPrintAnAcknowledgment(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := strings.Replace(string(readFile(t, oldPol)), "deny: [reload **]}", `deny: ["/^(rel|wri)/ **"]}`, 1)
	if err := os.WriteFile(oldPol, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	narrowed := strings.Replace(raw, `"/^(rel|wri)/ **"`, `"/^wri/ **"`, 1)
	narrowed = strings.Replace(narrowed, `command: "reload", expect: deny`, `command: "write", expect: deny`, 1)
	if err := os.WriteFile(newPol, []byte(narrowed), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 {
		t.Fatalf("a deny test acknowledges nothing: code %d\n%s%s", code, out.String(), errb.String())
	}
	acked := narrowed + "acknowledge:\n  - {role: no_reload, rule: \"/^(rel|wri)/ **\", reason: \"reload moves to the change window\"}\n"
	if err := os.WriteFile(newPol, []byte(acked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `regex-constrained (acknowledged: reload moves to the change window): noc on leaf-01: deny "/^(rel|wri)/ **" (no_reload) removed`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	// The same entry against a diff that removes nothing is stale.
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", newPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `report: acknowledge_stale: no_reload "/^(rel|wri)/ **"`) {
		t.Fatalf("stale: code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `acknowledge: no_reload "/^(rel|wri)/ **": reload moves to the change window`) {
		t.Fatalf("policy test: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A privilege attribute added to the reply fails the diff, and the RAISES
// line names the reply: test to add (review C2).
func TestPolicyDiffGatesAPrivilegeAttributeInTheReply(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	added := strings.Replace(raw, "roles: [read_only, no_reload]}", `roles: [read_only, no_reload], attributes: {arista_eos: ["roles=network-admin"]}}`, 1)
	if err := os.WriteFile(newPol, []byte(added), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `reply ["priv-lvl=1", "roles=network-operator"] -> ["priv-lvl=1", "roles=network-admin"]; no session test asserts it: `+
			`add {subject: noc, device: leaf-01, reply: ["priv-lvl=1", "roles=network-admin"]}`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	if err := os.WriteFile(newPol, []byte(added+`  - {subject: noc, device: leaf-01, reply: ["priv-lvl=1", "roles=network-admin"]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 {
		t.Fatalf("acknowledged: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// An identity handed to another person fails the diff until a session test
// names the new principal (review C3).
func TestPolicyDiffGatesAPrincipalWhoGainsASubject(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	swapped := strings.Replace(raw, "user:ops@example.com", "user:mallory@example.com", 1)
	if err := os.WriteFile(newPol, []byte(swapped), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "PRINCIPAL: user:mallory@example.com now resolves to subject ops (was none): that person now holds ops's access") ||
		!strings.Contains(out.String(), "principal: user:ops@example.com no longer resolves to a subject (was ops)") ||
		!strings.Contains(out.String(), "1 unacknowledged principal or username changes") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	acked := swapped + `  - {principal: "user:mallory@example.com", device: leaf-01, level: admin}` + "\n"
	if err := os.WriteFile(newPol, []byte(acked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 {
		t.Fatalf("acknowledged: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A broker right gained fails the diff until a test asserts the subject's
// rights with api: (review M6).
func TestPolicyDiffGatesABrokerRightGained(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	rights := strings.Replace(raw, "username: noc, token_ttl: 60s}", "username: noc, token_ttl: 60s, api: [revoke_others]}", 1)
	if err := os.WriteFile(newPol, []byte(rights), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `API: subject noc's broker rights [] -> ["revoke_others"]`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	if err := os.WriteFile(newPol, []byte(rights+"  - {subject: noc, device: leaf-01, api: [revoke_others]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 {
		t.Fatalf("acknowledged: code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", newPol, "--new", oldPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `api: subject noc's broker rights ["revoke_others"] -> []`) {
		t.Fatalf("a right lost: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// An edit to a key of an adapter the gate reads fails `port49 policy diff`
// until an acknowledge: entry names the platform and the key, and `policy
// test` prints the entry beside the others (review M8; spec §12).
func TestPolicyDiffGatesAnAdapterEdit(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	edited := "platforms: {arista_eos: {entity_classes: {management: ['^Management1$']}}}\n" + raw
	if err := os.WriteFile(newPol, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `ADAPTER: platforms.arista_eos.entity_classes {"loopback":`) ||
		!strings.Contains(out.String(), "; 1 unacknowledged adapter edits; 0 projection refusals; 0 devices newly refused admission\n") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	// The entry is printed ready to paste, bound by digest to this edit.
	entry := regexp.MustCompile(`add (\{platform: arista_eos, field: entity_classes, sha256: [0-9a-f]{64}, reason: )"\.\.\."\}` +
		` under acknowledge:`).FindStringSubmatch(out.String())
	if entry == nil {
		t.Fatalf("no paste-ready entry\n%s", out.String())
	}
	acked := edited + "acknowledge:\n  - " + entry[1] + "only Management1 is out of band}\n"
	if err := os.WriteFile(newPol, []byte(acked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "adapter (acknowledged: only Management1 is out of band): platforms.arista_eos.entity_classes") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "acknowledge: platforms.arista_eos.entity_classes: only Management1 is out of band\n") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A policy's rules and its tests' commands are printed by `policy test`,
// `policy diff` and `explain`, whose output lands in CI logs: a value the
// redaction patterns hide reads «redacted» there as everywhere else (spec
// §5.8; task 11 review I1). A load error that quotes the rule is redacted
// too.
func TestThePolicyToolsNeverPrintARuleSecret(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	withDeny := strings.Replace(raw, "deny: [reload **]}", `deny: [reload **, "snmp-server community Hunter2 **"]}`, 1)
	if err := os.WriteFile(oldPol, []byte(withDeny), 0o600); err != nil {
		t.Fatal(err)
	}
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	shadowed := strings.Replace(withDeny, "permit: [show **]}", `permit: [show **, "snmp-server community Hunter2 ro"]}`, 1)
	if err := os.WriteFile(newPol, []byte(shadowed), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(what string, args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		run(args, &out, &errb)
		if strings.Contains(out.String()+errb.String(), "Hunter2") {
			t.Fatalf("%s printed the secret:\n%s%s", what, out.String(), errb.String())
		}
		return out.String()
	}
	if out := check("policy test", "policy", "test", "--policy", newPol, "--inventory", inv); !strings.Contains(out,
		`shadowed: "snmp-server community «redacted» **" (no_reload)`) {
		t.Fatalf("policy test: %s", out)
	}
	if out := check("policy diff", "policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv); !strings.Contains(
		out, "EXPANDS: noc on leaf-01") {
		t.Fatalf("policy diff: %s", out)
	}
	if out := check("explain", "explain", "--policy", newPol, "--inventory", inv, "--subject", "noc", "--device",
		"leaf-01", "--command", "snmp-server community Hunter2 ro"); !strings.Contains(out, "snmp-server community «redacted»") {
		t.Fatalf("explain: %s", out)
	}
	broken := strings.Replace(withDeny, `"snmp-server community Hunter2 **"`, `"snmp-server community Hunter2 /^rw$/"`, 1)
	if err := os.WriteFile(oldPol, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	check("a load error", "policy", "test", "--policy", oldPol, "--inventory", inv)
	check("a load error", "explain", "--policy", oldPol, "--inventory", inv, "--subject", "noc", "--device", "leaf-01")
	check("a load error", "policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv)
}

// policy diff's adapter lines print a block's values as JSON, which lands in
// CI logs: a config check's match, a class pattern and every other block
// text print redacted as platform show prints them, and the digest an
// acknowledgment binds is still taken over the value as written (final review
// I3).
func TestPolicyDiffAdapterLinesNeverPrintABlockSecret(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	block := "platforms:\n  arista_eos:\n" +
		"    config_checks:\n      - {match: '^snmp-server community Hunter2a', says: a check}\n" +
		"    entity_classes: {secret_pattern: ['^snmp-server community Hunter2b$'], bad_comm: ['^Hunter2c$']}\n" +
		"    unreachable: {readonly: [\"snmp-server community Hunter2d **\"]}\n" +
		"    fallback: {readonly: \"a local user, password Hunter2e\"}\n"
	withClass := strings.Replace(raw, "roles:\n", "roles:\n  - {name: snmp, deny: [snmp-server community @bad_comm **]}\n", 1)
	if err := os.WriteFile(newPol, []byte(block+withClass), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "ADAPTER: platforms.arista_eos.config_checks") ||
		!strings.Contains(out.String(), "ADAPTER: platforms.arista_eos.entity_classes") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	for _, probe := range []string{"Hunter2a", "Hunter2b", "Hunter2c", "Hunter2d", "Hunter2e"} {
		if strings.Contains(out.String()+errb.String(), probe) {
			t.Errorf("policy diff prints %s:\n%s%s", probe, out.String(), errb.String())
		}
	}
	// A set's own check prints as written, and the entry binds the value as
	// written: acknowledged with it, the diff passes.
	if !strings.Contains(out.String(), `\\b(local|enable)\\s*$`) {
		t.Errorf("a shipped match is printed as written:\n%s", out.String())
	}
	var acks []string
	for _, m := range regexp.MustCompile(`add (\{platform: arista_eos, field: \w+, sha256: [0-9a-f]{64}, reason: )"\.\.\."\}`).
		FindAllStringSubmatch(out.String(), -1) {
		acks = append(acks, "  - "+m[1]+"a test}")
	}
	acked := block + withClass + "acknowledge:\n" + strings.Join(acks, "\n") + "\n"
	if err := os.WriteFile(newPol, []byte(acked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 {
		t.Fatalf("acknowledged: code %d\n%s%s", code, out.String(), errb.String())
	}
}

// Moving a subject from admin to readonly lowers it on every per-command
// platform, end to end through the command: the reply's role goes down
// role_order on EOS and NX-OS and priv-lvl goes down on IOS-XE, so the diff
// passes; the reverse is gated on each (task 3 review, carried to the final
// wave).
func TestPolicyDiffPassesAnAdminToReadonlyMoveOnEveryPlatform(t *testing.T) {
	oldPol, inv := policyFixture(t)
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}
  - {name: nx-01, platform: cisco_nxos, addresses: [10.0.0.2]}
  - {name: xe-01, platform: cisco_iosxe, addresses: [10.0.0.3]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := string(readFile(t, oldPol))
	lowered := strings.Replace(raw, "roles: [admin]}", "roles: [read_only]}", 1)
	if lowered == raw {
		t.Fatal("the fixture's ops grant moved")
	}
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(newPol, []byte(lowered), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 {
		t.Fatalf("admin -> readonly: code %d\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "privilege: ops on ") {
		t.Fatalf("the lowering is not reported:\n%s", out.String())
	}
	for _, device := range []string{"leaf-01", "nx-01", "xe-01"} {
		if !strings.Contains(out.String(), device) {
			t.Errorf("%s: the lowering is not reported:\n%s", device, out.String())
		}
	}
	out.Reset()
	if code := run([]string{"policy", "diff", "--old", newPol, "--new", oldPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "RAISES: ops on ") {
		t.Fatalf("readonly -> admin: code %d\n%s%s", code, out.String(), errb.String())
	}
	for _, device := range []string{"leaf-01", "nx-01", "xe-01"} {
		if !strings.Contains(out.String(), device) {
			t.Errorf("%s: the raise is not reported:\n%s", device, out.String())
		}
	}
}

// A finding that derives text from a rule, not only quotes it, still prints
// no secret: permit_joined_name names the joined word and the fix, and the
// word here is the secret. The writer redacts every value the policy's rules
// hide wherever it appears in a line, not only inside a quoted rule (task 11
// review, pre-existing leak from f426892).
func TestPolicyTestNeverPrintsASecretAJoinedNameFindingDerives(t *testing.T) {
	pol, inv := policyFixture(t)
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}
  - {name: xe-01, platform: cisco_iosxe, addresses: [10.0.0.3]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := string(readFile(t, pol))
	// A second rule names the value re-cased and with no secret keyword
	// before it, and a test types it on IOS-XE, which splits it: no text
	// derived from the value, joined, split or re-cased, prints (re-review
	// R1).
	withSecret := strings.Replace(raw, "permit: [show **]}",
		`permit: [show **, "show system radius-server 10.0.0.1 secret HUNTER2", "show interfaces Gi1", `+
			`"show running-config HunTer2"]}`, 1)
	if withSecret == raw {
		t.Fatal("the fixture's permit moved")
	}
	withSecret += "  - {subject: noc, device: xe-01, command: \"show system radius-server 10.0.0.1 secret HunTer2\", " +
		"expect: deny}\n"
	if err := os.WriteFile(pol, []byte(withSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
	got := out.String() + errb.String()
	if strings.Contains(strings.ToUpper(got), "HUNTER") {
		t.Fatalf("policy test printed the secret:\n%s", got)
	}
	// The finding still fires for a joined name that is no secret.
	if !strings.Contains(got, "`Gi1` never matches on cisco_iosxe") {
		t.Fatalf("the joined-name finding is gone:\n%s", got)
	}
	// explain types a value the policy never wrote: the line's own
	// redaction hides it, and the split note is left out with it.
	out.Reset()
	errb.Reset()
	run([]string{"explain", "--policy", pol, "--inventory", inv, "--subject", "noc", "--device", "xe-01",
		"--command", "show system radius-server 10.0.0.1 secret SEKRIT9"}, &out, &errb)
	if got := strings.ToUpper(out.String() + errb.String()); strings.Contains(got, "SEKRIT") ||
		!strings.Contains(got, "SECRET «REDACTED»") {
		t.Fatalf("explain printed the secret:\n%s%s", out.String(), errb.String())
	}
	// A value with a `"` or `\` in it, which %q escapes past the writer's
	// pass, in any letter case: a finding quoting a rule that carries it and
	// a test line typing it print it redacted (task 12b review I1).
	for _, c := range []struct{ hides, typed, test string }{
		{`PA"sS9`, `pa"ss9`, `Pa"Ss9`}, {`A\B9`, `a\b9`, `a\B9`}, {`Mi"X\d9`, `mI"x\D9`, `MI"x\d9`},
	} {
		with := strings.Replace(raw, "permit: [show **]}", `permit: [show **, 'show system radius-server 10.0.0.1 `+
			`secret `+c.hides+`', 'show interfaces Gi1 `+c.typed+`']}`, 1) + "  - {subject: noc, device: xe-01, " +
			"command: 'show running-config " + c.test + "', expect: permit}\n"
		if err := os.WriteFile(pol, []byte(with), 0o600); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errb.Reset()
		run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
		got := out.String() + errb.String()
		low, escaped := strings.ToLower(got), strings.ToLower(strings.Trim(strconv.Quote(c.hides), `"`))
		if strings.Contains(low, strings.ToLower(c.hides)) || strings.Contains(low, escaped) ||
			!strings.Contains(got, "`Gi1` never matches on cisco_iosxe") || !strings.Contains(got, "show running-config «redacted»") {
			t.Errorf("%s: policy test printed the secret:\n%s", c.typed, got)
		}
	}
}

// policy diff prints each probe command whose verdict moved, and on IOS-XE a
// probe splits a deny's joined word into the name and index it may be sent
// as: made from a value redaction hides, each piece prints «redacted», and
// the narrowing is still reported (task 11 re-review 2, R5).
func TestPolicyDiffNeverPrintsAPieceOfASecretAProbeSplits(t *testing.T) {
	oldPol, inv := policyFixture(t)
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: xe-01, platform: cisco_iosxe, addresses: [10.0.0.3]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := string(readFile(t, oldPol))
	before := strings.Replace(raw, "permit: [show **]}", `permit: [show **, "username **"]}`, 1)
	before = strings.Replace(before, "deny: [reload **]}", `deny: [reload **, "snmp-server community Kilo7 **"]}`, 1)
	if !strings.Contains(before, "Kilo7") || !strings.Contains(before, "username **") {
		t.Fatal("the fixture's roles moved")
	}
	before = before[:strings.Index(before, "tests:\n")]
	after := strings.Replace(before, `, "username **"`, "", 1)
	newPol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(oldPol, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPol, []byte(after), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb)
	got := out.String() + errb.String()
	if strings.Contains(strings.ToUpper(got), "KILO") || !strings.Contains(got, "narrows: noc on xe-01: \"username") ||
		!strings.Contains(got, "«redacted»") {
		t.Fatalf("policy diff:\n%s", got)
	}
}

// A probe tries a witness of each class and regex term, whole and split,
// under every command head that reaches its position: made from a term
// whose values redaction hides, a secret entity class or a secret regex,
// each prints «redacted», and the narrowing is still reported (task 11
// re-review 3, R6).
func TestPolicyDiffNeverPrintsAWitnessOfASecretClassOrRegex(t *testing.T) {
	for name, c := range map[string]struct{ block, deny string }{
		"entity class": {"platforms: {cisco_iosxe: {entity_classes: {bad_comm: ['^Mango55$', '^Papaya$']}}}\n",
			`"snmp-server community @bad_comm **"`},
		"regex": {"", `"snmp-server community /^Mango5[5-6]$/ **"`},
	} {
		oldPol, inv := policyFixture(t)
		if err := os.WriteFile(inv, []byte(`
devices:
  - {name: xe-01, platform: cisco_iosxe, addresses: [10.0.0.3]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
			t.Fatal(err)
		}
		raw := string(readFile(t, oldPol))
		before := strings.Replace(raw, "permit: [show **]}", `permit: [show **, "username **"]}`, 1)
		before = strings.Replace(before, "deny: [reload **]}", "deny: [reload **, "+c.deny+"]}", 1)
		before = c.block + before[:strings.Index(before, "tests:\n")]
		after := strings.Replace(before, `, "username **"`, "", 1)
		newPol := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(oldPol, []byte(before), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(newPol, []byte(after), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb)
		got := out.String() + errb.String()
		if u := strings.ToUpper(got); strings.Contains(u, "MANGO") || strings.Contains(u, "PAPAYA") ||
			!strings.Contains(got, "narrows: noc on xe-01: \"username community") {
			t.Fatalf("%s: policy diff:\n%s", name, got)
		}
	}
}

// policy diff prints a projection whose shape or bits moved (spec §8, §12).
func TestPolicyDiffPrintsAProjectionChange(t *testing.T) {
	if got := projectionText("", nil, ""); got != "none" {
		t.Errorf("%q", got)
	}
	if got := projectionText("capability", []string{"view"}, ""); got != "capability (bits view)" {
		t.Errorf("%q", got)
	}
	if got := projectionText("narrow", []string{"view", "view-configuration"}, "p49-readonly"); got !=
		"narrow (template p49-readonly, bits view view-configuration)" {
		t.Errorf("%q", got)
	}
}

// I7: every tool loads the bundle port49d loads for the same two files: diff
// loads, and explain refuses a device only the inventory's key groups decide.
func TestToolsLoadTheBundleAsPort49dDoes(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(pol, []byte("scopes: [{name: all_devices, match: {}}]\n"+
		"roles: [{name: r, privilege: readonly, permit: [show **]}]\n"+
		"subjects: [{name: s, identity: [\"user:alice@example.com\"], username: alice, token_ttl: 60s}]\n"+
		"grants: [{subject: s, scope: all_devices, roles: [r]}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte("devices: [{name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]},\n"+
		"  {name: lab-01, platform: arista_eos, addresses: [192.168.0.1]}]\n"+
		"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", pol, "--new", pol, "--inventory", inv}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	// explain reads the inventory's key groups as port49d does, so a device
	// none of them admits is refused, not minted for.
	out.Reset()
	if code := run([]string{"explain", "--policy", pol, "--inventory", inv, "--subject", "s", "--device", "lab-01",
		"--command", "show version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "deny device_unknown") {
		t.Fatalf("lab-01, which no key group admits: exit %d: %s%s", code, out.String(), errOut.String())
	}
	p, err := bundle.Load(pol, inv, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("the inventory's key groups were not read: %+v", r)
	}
	if !strings.HasPrefix(p.Bundle, "sha256:") || p.Bundle == p.Source {
		t.Fatalf("bundle %s source %s", p.Bundle, p.Source)
	}
}

// policy diff says which side's inventory failed, and names the inventory
// file, not a policy file, as the fault.
func TestPolicyDiffNamesTheInventoryForAnInventoryFault(t *testing.T) {
	pol, inv := policyFixture(t)
	if err := os.WriteFile(inv, []byte("devices: [{name: a, platform: arista_eos, addresses: [10.0.0.1]},\n"+
		"  {name: b, platform: arista_eos, addresses: [10.0.0.1]}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "diff", "--old", pol, "--new", pol, "--inventory", inv}, &out, &errOut)
	if code != 1 || !strings.HasPrefix(errOut.String(), "port49 policy diff: --old inventory "+inv+": ") ||
		strings.Contains(errOut.String(), "policy: "+pol) {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}

// grants remove and platform upgrade name the inventory file for its fault,
// never the policy or its platform set (Task 6 review I1).
func TestToolsNameTheInventoryFileOnItsFault(t *testing.T) {
	for _, args := range [][]string{
		{"grants", "remove", "--subject", "noc"},
		{"platform", "upgrade", "--to", "1.0.0"},
	} {
		pol, inv := policyFixture(t)
		if err := os.WriteFile(inv, []byte("devices: [{name: a, platform: arista_eos, addresses: [10.0.0.1]},\n"+
			"  {name: b, platform: arista_eos, addresses: [10.0.0.1]}]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := readFile(t, pol)
		var out, errOut bytes.Buffer
		code := run(append(args, "--policy", pol, "--inventory", inv, "--write"), &out, &errOut)
		want := "port49 " + args[0] + " " + args[1] + ": inventory_file " + inv + ": "
		if code != 1 || !strings.HasPrefix(errOut.String(), want) || strings.Contains(errOut.String(), "does not load") ||
			strings.Contains(errOut.String(), "platform_set") {
			t.Errorf("%s: exit %d: %s", args[1], code, errOut.String())
		}
		if string(readFile(t, pol)) != string(before) {
			t.Errorf("%s wrote the policy", args[1])
		}
	}
}

// Spec §10, §12: CI fails on every device admission refuses — a key-group tie
// (owner decision 1), a device no group admits, and, given port49d.yaml, one
// assigned a key_ref it does not define — since port49d serves none of them;
// retire_after problems are reported.
func TestPolicyTestJudgesAdmissionAndKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := strings.Replace(keysPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]",
		"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}, {match: {attributes: {site: lab}}, key_ref: lab_key}]", 1)
	inv := write("inventory.yaml", `devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.20.0.7]}
  - {name: stray, platform: arista_eos, addresses: [192.0.2.9]}
`)
	var out, errOut bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", write("p.yaml", base), "--inventory", inv}, &out, &errOut); code != 1 {
		t.Fatalf("a device in no group passed the gate: exit %d\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "admission: stray (arista_eos) refused: matches no key group") {
		t.Fatalf("%s", out.String())
	}
	out.Reset()
	cfg := write("port49d.yaml", keysConfig)
	code := run([]string{"policy", "test", "--policy", write("p.yaml", base), "--inventory", inv, "--config", cfg}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "keys: key group attributes {site: lab} → lab_key names key_ref lab_key") {
		t.Fatalf("an undefined key_ref: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "report: key prod_key version 2: retire_after 2026-10-01") &&
		!strings.Contains(out.String(), "report: key prod_key version 2 retires after 2026-10-01") {
		t.Fatalf("the date is not reported: %s", out.String())
	}
}

// I3: a test on a device the inventory no longer has fails CI, where the
// load that port49d would make succeeds.
func TestPolicyTestFailsATestOnAnAbsentDevice(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.yaml")
	inv := filepath.Join(dir, "i.yaml")
	body := keysPolicy + "tests: [{subject: s, device: leaf-gone, command: \"show version\", expect: permit}]\n"
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte(keysInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String()+errOut.String(), `device "leaf-gone" is not in the inventory`) {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
}

func TestPolicyDiffFailsOnADeviceTheNewPolicyRefuses(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := write("old.yaml", keysPolicy)
	typo := write("new.yaml", strings.Replace(keysPolicy, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	inv := write("inventory.yaml", keysInventory)
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "diff", "--old", old, "--new", typo, "--inventory", inv}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "REFUSED: admission: leaf-01 (arista_eos) is newly refused") {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
}

// A tie and a device assigned a key_ref port49d.yaml does not define each
// fail the gate by name; nothing from port49d.yaml's secret side is printed.
func TestPolicyTestFailsATieAndAnUndefinedKeyByDevice(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pol := write("p.yaml", strings.Replace(keysPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]",
		"key_groups: [{match: {attributes: {site: campus}}, key_ref: prod_key}, "+
			"{match: {attributes: {role: leaf}}, key_ref: prod_key}, {match: {cidr: 192.0.2.0/24}, key_ref: lab_key}]", 1))
	inv := write("inventory.yaml", `devices:
  - {name: leaf-19, platform: arista_eos, addresses: [10.20.4.9], attributes: {site: campus, role: leaf}}
  - {name: lab-01, platform: arista_eos, addresses: [192.0.2.9]}
  - {name: spine-01, platform: arista_eos, addresses: [10.30.0.1], attributes: {site: campus}}
`)
	cfg := write("port49d.yaml", keysConfig)
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv, "--config", cfg}, &out, &errOut)
	got := out.String() + errOut.String()
	if code != 1 {
		t.Fatalf("exit %d:\n%s", code, got)
	}
	for _, want := range []string{
		"admission: leaf-19 (arista_eos) refused: ",
		"attributes {site: campus} → prod_key",
		"attributes {role: leaf} → prod_key",
		"admission: lab-01 (arista_eos) refused: ",
		"keys: key group cidr 192.0.2.0/24 → lab_key names key_ref lab_key",
		"2 admission refusal(s), 1 key fault(s)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "spine-01") || strings.Contains(got, "NEVER_READ") {
		t.Errorf("an admitted device or a secret_env is printed:\n%s", got)
	}
}

// M3: a port49d.yaml with no keys defines none, so every key group's
// key_ref is undefined and the gate fails, rather than having nothing to check.
func TestPolicyTestReadsAnEmptyKeysBlockAsUndefined(t *testing.T) {
	pol, inv, _, _ := keysFiles(t)
	cfg := filepath.Join(t.TempDir(), "port49d.yaml")
	if err := os.WriteFile(cfg, []byte("keys: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv, "--config", cfg}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "keys: key group cidr 10.0.0.0/8 → prod_key names key_ref prod_key") ||
		!strings.Contains(out.String(), "admission: leaf-01 (arista_eos) refused: ") {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
}
