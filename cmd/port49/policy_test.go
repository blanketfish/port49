package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
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
		`{name: read_only, privilege: readonly, permit: [show **], attributes: {all: ["home-directory*/`+strings.Repeat("h", 227)+`/{principal}"]}}`, 1)
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
	if e := offlineEnv(nil); e.Dialects != nil || !e.Now.IsZero() {
		t.Fatalf("%+v", e)
	}
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
	run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
	for _, want := range []string{
		`report: grantless_subject: subject "gone" has no grant`,
		"     note: arista_eos applies output modifiers itself",
		"quarantine: leaf-01 (arista_eos): will be quarantined from 2099-01-01T00:00:00.000Z, when grant all_devices [admin] expires",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
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
		!strings.Contains(out.String(), "; 1 unacknowledged adapter edits\n") {
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
