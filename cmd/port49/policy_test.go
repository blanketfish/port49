package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// unmappedLevel declares a level no built-in platform renders: a role landing
// an arista_eos session there quarantines the device. `operator` renders on
// EOS since the owner's ruling of 2026-09-24 (spec §6, decision 23).
const unmappedLevel = "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"

// policyFixture writes a small policy and inventory and returns their paths.
// fixtureKeys is the keys: block of the fixtures whose inventories assign k.
const fixtureKeys = "keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_FIXTURE}\n"

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
`+fixtureKeys+`tests:
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

// A per_login_mfa weakening fails `port49 policy diff` until a session test in
// the new version asserts the new requirement, as a privilege raise does; a
// tightening only prints (decision 45 ruling 24; spec §12). The exit code and
// the printing live here, not in internal/policy.
func TestPolicyDiffGatesAPerLoginMFAWeakening(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	strict := "defaults:\n  per_login_mfa: {accept: [hardware_key_touch]}\n" + raw
	weak := "defaults:\n  per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}\n" + raw
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	strictPol, weakPol := write("strict.yaml", strict), write("weak.yaml", weak)
	diff := func(old, new string) (int, string) {
		var out, errb bytes.Buffer
		code := run([]string{"policy", "diff", "--old", old, "--new", new, "--inventory", inv}, &out, &errb)
		return code, out.String() + errb.String()
	}
	code, out := diff(strictPol, weakPol)
	if code != 1 ||
		!strings.Contains(out, "per_login_mfa_weakened: noc on leaf-01: accept [hardware_key_touch] reuse_for 15m (defaults) -> "+
			"accept [hardware_key_touch, idp_mfa] reuse_for 15m (defaults); no session test asserts it: add {subject: noc, "+
			"device: leaf-01, per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 15m}}") ||
		!strings.Contains(out, "2 unacknowledged per_login_mfa weakenings") {
		t.Fatalf("unacknowledged: code %d\n%s", code, out)
	}
	// A test asserting the new requirement, for each subject, acknowledges it.
	test := func(subject string) string {
		return "  - {subject: " + subject + ", device: leaf-01, per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 15m}}\n"
	}
	ackedPol := write("acked.yaml", weak+test("noc")+test("ops"))
	if code, out := diff(strictPol, ackedPol); code != 0 ||
		!strings.Contains(out, "per_login_mfa: noc on leaf-01") || !strings.Contains(out, "a session test asserts it") ||
		!strings.Contains(out, "0 unacknowledged per_login_mfa weakenings") {
		t.Fatalf("acknowledged: code %d\n%s", code, out)
	}
	// One subject acknowledged leaves the other failing.
	if code, out := diff(strictPol, write("half.yaml", weak+test("noc"))); code != 1 ||
		!strings.Contains(out, "1 unacknowledged per_login_mfa weakenings") {
		t.Fatalf("half acknowledged: code %d\n%s", code, out)
	}
	// The way back is a tightening: printed, never failing.
	if code, out := diff(weakPol, strictPol); code != 0 ||
		!strings.Contains(out, "per_login_mfa: noc on leaf-01: accept [hardware_key_touch, idp_mfa] reuse_for 15m (defaults) -> "+
			"accept [hardware_key_touch] reuse_for 15m (defaults)") || strings.Contains(out, "per_login_mfa_weakened") {
		t.Fatalf("a tightening: code %d\n%s", code, out)
	}
}

// Levels that accept no common method quarantine the device: `policy test`
// fails on it naming both levels and the device, `policy diff` on an entry the
// new version introduces, and not on one both versions hold (decision 45
// ruling 11; re-review R5).
func TestPolicyToolsFailADisjointPerLoginMFA(t *testing.T) {
	oldPol, inv := policyFixture(t)
	raw := string(readFile(t, oldPol))
	ok := strings.Replace(raw, "{name: read_only, privilege: readonly, permit: [show **]}",
		"{name: read_only, privilege: readonly, permit: [show **], per_login_mfa: {accept: [idp_mfa]}}", 1)
	disjoint := strings.Replace(ok, "scopes: [{name: all_devices, match: {}}]",
		"scopes:\n  - {name: all_devices, match: {}}\n  - {name: leaf, match: {name: leaf-01}, per_login_mfa: {accept: [hardware_key_touch]}}", 1)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	okPol, disjointPol := write("ok.yaml", ok), write("disjoint.yaml", disjoint)
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", disjointPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "quarantine: leaf-01") || !strings.Contains(out.String(), "role read_only") ||
		!strings.Contains(out.String(), "scope leaf") {
		t.Fatalf("policy test: code %d\n%s%s", code, out.String(), errb.String())
	}
	diff := func(old, new string) (int, string) {
		var out, errb bytes.Buffer
		code := run([]string{"policy", "diff", "--old", old, "--new", new, "--inventory", inv}, &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, got := diff(okPol, disjointPol); code != 1 || !strings.Contains(got, "QUARANTINES: leaf-01") ||
		!strings.Contains(got, "scope leaf") {
		t.Fatalf("an introduced entry: code %d\n%s", code, got)
	}
	// Both sides hold it: an edit that changes nothing about it passes.
	if code, got := diff(disjointPol, write("disjoint2.yaml", disjoint+"# reviewed\n")); code != 0 ||
		strings.Contains(got, "QUARANTINES") {
		t.Fatalf("an entry both versions hold: code %d\n%s", code, got)
	}
}

// The access review shows where a requirement is written, in a column that
// appears only when some row has one.
func TestAccessReviewShowsThePerLoginMFALevels(t *testing.T) {
	pol, inv := policyFixture(t)
	review := func() string {
		var out, errb bytes.Buffer
		if code := run([]string{"access", "review", "--policy", pol, "--inventory", inv, "--subject", "noc"}, &out,
			&errb); code != 0 {
			t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
		}
		return out.String()
	}
	if got := review(); strings.Contains(got, "PER_LOGIN_MFA") {
		t.Fatalf("a policy with no requirement has the column:\n%s", got)
	}
	raw := string(readFile(t, pol))
	with := strings.Replace(raw, "{name: read_only, privilege: readonly, permit: [show **]}",
		"{name: read_only, privilege: readonly, permit: [show **], per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}}", 1)
	if err := os.WriteFile(pol, []byte(with), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := review(); !strings.Contains(got, "PER_LOGIN_MFA") || !strings.Contains(got, "role read_only [hardware_key_touch idp_mfa]") {
		t.Fatalf("the column is missing or does not name the level:\n%s", got)
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
	code := run([]string{"policy", "test", "--policy", write("p.yaml", base), "--inventory", inv}, &out, &errOut)
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

// A key_groups edit that refuses a fleet names the first 20 devices and
// counts the rest, so the cause is not buried; the exit still fails (Task 17
// review).
func TestPolicyDiffCapsTheNewlyRefusedLines(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var inv strings.Builder
	inv.WriteString("devices:\n")
	for i := range 25 {
		fmt.Fprintf(&inv, "  - {name: leaf-%02d, platform: arista_eos, addresses: [10.20.0.%d]}\n", i, i+1)
	}
	old := write("old.yaml", keysPolicy)
	typo := write("new.yaml", strings.Replace(keysPolicy, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "diff", "--old", old, "--new", typo, "--inventory", write("inventory.yaml",
		inv.String())}, &out, &errOut)
	if code != 1 || strings.Count(out.String(), "is newly refused: ") != 20 ||
		!strings.Contains(out.String(), "REFUSED: admission: and 5 more devices newly refused\n") {
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
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errOut)
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
		t.Errorf("an admitted device or a secret_ref is printed:\n%s", got)
	}
}

// M3: a policy whose keys: block is empty defines no key, so every key
// group's key_ref is undefined and the gate fails, rather than having nothing
// to check.
func TestPolicyTestReadsAnEmptyKeysBlockAsUndefined(t *testing.T) {
	_, inv, _ := keysFiles(t)
	pol := filepath.Join(t.TempDir(), "policy-nokeys.yaml")
	if err := os.WriteFile(pol, []byte(strings.Replace(keysPolicy, keysBlock, "keys: {}\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "keys: key group cidr 10.0.0.0/8 → prod_key names key_ref prod_key") ||
		!strings.Contains(out.String(), "admission: leaf-01 (arista_eos) refused: ") {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
}

// I1: port49d always assesses admission, so a bundle with no key_groups in
// either file admits only pinned devices, and none here: its start and every
// reload refuse it. `policy test` fails it, and
// `policy diff` fails the edit that deletes the block, naming each device.
func TestCIFailsWhenTheKeyGroupsBlockIsRemoved(t *testing.T) {
	pol, inv, _ := keysFiles(t)
	gone := filepath.Join(t.TempDir(), "nogroups.yaml")
	body := strings.Replace(keysPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n", "", 1)
	if body == keysPolicy {
		t.Fatal("the fixture kept its key_groups")
	}
	if err := os.WriteFile(gone, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	{
		var out, errOut bytes.Buffer
		args := []string{"policy", "test", "--policy", gone, "--inventory", inv}
		code := run(args, &out, &errOut)
		got := out.String() + errOut.String()
		if code != 1 || !strings.Contains(got, "admission: neither the policy nor the inventory declares key_groups") ||
			!strings.Contains(got, "port49d admits none of the 2 device(s)") ||
			!strings.Contains(got, "admission: leaf-19 (arista_eos) refused: matches no key group") {
			t.Fatalf("exit %d:\n%s", code, got)
		}
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "diff", "--old", pol, "--new", gone, "--inventory", inv}, &out, &errOut)
	got := out.String() + errOut.String()
	if code != 1 || !strings.Contains(got, "REFUSED: admission: the key_groups block was removed") ||
		!strings.Contains(got, "REFUSED: admission: leaf-01 (arista_eos) is newly refused") ||
		!strings.Contains(got, "REFUSED: admission: leaf-19 (arista_eos) is newly refused") ||
		!strings.Contains(got, "; 2 devices newly refused admission") {
		t.Fatalf("diff: exit %d:\n%s", code, got)
	}
}

// A device pinned to a key_ref on its inventory record is admitted with no
// key group, as port49d admits it; the gate fails only the unpinned.
func TestPolicyTestWithNoKeyGroupsFailsOnlyTheUnpinned(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.yaml")
	inv := filepath.Join(dir, "i.yaml")
	body := strings.Replace(keysPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n", "", 1)
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte(`devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.20.0.7], key_ref: prod_key}
  - {name: leaf-19, platform: arista_eos, addresses: [10.20.4.9]}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errOut)
	got := out.String()
	if code != 1 || !strings.Contains(got, "admission: leaf-19 (arista_eos) refused: matches no key group") ||
		strings.Contains(got, "leaf-01") || strings.Contains(got, "admits none") {
		t.Fatalf("exit %d:\n%s%s", code, got, errOut.String())
	}
}

// An inventory with no devices has no admission to judge: port49d's own
// admit-none check passes an empty inventory, so the gate says nothing.
func TestPolicyTestOnAnEmptyInventorySaysNothingOfAdmission(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.yaml")
	inv := filepath.Join(dir, "i.yaml")
	body := strings.Replace(keysPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n", "", 1)
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errOut)
	if strings.Contains(out.String()+errOut.String(), "admission") {
		t.Fatalf("%s%s", out.String(), errOut.String())
	}
}

func TestPolicyReplayTakesBothFilesOrNeither(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"policy", "replay", "--policy", "p.yaml", "-"}, &out, &errOut); code != 2 {
		t.Fatalf("one file exits %d", code)
	}
	if code := run([]string{"policy", "replay", "--inventory", "i.yaml", "-"}, &out, &errOut); code != 2 ||
		!strings.Contains(errOut.String(), "port49 policy replay [--line N] [--policy FILE --inventory FILE] LOGFILE|-") {
		t.Fatalf("the other file exits %d\n%s", code, errOut.String())
	}
}

// A log whose blob event was redacted replays from the policy and inventory
// files: its records agree, where without them they are unverifiable, and
// nothing replay prints carries the value the log redacted, even for a
// record edited to drop its redacted mark, which diverges.
func TestPolicyReplayVerifiesARedactedBlobFromTheFiles(t *testing.T) {
	const secret = "Xk9vQ7pLm2Zr"
	pol, inv := policyFixture(t)
	raw, err := os.ReadFile(pol)
	if err != nil {
		t.Fatal(err)
	}
	withSecret := strings.Replace(string(raw), `permit: ["**"]}`,
		`permit: ["**"], deny: ["snmp-server community /^(public)?(`+secret+`)?$/ **"]}`, 1)
	if withSecret == string(raw) {
		t.Fatal("the fixture's admin role was not found to edit")
	}
	if err := os.WriteFile(pol, []byte(withSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := bundle.Load(pol, inv, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	d, ok := p.Device("leaf-01")
	if !ok {
		t.Fatal("no leaf-01")
	}
	compiled := time.Now().UTC().Truncate(time.Second)
	res, err := p.Resolve("user:ops@example.com", d, compiled)
	if err != nil {
		t.Fatal(err)
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), secret) {
		t.Fatal("the fixture's blob does not carry the secret")
	}
	blob, err := engine.Decode(hash, body)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := engine.Compile(blob)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := blob.SessionAttributes(engine.Values{Principal: "user:ops@example.com", Username: "ops",
		Device: "leaf-01"})
	if err != nil {
		t.Fatal(err)
	}
	shown := strings.ReplaceAll(string(body), "/^(public)?("+secret+")?$/", platform.Redacted)
	device := &decision.Device{Name: "leaf-01", Platform: "arista_eos"}
	write := func(edit func(*decision.Record)) string {
		command := []string{"service=shell", "cmd=snmp-server", "cmd-arg=community", "cmd-arg=public", "cmd-arg=<cr>"}
		o := prog.Command(command)
		if o.Reason != decision.NoPermitDominatesDeny {
			t.Fatalf("the secret deny does not decide the command: %+v", o)
		}
		logged := o.Policy(p.Bundle, hash)
		logged.MatchedDeny.Rule = []string{"snmp-server", "community", platform.Redacted, "**"}
		redacted := []string{"service=shell", "cmd=snmp-server", "cmd-arg=community", "cmd-arg=" + platform.Redacted,
			"cmd-arg=<cr>"}
		show := []string{"service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"}
		cmd := decision.Record{TS: compiled, Event: decision.EventAuthorizeCommand, Verdict: decision.VerdictDeny,
			Reason: o.Reason, Principal: "user:ops@example.com", Device: device,
			Request: &decision.Request{Raw: redacted, Redacted: true}, Policy: logged}
		edit(&cmd)
		var log bytes.Buffer
		sink := decision.NewJSONLines(&log)
		sink.Emit(decision.Record{TS: compiled, Event: decision.EventBlob,
			Blob: &decision.Blob{Hash: hash, Body: []byte(shown), Redacted: true}})
		sink.Emit(decision.Record{TS: compiled, Event: decision.EventAuthorizeSession,
			Verdict: decision.VerdictPermit, Reason: blob.SessionReason(), Principal: "user:ops@example.com",
			Device: device, Session: &decision.Session{Username: "ops"}, Reply: &decision.Reply{Attributes: attrs},
			Policy: &decision.Policy{Bundle: p.Bundle, Blob: hash}})
		s := prog.Command(show)
		sink.Emit(decision.Record{TS: compiled, Event: decision.EventAuthorizeCommand,
			Verdict: decision.VerdictPermit, Reason: s.Reason, Principal: "user:ops@example.com", Device: device,
			Request: &decision.Request{Raw: show}, Policy: s.Policy(p.Bundle, hash)})
		sink.Emit(cmd)
		path := filepath.Join(t.TempDir(), "decisions.jsonl")
		if strings.Contains(log.String(), secret) {
			t.Fatal("the fixture's log carries the secret")
		}
		if err := os.WriteFile(path, log.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	check := func(name string, args []string, code int, want string) {
		t.Helper()
		var out, errb bytes.Buffer
		got := run(append([]string{"policy", "replay"}, args...), &out, &errb)
		printed := out.String() + errb.String()
		if got != code || !strings.Contains(printed, want) {
			t.Fatalf("%s: code %d\n%s", name, got, printed)
		}
		for _, f := range []string{secret, strings.ToLower(secret), strings.ToUpper(secret), secret[:5], secret[4:9],
			secret[7:], hex.EncodeToString([]byte(secret)), base64.StdEncoding.EncodeToString([]byte(secret))} {
			if strings.Contains(strings.ToLower(printed), strings.ToLower(f)) {
				t.Fatalf("%s: replay prints %q:\n%s", name, f, printed)
			}
		}
	}
	files := []string{"--policy", pol, "--inventory", inv}
	asLogged := write(func(*decision.Record) {})
	check("no files", []string{asLogged}, 1, "replayed 3 records: 0 agree, 0 diverge, 3 unverifiable")
	check("the files", append(files, asLogged), 1, "replayed 3 records: 2 agree, 0 diverge, 1 unverifiable")
	check("the files, --line 4", append(files, "--line", "4", asLogged), 1,
		"line 4 authorize_command: unverifiable the record was redacted before it was written")
	// An edit that drops the redacted mark and restores the command replays
	// against the verbatim blob, whose deny names the secret: it diverges, and
	// what the blob matched is not printed.
	unmarked := write(func(cmd *decision.Record) {
		cmd.Request = &decision.Request{Raw: []string{"service=shell", "cmd=snmp-server", "cmd-arg=community",
			"cmd-arg=public", "cmd-arg=<cr>"}}
	})
	check("unmarked", append(files, "--line", "4", unmarked), 1,
		"line 4 authorize_command: diverge the verdict agrees but the matched rules do not")
	check("unmarked, all", append(files, unmarked), 1, "replayed 3 records: 2 agree, 1 diverge, 0 unverifiable")
	// Files that name another bundle give no blob: the blob they give
	// leaf-01 names that bundle, not the one the record was decided by.
	other, err := os.ReadFile(inv)
	if err != nil {
		t.Fatal(err)
	}
	inv2 := filepath.Join(t.TempDir(), "inventory.yaml")
	another := strings.Replace(string(other), "devices:\n", "devices:\n  - {name: leaf-02, platform: arista_eos, "+
		"addresses: [10.0.0.2]}\n", 1)
	if another == string(other) {
		t.Fatal("the fixture's devices were not found to edit")
	}
	if err := os.WriteFile(inv2, []byte(another), 0o600); err != nil {
		t.Fatal(err)
	}
	check("another bundle", []string{"--policy", pol, "--inventory", inv2, asLogged}, 1,
		"replayed 3 records: 0 agree, 0 diverge, 3 unverifiable")
}

// The diff report names the key a group subject uses (decision 41 ruling 8).
func TestPolicyDiffNamesAMachineGroup(t *testing.T) {
	_, inv := policyFixture(t)
	dir := t.TempDir()
	body := func(key string) []byte {
		return []byte("scopes: [{name: all_devices, match: {}}]\nroles: [{name: ro, privilege: readonly, permit: [show **]}]\n" +
			"subjects: [{name: backup, " + key + ": backup-hosts, token_ttl: 5m}]\n" +
			"grants: [{subject: backup, scope: all_devices, roles: [ro]}]\n")
	}
	oldPol, newPol := filepath.Join(dir, "old.yaml"), filepath.Join(dir, "new.yaml")
	if err := os.WriteFile(oldPol, body("group"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPol, body("machine_group"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `subject: backup's group "backup-hosts" -> machine_group "backup-hosts"`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A subject that is no group on one side of the diff says so: "none", never a
// group key it never had.
func TestPolicyDiffNamesNoneForAMissingGroup(t *testing.T) {
	_, inv := policyFixture(t)
	dir := t.TempDir()
	write := func(name, subjects string) string {
		path := filepath.Join(dir, name)
		body := "scopes: [{name: all_devices, match: {}}]\nroles: [{name: ro, privilege: readonly, permit: [show **]}]\n" +
			"subjects: [" + subjects + "]\n" +
			"grants: [{subject: backup, scope: all_devices, roles: [ro]}]\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	identity := write("identity.yaml", `{name: backup, identity: "app:backup", username: backup, token_ttl: 5m}`)
	machines := write("machines.yaml", `{name: backup, machine_group: backup-hosts, token_ttl: 5m}`)
	for _, tc := range []struct{ old, new, want string }{
		{machines, identity, `subject: backup's machine_group "backup-hosts" -> none`},
		{identity, machines, `subject: backup's none -> machine_group "backup-hosts"`},
	} {
		var out, errb bytes.Buffer
		if code := run([]string{"policy", "diff", "--old", tc.old, "--new", tc.new, "--inventory", inv}, &out, &errb); code != 1 ||
			!strings.Contains(out.String(), tc.want) {
			t.Errorf("code %d, want %q\n%s%s", code, tc.want, out.String(), errb.String())
		}
	}
}

// A diff that brings the entry-deny warning prints it and still exits 0:
// the warning is reported, never a gate (decision 44 ruling 4).
func TestPolicyDiffPrintsAProjectionWarningAndExitsZero(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: jx-01, platform: juniper_junos, addresses: [10.0.0.2]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, deny string) string {
		path := filepath.Join(dir, name)
		body := "platform_set: 1.2.0\nscopes: [{name: all_devices, match: {}}]\n" +
			"roles: [{name: op, privilege: operator, permit: [\"**\"]" + deny + "}]\n" +
			"subjects: [{name: noc, identity: \"user:noc@example.com\", username: noc, token_ttl: 60s}]\n" +
			"grants: [{subject: noc, scope: all_devices, roles: [op]}]\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	oldPol := write("old.yaml", "")
	newPol := write("new.yaml", `, deny: ["show configuration **"]`)
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "warning: projection_netconf_closed:") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// `port49 policy test` on a 1.3.0 readonly denying `show security` reports
// the capability reply with both bits and the reach deny, and passes.
func TestPolicyTestReportsTheSet130Reply(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: jx-01, platform: juniper_junos, addresses: [10.0.0.2]}\n"+
		"key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: k}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("platform_set: 1.3.0\nscopes: [{name: all_devices, match: {}}]\n"+
		"roles: [{name: r, privilege: readonly, permit: [\"show **\"], deny: [\"show security **\"]}]\n"+
		"subjects: [{name: noc, identity: \"user:noc@example.com\", username: noc, token_ttl: 60s}]\n"+
		"grants: [{subject: noc, scope: all_devices, roles: [r]}]\n"+fixtureKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "capability shape, bits view view-configuration") ||
		!strings.Contains(out.String(), "(deny_reach_bits; decision 48): monitor **") ||
		strings.Contains(out.String(), "projection_deny_beneath_view_configuration") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// The reply lists `policy diff` prints, and the RAISES hint an operator pastes
// into a session test, print the projection's deny-commands as it rendered it:
// the word-level redaction read `key` in `show +key` as an abbreviation and hid
// the regex after it (issue 17).
func TestPolicyDiffPrintsTheRenderedDenyReply(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: jx-01, platform: juniper_junos, addresses: [10.0.0.2]}\n"+
		"key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: k}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, deny string) string {
		path := filepath.Join(dir, name)
		body := "platform_set: 1.3.0\nscopes: [{name: all_devices, match: {}}]\n" +
			"roles: [{name: r, privilege: readonly, permit: [\"show **\"]" + deny + "}]\n" +
			"subjects: [{name: noc, identity: \"user:noc@example.com\", username: noc, token_ttl: 60s}]\n" +
			"grants: [{subject: noc, scope: all_devices, roles: [r]}]\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var out, errb bytes.Buffer
	run([]string{"policy", "diff", "--old", write("old.yaml", ""), "--new", write("new.yaml", `, deny: ["show cli **"]`),
		"--inventory", inv}, &out, &errb)
	const want = `-> ["user-permissions=view view-configuration", "deny-commands=^( *show +cli( .*)? *(\\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\\|.*)?| *set +cli( .*)? *(\\|.*)?)$"]`
	if !strings.Contains(out.String(), want) {
		t.Fatalf("the reply line:\n%s%s", out.String(), errb.String())
	}
}

func policyKeysFixture(t *testing.T) (write func(name, body string) string, inv string) {
	t.Helper()
	dir := t.TempDir()
	write = func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write, write("inventory.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.20.0.7]}\n")
}

// policy test reads the key sets from the policy itself (decision 53 ruling
// 3), and fails every policy port49d refuses for its keys: no keys: block,
// with or without key_groups, and a reference outside key_secret_refs.
func TestPolicyTestReadsTheKeysFromThePolicy(t *testing.T) {
	write, inv := policyKeysFixture(t)
	const groups = "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}]\n"
	const head = "scopes: [{name: all_devices, match: {}}]\nroles: [{name: r, privilege: readonly, permit: [show **]}]\n" +
		"subjects: [{name: s, identity: [\"user:alice@example.com\"], username: alice, token_ttl: 60s}]\n" +
		"grants: [{subject: s, scope: all_devices, roles: [r]}]\n"
	keys := func(ref string) string {
		return "keys:\n  k:\n    current: {version: 3, secret_ref: " + ref + "}\n" +
			"    accept: [{version: 2, secret_ref: " + ref + "_OLD}]\n"
	}
	cfgFile := write("port49d.yaml", "key_secret_refs: {env_prefix: PORT49_ENC_}\n")
	for name, c := range map[string]struct {
		policy string
		args   []string
		code   int
		want   string
	}{
		"a keys block": {head + groups + keys("env:PORT49_KEY_NEW"), nil, 0, "report: key k version 2 has no retire_after"},
		"no keys block, with key_groups": {head + groups, nil, 1,
			"keys: the policy declares no keys: block"},
		"no keys block, no key_groups":   {head, nil, 1, "keys: the policy declares no keys: block"},
		"a ref outside the allowance":    {head + groups + keys("env:PORT49_ENC_V2"), nil, 1, "outside key_secret_refs"},
		"the same, --config widening it": {head + groups + keys("env:PORT49_ENC_V2"), []string{"--config", cfgFile}, 0, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := append([]string{"policy", "test", "--policy", write("p.yaml", c.policy), "--inventory", inv}, c.args...)
			code := run(args, &out, &errOut)
			got := out.String() + errOut.String()
			if code != c.code || !strings.Contains(got, c.want) {
				t.Fatalf("exit %d, want %d, with %q:\n%s", code, c.code, c.want, got)
			}
		})
	}
}

// policy diff fails a change that names another secret for a version both
// files hold (decision 53 ruling 3; pre-flight M9): across a restart port49d
// has nothing to compare it against.
func TestPolicyDiffRefusesARekeyedVersion(t *testing.T) {
	write, inv := policyKeysFixture(t)
	policyWith := func(ref string) string {
		return strings.Replace(keysPolicy, keysBlock, "keys:\n  prod_key:\n    current: {version: 1, secret_ref: "+ref+"}\n", 1)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "diff", "--old", write("old.yaml", policyWith("env:PORT49_KEY_A")),
		"--new", write("new.yaml", policyWith("env:PORT49_KEY_B")), "--inventory", inv}, &out, &errOut)
	// An env: reference prints as one, never by name: a secret pasted where a
	// name goes parses as a name, and this is the CI gate's stdout.
	if code != 1 || !strings.Contains(out.String(), "REFUSED: keys: prod_key version 1 names secret_ref an env: "+
		"reference, and the old policy an env: reference") || strings.Contains(out.String(), "PORT49_KEY_") {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
	// A pasted token as the name, in either direction, is never printed; a
	// file: reference, which a secret cannot be, still names its path.
	const pasted = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	for name, c := range map[string][2]string{
		"pasted in the new": {"env:PORT49_KEY_A", "env:" + pasted},
		"pasted in the old": {"env:" + pasted, "env:PORT49_KEY_A"},
	} {
		out.Reset()
		errOut.Reset()
		code = run([]string{"policy", "diff", "--old", write("o-"+name+".yaml", policyWith(c[0])),
			"--new", write("n-"+name+".yaml", policyWith(c[1])), "--inventory", inv}, &out, &errOut)
		if code != 1 || !strings.Contains(out.String(), "REFUSED: keys: prod_key version 1") {
			t.Fatalf("%s: exit %d (the re-key was not refused)", name, code)
		}
		if strings.Contains(out.String()+errOut.String(), pasted) {
			t.Fatalf("%s: the pasted value was printed", name)
		}
	}
	out.Reset()
	errOut.Reset()
	code = run([]string{"policy", "diff", "--old", write("of.yaml", policyWith("file:/run/port49/keys/a")),
		"--new", write("nf.yaml", policyWith("file:/run/port49/keys/b")), "--inventory", inv}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "secret_ref file:/run/port49/keys/b, and the old policy file:/run/port49/keys/a") {
		t.Fatalf("a file: re-key: exit %d:\n%s", code, out.String())
	}
	out.Reset()
	errOut.Reset()
	code = run([]string{"policy", "diff", "--old", write("old2.yaml", policyWith("env:PORT49_KEY_A")),
		"--new", write("new2.yaml", policyWith("env:PORT49_KEY_A")), "--inventory", inv}, &out, &errOut)
	if strings.Contains(out.String(), "REFUSED: keys:") {
		t.Fatalf("an unchanged key was refused:\n%s", out.String())
	}
}

// policy test says which allowance it checked the references against when no
// --config named port49d.yaml's: a fleet that narrows key_secret_refs would
// otherwise see CI go green on a policy every port49d refuses (re-review 8, M1).
const testRow = "tests:\n  - {subject: s, device: leaf-01, command: \"show version\", expect: permit}\n"

func TestPolicyTestSaysWhichAllowanceItChecked(t *testing.T) {
	write, inv := policyKeysFixture(t)
	const head = "scopes: [{name: all_devices, match: {}}]\nroles: [{name: r, privilege: readonly, permit: [show **]}]\n" +
		"subjects: [{name: s, identity: [\"user:alice@example.com\"], username: alice, token_ttl: 60s}]\n" +
		"grants: [{subject: s, scope: all_devices, roles: [r]}]\n" +
		"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}]\n" + testRow
	keyed := head + "keys:\n  k:\n    current: {version: 3, secret_ref: env:PORT49_KEY_NEW}\n"
	cfg := write("port49d.yaml", "key_secret_refs: {env_prefix: PORT49_KEY_}\n")
	const line = "keys: checked against the default key_secret_refs (env: variables starting PORT49_KEY_, file: under /run/port49/keys); " +
		"pass --config to check port49d.yaml's"
	for name, c := range map[string]struct {
		policy string
		args   []string
		want   bool
	}{
		"a reference, no --config":    {keyed, nil, true},
		"a reference, with --config":  {keyed, []string{"--config", cfg}, false},
		"keys: {} names no reference": {head + "keys: {}\n", nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := append([]string{"policy", "test", "--policy", write("p.yaml", c.policy), "--inventory", inv}, c.args...)
			code := run(args, &out, &errOut)
			if got := strings.Contains(out.String(), line); got != c.want {
				t.Fatalf("exit %d, line present %v, want %v:\n%s%s", code, got, c.want, out.String(), errOut.String())
			}
		})
	}
}

// A secret pasted where an env: name goes is outside the allowance, and
// policy test says which key and version, never the variable it parsed as.
func TestPolicyTestNeverPrintsAPastedEnvName(t *testing.T) {
	write, inv := policyKeysFixture(t)
	body := "scopes: [{name: all_devices, match: {}}]\nroles: [{name: r, privilege: readonly, permit: [show **]}]\n" +
		"subjects: [{name: s, identity: [\"user:alice@example.com\"], username: alice, token_ttl: 60s}]\n" +
		"grants: [{subject: s, scope: all_devices, roles: [r]}]\n" +
		"keys:\n  k:\n    current: {version: 3, secret_ref: env:FAKEtoken0123456789abcdef0123456789abcdef}\n"
	var out, errOut bytes.Buffer
	run([]string{"policy", "test", "--policy", write("p.yaml", body), "--inventory", inv}, &out, &errOut)
	got := out.String() + errOut.String()
	if !strings.Contains(got, "key k version 3 secret_ref an env: reference is outside key_secret_refs") ||
		strings.Contains(got, "FAKEtoken") {
		t.Fatalf("the refusal is missing, or names the pasted variable")
	}
}
