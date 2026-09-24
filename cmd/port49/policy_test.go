package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
)

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
	if code := run([]string{"explain", "--policy", pol, "--subject", "noc", "--device", "leaf-01"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "--inventory") {
		t.Fatalf("no inventory: code %d %s", code, errb.String())
	}
}

// `port49 policy test` passes a policy whose tests pass, and fails one whose
// test does not, naming it.
func TestPolicyTestIsACIGate(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "PASS noc on leaf-01: \"reload\" -> deny no_rule_matched") ||
		!strings.Contains(out.String(), "2 tests, 0 failed") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	raw, _ := os.ReadFile(pol)
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

// A policy that fails a load-time check fails the gate, with the check's
// message, before any test runs: here, a class no platform defines (spec §4).
// A policy that loads with a device quarantined names it (spec §10).
func TestPolicyTestFailsAPolicyThatDoesNotLoad(t *testing.T) {
	pol, inv := policyFixture(t)
	raw, _ := os.ReadFile(pol)
	if err := os.WriteFile(pol, []byte(strings.Replace(string(raw), "permit: [show **]", "permit: [interface @uplinks]", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "@uplinks, which no platform defines") || out.Len() != 0 {
		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out.String(), errb.String())
	}
	if err := os.WriteFile(pol, []byte(strings.Replace(string(raw), "privilege: readonly", "privilege: operator", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "quarantine: leaf-01 (arista_eos): quarantined: subject \"noc\": level operator has no rendering") ||
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
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(path, log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "replay", path}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "replayed 1 records: 1 agree, 0 diverge, 0 unverifiable") {
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
