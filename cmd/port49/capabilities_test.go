package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `devices capabilities` reads the log a daemon wrote and prints the matrix
// and the reconciliation, and exits 1 on a finding; a gap in the accounting
// stream makes the reconciliation's finding a possibility.
func TestDevicesCapabilities(t *testing.T) {
	pol, inv := policyFixture(t)
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	lines := []string{
		`{"ts":"2026-09-24T12:00:01.000Z","event":"authorize_session","verdict":"permit","reason":"context_matched","device":{"nas":"10.0.0.1","name":"leaf-01","platform":"arista_eos"},"session":{"ctx_id":"c1","port":"vty4","rem_addr":"","privilege":15}}`,
		`{"ts":"2026-09-24T12:00:02.000Z","event":"account","flags":"stop","attribution":"resolved","device":{"nas":"10.0.0.1","name":"leaf-01","platform":"arista_eos"},"session":{"ctx_id":"c1","port":"vty4","rem_addr":"","privilege":15},"record":{"raw":["task_id=3","cmd=show interfaces <cr>"],"vector":["show","interfaces","<cr>"],"priv_lvl":15}}`,
		`not a record`,
	}
	if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
	if code != 1 || !strings.Contains(out.String(), "leaf-01  arista_eos  admitted   session,commands  session") ||
		!strings.Contains(out.String(), "⚠ UNAUTHORIZED TIER — leaf-01") ||
		!strings.Contains(out.String(), `example: "show interfaces"`) ||
		!strings.Contains(out.String(), "1 log lines did not read as records") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	gap := `{"ts":"2026-09-24T12:00:03.000Z","event":"account_gap","gap":{"stage":"drain_unparseable","records":2,"since":"2026-09-24T12:00:00.000Z"}}`
	if err := os.WriteFile(log, []byte(strings.Join(append(lines[:2], gap), "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code = run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "? POSSIBLY AN UNAUTHORIZED TIER") ||
		!strings.Contains(out.String(), "drain_unparseable 2") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A device never seen in the window is a note, not a page: exit 0 (I13).
func TestANeverSeenDeviceIsANote(t *testing.T) {
	pol, inv := policyFixture(t)
	if err := os.WriteFile(inv, []byte(strings.Replace(string(readFile(t, inv)), "devices:\n",
		"devices:\n  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(log, []byte(`{"ts":"2026-09-24T12:00:01.000Z","event":"authorize_session","verdict":"permit",`+
		`"reason":"context_matched","device":{"nas":"10.0.0.1","name":"leaf-01","platform":"arista_eos"},`+
		`"session":{"ctx_id":"c1","port":"vty4","rem_addr":"","privilege":15}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "note: never seen") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// An example echoed from the log is redacted by the built-in patterns and by
// the policy's own, and a line that does not read as a record is counted,
// never quoted: the report lands in cron mail and tickets (spec §5.8).
func TestDevicesCapabilitiesNeverPrintsASecret(t *testing.T) {
	pol, inv := policyFixture(t)
	if err := os.WriteFile(pol, append([]byte("platforms: {arista_eos: {redact: [{match: ['**'], after: psk}]}}\n"),
		readFile(t, pol)...), 0o600); err != nil {
		t.Fatal(err)
	}
	account := func(cmd string, vector string) string {
		return `{"ts":"2026-09-24T12:00:02.000Z","event":"account","flags":"stop","attribution":"resolved",` +
			`"device":{"nas":"10.0.0.1","name":"leaf-01","platform":"arista_eos"},"session":{"ctx_id":"c1",` +
			`"port":"vty4","rem_addr":"","privilege":15},"record":{"raw":["task_id=3","cmd=` + cmd + ` <cr>"],` +
			`"vector":[` + vector + `,"<cr>"],"priv_lvl":15}}`
	}
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	lines := []string{
		account("username admin secret HUNTER2", `"username","admin","secret","HUNTER2"`),
		account("crypto key psk HUNTER2", `"crypto","key","psk","HUNTER2"`),
		account(`crypto key psk HUN\"TER2`, `"crypto","key","psk","HUN\"TER2"`),
		`{"ts":"HUNTER2 is not a record`,
	}
	if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
	if text := out.String() + errb.String(); code != 1 || strings.Contains(text, "HUNTER2") || strings.Contains(text, "TER2") ||
		!strings.Contains(text, "⚠ UNAUTHORIZED TIER — leaf-01") || !strings.Contains(text, "«redacted»") ||
		!strings.Contains(text, "1 log lines did not read as records") {
		t.Fatalf("code %d\n%s", code, text)
	}
}

// An empty log fixes no window: the header says so rather than printing a
// zero time, and nothing pages.
func TestDevicesCapabilitiesOnAnEmptyLog(t *testing.T) {
	pol, inv := policyFixture(t)
	log := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "window: no records;") || strings.Contains(out.String(), "0001-") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}
