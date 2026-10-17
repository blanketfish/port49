package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
)

const keysPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

const keysInventory = `devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.20.0.7]}
  - {name: leaf-19, platform: arista_eos, addresses: [10.20.4.9]}
`

const keysConfig = `keys:
  prod_key:
    current: {version: 3, secret_env: NEVER_READ_V3}
    accept:  [{version: 2, secret_env: NEVER_READ_V2, retire_after: 2026-10-01}]
`

func keysFiles(t *testing.T) (policyPath, inventoryPath, configPath, logPath string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	keysNow = func() time.Time { return now }
	t.Cleanup(func() { keysNow = time.Now })
	var log bytes.Buffer
	sink := decision.NewJSONLines(&log)
	sink.Emit(decision.Record{TS: now.Add(-time.Minute), Event: decision.EventRedeem,
		Device: &decision.Device{Name: "leaf-01", Platform: "arista_eos", KeyRef: "prod_key", KeyVersion: 3}})
	sink.Emit(decision.Record{TS: now.Add(-2 * time.Minute), Event: decision.EventRedeem,
		Device: &decision.Device{Name: "leaf-19", Platform: "arista_eos", KeyRef: "prod_key", KeyVersion: 2}})
	return write("policy.yaml", keysPolicy), write("inventory.yaml", keysInventory),
		write("port49d.yaml", keysConfig), write("decisions.jsonl", log.String())
}

func TestKeysStatusNamesTheDeviceOnTheOldVersion(t *testing.T) {
	pol, inv, cfg, log := keysFiles(t)
	var out, errOut bytes.Buffer
	code := run([]string{"keys", "status", "--policy", pol, "--inventory", inv, "--config", cfg, log}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	// At keysFiles' clock, version 2 is still accepted: it admits through
	// 2026-10-01.
	if !strings.Contains(out.String(), "rotation not finished: leaf-19") || !strings.Contains(out.String(), "      2  accept ") {
		t.Fatalf("%s", out.String())
	}
}

func TestKeysShowSaysWhichKeyAndWhy(t *testing.T) {
	pol, inv, cfg, _ := keysFiles(t)
	var out, errOut bytes.Buffer
	code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "--config", cfg, "leaf-19"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"leaf-19: key_ref prod_key, by the cidr tier (cidr 10.0.0.0/8 → prod_key)",
		"provision version 3", "also accepted: version 2, retire_after 2026-10-01", "the secret is not shown"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
	if code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "nobody"}, &out, &errOut); code != 1 {
		t.Fatalf("an unknown device exits %d", code)
	}
}

// secretForms are the ways a secret could leak into output: as written, in
// either case, quoted, escaped, hex and base64.
func secretForms(secret string) []string {
	forms := []string{secret, strings.ToLower(secret), strings.ToUpper(secret), fmt.Sprintf("%q", secret),
		strconv.QuoteToASCII(secret), hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret))),
		base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawStdEncoding.EncodeToString([]byte(secret)),
		base64.URLEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret))}
	// A truncated echo is a leak too: a YAML type error prints a value's
	// first seven characters, and a backtick in it can cut that to five.
	for i := 0; i+5 <= len(secret); i++ {
		forms = append(forms, secret[i:i+5])
	}
	return forms
}

// Spec §12: `keys status` and `keys show` name a key by key_ref and version
// and never render its secret, in any mode or error path.
func TestKeysNeverPrintASecret(t *testing.T) {
	const v3, v2 = "Sx9-qT4v!Lm2@pR7zK0w#Yh5", "Qa8$ZmN3^tBv6&cXe1*Wr4Ju"
	t.Setenv("NEVER_READ_V3", v3)
	t.Setenv("NEVER_READ_V2", v2)
	pol, inv, cfg, log := keysFiles(t)
	dir := t.TempDir()
	cases := [][]string{
		{"keys", "status", "--policy", pol, "--inventory", inv, "--config", cfg, log},
		{"keys", "status", "--policy", pol, "--inventory", inv, "--config", cfg, "--since", "90s", log},
		{"keys", "show", "--policy", pol, "--inventory", inv, "--config", cfg, "leaf-19"},
		{"keys", "show", "--policy", pol, "--inventory", inv, "--config", cfg, "nobody"},
	}
	// An operator who pastes the secret into port49d.yaml, in each place a
	// decode error or a key check could quote it back.
	const alnum, tick = "Wd7ZkP2mRq9TxL4vNc8B", "H`j5Ns8!Pw3@Zb6#Fq1$Gm7"
	secrets := []string{v3, v2, alnum, tick}
	for i, body := range []string{
		"keys:\n  prod_key:\n    current: " + v3 + "\n",
		"keys:\n  prod_key:\n    current: {version: " + alnum + ", secret_env: X}\n",
		"keys:\n  prod_key:\n    current:\n      version: 3\n      secret_env: X\n      " + v3 + ": x\n",
		"keys:\n  prod_key:\n    current: {version: 3, " + alnum + "}\n",
		"keys:\n  prod_key:\n    current: {version: 3, secret_env: X}\n" +
			"    accept: [{version: 2, secret_env: Y, retire_after: \"" + v3 + "\"}]\n",
		"keys:\n  prod_key:\n    current: *" + alnum + "\n",
		"keys:\n  prod_key:\n    current: !" + alnum + " x\n",
		"keys:\n  prod_key:\n    current: " + tick + "\n",
		"keys:\n  prod_key:\n    current: {version: 3, secret_env: \"" + v3 + "\"}\n",
		"keys:\n  prod_key:\n    current: {version: 3, secret_env: " + alnum + "}\n",
		"keys:\n  " + alnum + ":\n    current: {version: 3, secret_env: X}\n",
	} {
		bad := filepath.Join(dir, fmt.Sprintf("bad-%d.yaml", i))
		if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, []string{"keys", "show", "--policy", pol, "--inventory", inv, "--config", bad, "leaf-19"},
			[]string{"keys", "status", "--policy", pol, "--inventory", inv, "--config", bad, log})
	}
	cases = append(cases, []string{"keys", "show", "--bogus"})
	for _, args := range cases {
		var out, errOut bytes.Buffer
		run(args, &out, &errOut)
		for _, secret := range secrets {
			for _, form := range secretForms(secret) {
				if strings.Contains(out.String(), form) || strings.Contains(errOut.String(), form) {
					t.Errorf("%v printed the secret as %q:\nstdout: %s\nstderr: %s", args[1:3], form, out.String(), errOut.String())
				}
			}
		}
	}
}

// Two groups tying on a device are named by what they match, not only by
// key_ref: two attribute groups can share one.
func TestKeysShowNamesTheGroupsOfATie(t *testing.T) {
	_, _, cfg, _ := keysFiles(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	inv := filepath.Join(dir, "inventory.yaml")
	body := strings.Replace(keysPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]",
		"key_groups: [{match: {attributes: {site: campus}}, key_ref: prod_key}, "+
			"{match: {attributes: {role: leaf}}, key_ref: prod_key}]", 1)
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: leaf-19, platform: arista_eos, addresses: [10.20.4.9], "+
		"attributes: {site: campus, role: leaf}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "--config", cfg, "leaf-19"}, &out, &errOut); code != 1 {
		t.Fatalf("a tie exits %d: %s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"attributes {site: campus} → prod_key", "attributes {role: leaf} → prod_key"} {
		if !strings.Contains(out.String()+errOut.String(), want) {
			t.Errorf("missing %q in %s%s", want, out.String(), errOut.String())
		}
	}
}

// An accept version past its retire_after admits nothing (spec §10), so keys
// show does not call it accepted.
func TestKeysShowDoesNotCallAPastVersionAccepted(t *testing.T) {
	pol, inv, _, _ := keysFiles(t)
	past := filepath.Join(t.TempDir(), "port49d.yaml")
	if err := os.WriteFile(past, []byte(strings.Replace(keysConfig, "2026-10-01", "2020-01-01", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "--config", past, "leaf-19"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if strings.Contains(out.String(), "also accepted: version 2") ||
		!strings.Contains(out.String(), "version 2 retired: retire_after 2020-01-01 has passed, so it admits none") {
		t.Fatalf("%s", out.String())
	}
}

// A device whose pin is not a key_ref name is refused alone, and neither
// command prints the pin.
func TestKeysNeverPrintAPastedPin(t *testing.T) {
	const secret = "Wd7ZkP2mRq9TxL4vNc8B"
	pol, _, cfg, log := keysFiles(t)
	inv := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(inv, []byte(keysInventory+"  - {name: pasted, platform: arista_eos, addresses: [10.20.9.9], "+
		"key_ref: "+secret+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"keys", "show", "--policy", pol, "--inventory", inv, "--config", cfg, "pasted"},
		{"keys", "show", "--policy", pol, "--inventory", inv, "pasted"},
		{"keys", "status", "--policy", pol, "--inventory", inv, "--config", cfg, log},
	} {
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		if strings.Contains(out.String()+errOut.String(), "Wd7Zk") {
			t.Errorf("%v printed the pin:\n%s%s", args[1], out.String(), errOut.String())
		}
		if args[1] == "status" && (code != 0 || !strings.Contains(out.String(), "rotation not finished: leaf-19")) {
			t.Errorf("the rest of the fleet: exit %d\n%s%s", code, out.String(), errOut.String())
		}
	}
}

func TestKeysShowSaysATLSDeviceHasNoKey(t *testing.T) {
	pol, _, cfg, _ := keysFiles(t)
	inv := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: tls-7, platform: arista_eos, addresses: [10.20.0.70], transport: tls}\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "--config", cfg, "tls-7"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if want := "tls-7: transport tls (RFC 9887): no shared key; its credential is its certificate"; !strings.Contains(out.String(), want) {
		t.Fatalf("got %q", out.String())
	}
}

func TestKeysStatusSkipsATLSDevice(t *testing.T) {
	pol, _, cfg, _ := keysFiles(t)
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	body := "devices:\n  - {name: leaf-19, platform: arista_eos, addresses: [10.20.4.9]}\n" +
		"  - {name: tls-7, platform: arista_eos, addresses: [10.20.0.70], transport: tls}\n"
	if err := os.WriteFile(inv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	sink := decision.NewJSONLines(&log)
	now := keysNow()
	// Only leaf-19 appears in the log; a keyed device never seen is listed,
	// and a TLS device, which has no key to see, must not be.
	sink.Emit(decision.Record{TS: now.Add(-time.Minute), Event: decision.EventRedeem,
		Device: &decision.Device{Name: "leaf-19", Platform: "arista_eos", KeyRef: "prod_key", KeyVersion: 2}})
	logPath := filepath.Join(dir, "decisions.jsonl")
	if err := os.WriteFile(logPath, log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"keys", "status", "--policy", pol, "--inventory", inv, "--config", cfg, logPath}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "leaf-19") || strings.Contains(out.String(), "tls-7") {
		t.Fatalf("a TLS device has no key to phase out, and leaf-19 is the control: %s", out.String())
	}
}
