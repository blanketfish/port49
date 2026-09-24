package main

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// port49d redacts with the built-in patterns and, where a policy is in force,
// the ones its `platforms:` blocks add, read at each record so a reload
// reaches them (spec §5.8).
func TestTheDaemonRedactsWithThePolicyInForce(t *testing.T) {
	if rules := redactorFor(nil)("arista_eos"); !reflect.DeepEqual(rules, platform.Redactions("arista_eos")) {
		t.Fatalf("no policy: %+v", rules)
	}
	parse := func(body string) *policy.Policy {
		p, err := policy.Parse([]byte(body+minimalPolicy), policy.Env{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	live := policy.NewLive(parse(""))
	redact := redactorFor(live)
	if rules := redact("arista_eos"); len(rules) != len(platform.Redactions("arista_eos")) {
		t.Fatalf("%+v", rules)
	}
	live.Swap(parse("platforms: {arista_eos: {redact: [{match: ['**'], after: psk}]}}\n"))
	if rules := redact("arista_eos"); len(rules) != len(platform.Redactions("arista_eos"))+1 ||
		rules[len(rules)-1].After != "psk" {
		t.Fatalf("after the reload: %+v", rules)
	}
	if rules := redact("cisco_nxos"); len(rules) != len(platform.Redactions("cisco_nxos")) {
		t.Fatalf("a block reaches only its own platform: %+v", rules)
	}
}

// A policy the daemon refuses is quoted in its refusal line, at start and on
// every reload, and stderr is a log: a rule's secret value is redacted there
// as it is everywhere else (spec §5.8; task 11 review C2).
func TestARefusedPolicyNeverPrintsARuleSecret(t *testing.T) {
	secret := strings.Replace(minimalPolicy, `permit: ["**"]}`,
		`permit: ["**"], deny: ["snmp-server community Hunter2 /^rw$/"]}`, 1)
	if _, err := parsePolicy(brokerConfig(t, minimalPolicy), []byte(secret)); err == nil ||
		strings.Contains(err.Error(), "Hunter2") || !strings.Contains(err.Error(), "snmp-server community") {
		t.Fatalf("at start: %v", err)
	}
	rig := newReloadRig(t, minimalPolicy)
	rig.write(t, secret)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if out := rig.out.String(); !strings.Contains(out, "refused; still serving") || strings.Contains(out, "Hunter2") {
		t.Fatalf("on a reload: %q", out)
	}
}

// Every line port49d says about a loaded policy runs its quoted rules through
// the redaction, the widened-deny line included (task 11 review C2).
func TestAWidenedDenyLineNeverPrintsARuleSecret(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	cfg := brokerConfig(t, strings.Replace(minimalPolicy, `permit: ["**"]}`,
		`permit: ["**"], deny: ["snmp-server community Hunter2 /tftp/"]}`, 1))
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "ntp1", Platform: "meinberg_lantime"})
	if err := buildWith(cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "matches any argument") || strings.Contains(out.String(), "Hunter2") {
		t.Fatalf("stderr: %s", out.String())
	}
}
