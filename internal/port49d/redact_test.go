package port49d

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

// A policy the daemon refuses is named in its refusal line, at start and on
// every reload, and stderr is a log. The line quotes no rule text and no
// term, so a value is hidden whether a built-in pattern covers it or only
// the refused file's own `platforms:` pattern does, which never loaded
// (spec §5.8; task 11 review C2, fail closed).
func TestARefusedPolicyNeverPrintsARuleSecret(t *testing.T) {
	operator := "platforms: {arista_eos: {redact: [{match: ['**'], after: psk}]}}\n"
	for _, tt := range []struct{ name, prefix, deny, want string }{
		{"a regex that is a word", "", "snmp-server community /^Hunter2$/", `role "r": deny #1: term 3 is a regex`},
		{"a case-sensitive deny", "", "snmp-server community /(?-i)Hunter2/", `role "r": deny #1: term 3 turns`},
		{"a value only the file's own pattern covers", operator, "crypto psk Hunter2 /^rw$/",
			`role "r": deny #1: term 4 is a regex`},
	} {
		secret := tt.prefix + strings.Replace(minimalPolicy, `permit: ["**"]}`,
			`permit: ["**"], deny: ["`+tt.deny+`"]}`, 1)
		cfg := brokerConfig(t, minimalPolicy)
		if _, err := parseBundle(cfg, []byte(secret), cfg.Inventory); err == nil ||
			strings.Contains(err.Error(), "Hunter2") || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("%s, at start: %v", tt.name, err)
		}
		rig := newReloadRig(t, minimalPolicy)
		rig.write(t, secret)
		rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
		if out := rig.out.String(); !strings.Contains(out, "refused; still serving") || !strings.Contains(out, tt.want) ||
			strings.Contains(out, "Hunter2") {
			t.Fatalf("%s, on a reload: %q", tt.name, out)
		}
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
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "ntp1", Platform: "meinberg_lantime", KeyRef: "lab_key"})
	if err := buildWith(cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "matches any argument") || strings.Contains(out.String(), "Hunter2") {
		t.Fatalf("stderr: %s", out.String())
	}
}

// A variant keyed by its own name would get only the default redaction list,
// and Junos's own patterns (platforms/redact.yaml) would not apply to its
// records: a secret in the log (spec §5.8; plan 6a Decided 11).
func TestAVariantIsRedactedAsItsBase(t *testing.T) {
	pol, err := policy.Parse([]byte(minimalPolicy+"platforms:\n  srx_variant: {based_on: juniper_junos}\n"), policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	got := redactorFor(policy.NewLive(pol))("srx_variant")
	want := platform.Redactions("juniper_junos")
	if len(got) < len(want) || !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatalf("the variant's patterns do not begin with Junos's: got %d, Junos %d", len(got), len(want))
	}
	if reflect.DeepEqual(platform.Redactions("srx_variant"), want) {
		t.Fatal("the default list equals Junos's, so this test proves nothing")
	}
	// A record the variant sends with a hash only Junos's patterns hide, in
	// any case and abbreviated, as the device accepts it, never reaches the
	// log (spec §5.8).
	const hash = "$6$Vq9rT2xK$Zm8pL0wQyS3cN5vB7aHjE1uO4iR6tY"
	for _, line := range []string{
		"set system root-authentication encrypted-password " + hash,
		"SET SYSTEM ROOT-AUTHENTICATION ENCRYPTED-PASSWORD " + hash,
		"set system root-authentication encrypted-pass " + hash,
		"set system root-authentication plain-text-password-value " + hash,
		"set snmp v3 usm local-engine user u authentication-sha256 authentication-password " + hash,
		"set snmp v3 usm local-engine user u privacy-aes128 privacy-password " + hash,
	} {
		raw := []string{"task_id=1", "service=shell", "cmd=" + line}
		if _, hidden := platform.Redact(platform.Redactions("srx_variant"), []string{line}); hidden {
			t.Fatalf("%s: the default list hides it, so this case proves nothing", line)
		}
		outRaw, outVec, _ := platform.RedactRecord(got, raw, []string{line})
		if joined := strings.ToLower(strings.Join(append(outRaw, outVec...), " ")); strings.Contains(joined,
			strings.ToLower(hash)) || strings.Contains(joined, "vq9rt2xk") {
			t.Errorf("%s: the variant's record carries the hash: %q %q", line, outRaw, outVec)
		}
	}
}
