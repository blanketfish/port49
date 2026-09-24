package policy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

// mintRefused is a policy whose session reply, filled in with the subject's
// username, is longer than RFC 8907 carries: the broker refuses every mint
// attribute_too_long, so nothing is permitted anywhere.
var mintRefused = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {all: ["home*/` + strings.Repeat("h", 230) + `/{username}"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: a-username-long-enough-to-overflow, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]
`

// A policy test answers as the broker and explain do: a mint the broker
// refuses permits nothing, so a test expecting permit fails, and names the
// mint item error explain prints (spec §12).
func TestATestAgreesWithTheBrokersMintChecks(t *testing.T) {
	p := mustParse(t, mintRefused+`tests:
  - {subject: s, device: leaf-01, command: "show version", expect: permit}
  - {subject: s, device: leaf-01, command: "show version", expect: deny}
  - {principal: "user:s@example.com", device: nx-01, command: "show version", expect: permit}
`)
	results := p.RunTests(noon)
	if len(results) != 3 {
		t.Fatalf("%d results", len(results))
	}
	for i, r := range results {
		if r.Permit || r.MintError != "attribute_too_long" || r.Pass != (i == 1) {
			t.Errorf("%d: permit=%v mint=%q pass=%v", i, r.Permit, r.MintError, r.Pass)
		}
	}
	e, err := p.Explain("s", "", "leaf-01", "show version", noon)
	if err != nil || e.MintError != results[0].MintError {
		t.Fatalf("explain says %q (%v), the test %q", e.MintError, err, results[0].MintError)
	}
	// A passing test the mint refuses acknowledges nothing.
	if got := p.passedPermits(p.expiryInstants(noon)); len(got) != 0 {
		t.Fatalf("acknowledgments %+v", got)
	}
}

// An inventory device with no platform is answered device_unconfigured, as
// the broker and explain answer it, not device_quarantined.
func TestATestOnADeviceWithNoPlatformIsDeviceUnconfigured(t *testing.T) {
	p, err := Parse([]byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]
tests:
  - {subject: s, device: bare, command: "show version", expect: deny}
`), Env{Now: noon, Devices: append(inventory(), admission.Device{Name: "bare", Addresses: []netip.Addr{netip.MustParseAddr("10.9.9.8")}})})
	if err != nil {
		t.Fatal(err)
	}
	r := p.RunTests(noon)[0]
	if !r.Pass || r.Permit || r.MintError != "device_unconfigured" || r.Reason != "" {
		t.Fatalf("%+v", r)
	}
}

// MintCheck is the broker's one reading of a mint: a blob that will not
// encode is the broker's own error, a reply too long or carrying a separator
// once filled in is the data's.
func TestMintCheckNamesTheItemError(t *testing.T) {
	if code, _ := MintCheck(Resolution{}, "user:s@example.com", "leaf-01"); code != "broker_error" {
		t.Fatalf("an empty blob: %q", code)
	}
	p := mustParse(t, strings.Replace(mintRefused, "a-username-long-enough-to-overflow", "s", 1))
	res, err := p.ResolveSubject("s", deviceNamed(t, "leaf-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	for username, want := range map[string]string{"s": "", "s=x": "attribute_unsafe",
		strings.Repeat("s", 40): "attribute_too_long"} {
		res.Username = username
		if code, _ := MintCheck(res, "user:s@example.com", "leaf-01"); code != want {
			t.Errorf("%s: %q, want %q", username, code, want)
		}
	}
}

// IOS-XE sends `GigabitEthernet1` as `GigabitEthernet`, `1` (L21), so the
// offline tools evaluate what the device sends: a permit written joined never
// matches there, explain and policy test say so as the daemon would, and lint
// names the permit. EOS sends the word whole.
func TestTheOfflineToolsSplitAnInterfaceNameAsIOSXEDoes(t *testing.T) {
	const body = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: joined, privilege: readonly, permit: [interface GigabitEthernet1 **]}
  - {name: split, privilege: readonly, permit: [interface Loopback 0 **]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [joined, split]}]
tests:
  - {subject: s, device: xe-01, command: "interface GigabitEthernet1 shutdown", expect: deny, reason: no_rule_matched}
  - {subject: s, device: xe-01, command: "interface Loopback0 shutdown", expect: permit}
  - {subject: s, device: leaf-01, command: "interface GigabitEthernet1 shutdown", expect: permit}
`
	p := mustParse(t, body)
	for _, r := range p.RunTests(noon) {
		if !r.Pass {
			t.Errorf("%s %q: permit=%v %s %v", r.Test.Device, r.Test.Command, r.Permit, r.Reason, r.Err)
		}
		split := slices.ContainsFunc(r.Caveats, func(c string) bool { return strings.Contains(c, "as IOS-XE sends an interface name") })
		if split != (r.Test.Device == "xe-01") {
			t.Errorf("%s %q: caveats %q", r.Test.Device, r.Test.Command, r.Caveats)
		}
	}
	e, err := p.Explain("s", "", "xe-01", "interface GigabitEthernet1 shutdown", noon)
	if err != nil || e.Outcome.Permit || e.Outcome.Reason != "no_rule_matched" ||
		!slices.Equal(e.Outcome.Vector, []string{"interface", "GigabitEthernet", "1", "shutdown"}) {
		t.Fatalf("explain: %+v %v", e.Outcome, err)
	}
	var found []string
	for _, f := range p.Lint() {
		if f.Kind == FindingPermitJoinedName {
			found = append(found, f.Message)
		}
	}
	if len(found) != 1 || !strings.Contains(found[0], `role "joined": permit "interface GigabitEthernet1 **" on cisco_iosxe`) ||
		!strings.Contains(found[0], "never matches on cisco_iosxe") || !strings.Contains(found[0], "write `GigabitEthernet 1`") {
		t.Fatalf("lint: %q", found)
	}
}
