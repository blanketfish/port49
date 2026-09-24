package policy

import (
	"strings"
	"testing"
)

// A permit the device refuses in its own parser at the session's level is
// dead: the device never asks port49 about it (spec §12, "Intersection
// checks"). On EOS and IOS-XE at readonly `clear counters` is refused; on
// IOS-XE at operator it is the one command level 7 runs, and `configure
// terminal` is still refused (tests/lab/results/ceiling-*.md). NX-OS refuses
// nothing, so nothing is dead there.
func TestADeadRuleIsReported(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: noc, privilege: readonly, permit: [show **, clear counters]}
  - {name: ops, privilege: operator, permit: [show **, clear counters, configure terminal]}
subjects:
  - {name: a, identity: "user:a@example.com", username: a, token_ttl: 60s}
  - {name: b, identity: "user:b@example.com", username: b, token_ttl: 60s}
grants:
  - {subject: a, scope: all_devices, roles: [noc]}
  - {subject: b, scope: all_devices, roles: [ops]}
`)
	got := findings(p, FindingDeadRule)
	want := []string{
		`role "noc": permit "clear counters" cannot be reached at readonly (priv-lvl=1) on cisco_iosxe`,
		`role "noc": permit "clear counters" cannot be reached at readonly (priv-lvl=1, roles=network-operator) on arista_eos`,
		`role "ops": permit "configure terminal" cannot be reached at operator (priv-lvl=7) on cisco_iosxe`,
	}
	if len(got) != len(want) {
		t.Fatalf("%d findings, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("finding %d: %q, want %q…", i, got[i], want[i])
		}
	}
	if !strings.Contains(got[2], "tests/lab/results/ceiling-cisco_iosxe.md") {
		t.Errorf("the finding cites the note: %q", got[2])
	}
}

// A subject port49 confines at a level whose device role, on its own, is
// every command is exposed when the device falls back to local (spec §6,
// §12): it is named with what port49 permits it and what the fallback gives.
// A subject port49 permits everything is not, and neither is a level the
// fallback does not widen.
func TestAFallbackExposureIsReported(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: backup, privilege: admin, permit: [show **]}
  - {name: root, privilege: admin, permit: ["**"]}
  - {name: noc, privilege: readonly, permit: [show **]}
subjects:
  - {name: svc_oxidized, identity: "app:oxidized", username: oxidized, token_ttl: 60s}
  - {name: admins, identity: "user:a@example.com", username: a, token_ttl: 60s}
  - {name: noc, identity: "user:n@example.com", username: n, token_ttl: 60s}
grants:
  - {subject: svc_oxidized, scope: all_devices, roles: [backup]}
  - {subject: admins, scope: all_devices, roles: [root]}
  - {subject: noc, scope: all_devices, roles: [noc]}
`)
	got := findings(p, FindingFallbackExposure)
	if len(got) != 3 {
		t.Fatalf("one per platform with a fallback, for svc_oxidized alone: %q", got)
	}
	for i, platformName := range []string{"cisco_iosxe", "arista_eos", "cisco_nxos"} {
		if !strings.HasPrefix(got[i], `subject "svc_oxidized" at admin (`) || !strings.Contains(got[i], ") on "+platformName+
			": port49's rules confine it to show **, and if port49 cannot answer") {
			t.Errorf("%q", got[i])
		}
	}
	if !strings.Contains(got[1], "it gets network-admin: every command, configuration included") {
		t.Errorf("%q", got[1])
	}
}

// The exposure lists the composition's permits unquoted, where the printer's
// quote redaction cannot reach them, so it redacts them itself: a permit with
// a value redaction hides reads «redacted» (spec §5.8).
func TestAFallbackExposureRedactsThePermits(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: snmp, privilege: admin, permit: [show **, snmp-server community public **]}
subjects:
  - {name: svc, identity: "app:svc", username: svc, token_ttl: 60s}
grants:
  - {subject: svc, scope: all_devices, roles: [snmp]}
`)
	got := findings(p, FindingFallbackExposure)
	if len(got) == 0 {
		t.Fatal("no exposure reported")
	}
	for _, f := range got {
		if strings.Contains(f, "public") || !strings.Contains(f, "snmp-server community «redacted» **") {
			t.Errorf("%q", f)
		}
	}
}
