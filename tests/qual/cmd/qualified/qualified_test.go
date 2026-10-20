package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/devicemock"
)

const fixtures = "../../../../internal/devicemock/testdata"

func TestTheCommittedListIsTheGeneratedOne(t *testing.T) {
	got, err := Build("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile("../../../../docs/qualified-platforms.md")
	if got != string(want) {
		t.Fatal("docs/qualified-platforms.md is stale: run make qualified-platforms")
	}
}

func golden(steps ...devicemock.GoldenStep) devicemock.Golden {
	return devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{"token_login": {Outcome: "login_ok", Steps: steps}}}
}

var (
	permitted = devicemock.GoldenStep{Step: "command_permitted", Event: "author_pass_add"}
	denied    = devicemock.GoldenStep{Step: "command_denied", Event: "author_fail"}
	stop      = devicemock.GoldenStep{Step: "account_stop", Event: "acct_success"}
)

func TestStatusFromTheGolden(t *testing.T) {
	g := golden(permitted, denied, stop)
	if s := status([]string{"tcp"}, g, false); s != "qualified" {
		t.Fatalf("%s", s)
	}
	g.PendingLab = true
	if s := status([]string{"tcp"}, g, false); s != "re-vet pending" {
		t.Fatalf("%s", s)
	}
	g.PendingLab = false
	g.Scenarios["token_login"] = devicemock.GoldenScenario{Outcome: "login_refused"}
	if s := status([]string{"tcp"}, g, false); s != "partial" {
		t.Fatalf("%s", s)
	}
}

func TestTLSCellNeedsTheTLSLogin(t *testing.T) {
	g := golden(permitted, denied, stop)
	if c := tlsCell([]string{"tcp"}, g); c != "—" {
		t.Fatalf("no tls transport: %s", c)
	}
	if c := tlsCell([]string{"tcp", "tls"}, g); c != "no" {
		t.Fatalf("tls listed but no tls_token_login: %s", c)
	}
	g.Scenarios["tls_token_login"] = devicemock.GoldenScenario{Outcome: "login_ok"}
	if c := tlsCell([]string{"tcp", "tls"}, g); c != "yes" {
		t.Fatalf("%s", c)
	}
	g.Scenarios["tls_token_login"] = devicemock.GoldenScenario{Outcome: "login_refused"}
	if s := status([]string{"tcp", "tls"}, g, false); s != "partial" {
		t.Fatalf("a refused tls login is partial: %s", s)
	}
}

// Junos sends no per-command authorization (L18): the cell is not applicable only
// when the profile records it, and a profile that merely lacks the steps reads no.
func TestCommandAuthorizationNotApplicableNeedsTheMarker(t *testing.T) {
	g := golden(stop)
	if c := command(g, true, "L18"); c != "— (L18)" {
		t.Fatalf("marker and no command steps: %s", c)
	}
	if s := status([]string{"tcp"}, g, true); s != "qualified" {
		t.Fatalf("a recorded not-applicable cell does not count against qualified: %s", s)
	}
	if c := command(g, false, ""); c != "no" {
		t.Fatalf("no marker: absence is never not-applicable: %s", c)
	}
	if s := status([]string{"tcp"}, g, false); s != "partial" {
		t.Fatalf("%s", s)
	}
	denyOnly := golden(devicemock.GoldenStep{Step: "command_denied", Event: "author_error"}, stop)
	if c := command(denyOnly, true, "L18"); c != "no" {
		t.Fatalf("a marker does not excuse command steps the golden holds: %s", c)
	}
	if c := command(golden(permitted, denied, stop), true, "L18"); c != "yes" {
		t.Fatalf("measured command steps win over the marker: %s", c)
	}
}

// repoWith is a repository root holding one profile, copied from the fixtures with
// its golden path and gaps set, and the fixture notes unless withNotes is false.
func repoWith(t *testing.T, g devicemock.Golden, gap, withNotes bool, edits ...func(string) string) string {
	dir := t.TempDir()
	if withNotes {
		notes := filepath.Join(dir, "tests/lab/results")
		os.MkdirAll(notes, 0o755)
		ents, _ := os.ReadDir(filepath.Join(fixtures, "tests/lab/results"))
		for _, e := range ents {
			raw, _ := os.ReadFile(filepath.Join(fixtures, "tests/lab/results", e.Name()))
			os.WriteFile(filepath.Join(notes, e.Name()), raw, 0o600)
		}
	}
	raw, err := os.ReadFile(filepath.Join(fixtures, "profiles/fixture_junos.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(raw), `golden: ""`, "golden: tests/qual/golden/juniper_junos/1.0.json", 1)
	if gap {
		s = strings.Replace(s, "engine_gaps: []", `engine_gaps: [{id: command_authorization_not_sent, what: "the device sends none (L18)", sources: [{note: tests/lab/results/L99-fixture_junos.md, register: L99}]}]`, 1)
	}
	for _, e := range edits {
		s = e(s)
	}
	os.MkdirAll(filepath.Join(dir, "tests/qual/profiles/juniper_junos"), 0o755)
	os.WriteFile(filepath.Join(dir, "tests/qual/profiles/juniper_junos/1.0.yaml"), []byte(s), 0o600)
	os.MkdirAll(filepath.Join(dir, "tests/qual/golden/juniper_junos"), 0o755)
	if err := devicemock.WriteGolden(filepath.Join(dir, "tests/qual/golden/juniper_junos/1.0.json"), g); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestARowNeedsItsNotes(t *testing.T) {
	dir := repoWith(t, golden(stop), true, false)
	if _, err := Build(dir); err == nil || !strings.Contains(err.Error(), "L99-fixture_junos.md") {
		t.Fatalf("a profile whose note is missing makes no row: the build fails naming it: %v", err)
	}
}

func TestARowForJunosReadsQualifiedOnlyWithTheMarker(t *testing.T) {
	for _, tc := range []struct {
		gap  bool
		want string
	}{{true, "| Juniper | Junos | 1.0 | yes | — | — (L18) | yes | yes | qualified |"}, {false, "| Juniper | Junos | 1.0 | yes | — | no | yes | yes | partial |"}} {
		got, err := Build(repoWith(t, golden(stop), tc.gap, true))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, tc.want+"\n") {
			t.Fatalf("gap=%v: want row %q in:\n%s", tc.gap, tc.want, got)
		}
	}
}

func TestAMissingGoldenFailsTheBuild(t *testing.T) {
	dir := repoWith(t, golden(stop), true, true)
	os.Remove(filepath.Join(dir, "tests/qual/golden/juniper_junos/1.0.json"))
	if _, err := Build(dir); err == nil {
		t.Fatal("a profile without its golden makes no row")
	}
}

func rowWith(t *testing.T, g devicemock.Golden, edits ...func(string) string) string {
	t.Helper()
	got, err := Build(repoWith(t, g, false, true, edits...))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func replace(old, new string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, old) {
			panic("stale replace: " + old)
		}
		return strings.Replace(s, old, new, 1)
	}
}

// A TLS-only platform has no 49 cell, and its command and accounting cells read
// from tls_token_login.
func TestATLSOnlyRowReadsTheTLSLogin(t *testing.T) {
	g := devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{
		"tls_token_login": {Outcome: "login_ok", Steps: []devicemock.GoldenStep{permitted, denied, stop}}}}
	got := rowWith(t, g, replace("transports: [tcp]", "transports: [tls]"), replace("scenarios: [token_login, wrong_credential, store_unavailable]", "scenarios: [tls_token_login]"))
	want := "| Juniper | Junos | 1.0 | — | yes | yes | yes | yes | qualified |\n"
	if !strings.Contains(got, want) {
		t.Fatalf("want %q in:\n%s", want, got)
	}
}

func TestTheGenericPlatformIsNamedByItsLabPlatform(t *testing.T) {
	got := rowWith(t, golden(permitted, denied, stop), replace("platform: juniper_junos", "platform: generic"), replace("lab_platform: fixture_junos", "lab_platform: cisco_xrd"))
	if !strings.Contains(got, "| Cisco | IOS XR (XRd) | 1.0 | yes |") {
		t.Fatalf("generic/cisco_xrd:\n%s", got)
	}
}

func TestAnUnmappedPlatformFailsTheBuild(t *testing.T) {
	_, err := Build(repoWith(t, golden(stop), false, true, replace("platform: juniper_junos", "platform: generic"), replace("lab_platform: fixture_junos", "lab_platform: unlisted_os")))
	if err == nil || !strings.Contains(err.Error(), "generic/unlisted_os") {
		t.Fatalf("an unmapped platform makes no row: the build fails naming it: %v", err)
	}
}

func TestVersionsSortNumerically(t *testing.T) {
	vs := []string{"10.1", "9.3", "9.10", "23.4R2-S2.1", "9.3.1"}
	slices.SortFunc(vs, compareVersions)
	want := []string{"9.3", "9.3.1", "9.10", "10.1", "23.4R2-S2.1"}
	if !slices.Equal(vs, want) {
		t.Fatalf("got %v, want %v", vs, want)
	}
}

// The command cell cites the register its own gap names, not Junos's: SR Linux's gap says L76
// cell b. An operator-facing gap (id operator_...) is printed under the table.
func TestTheCommandCellCitesItsOwnGapAndOperatorGapsArePrinted(t *testing.T) {
	edit := func(s string) string {
		s = strings.Replace(s, "the device sends none (L18)", "the device sends none (L76 cell b)", 1)
		return strings.Replace(s, "engine_gaps: [{", `engine_gaps: [{id: operator_policy_required, what: "logins need the priv-lvl policy block", sources: [{note: tests/lab/results/L99-fixture_junos.md, register: L99}]}, {`, 1)
	}
	got, err := Build(repoWith(t, golden(stop), true, true, edit))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| yes | — | — (L76 cell b) | yes | yes | qualified |", "## What an operator must do", "- **Juniper 1.0**: logins need the priv-lvl policy block"} {
		if !strings.Contains(got, want) {
			t.Fatalf("want %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "(L18)") {
		t.Fatalf("a Junos citation on another platform:\n%s", got)
	}
}
