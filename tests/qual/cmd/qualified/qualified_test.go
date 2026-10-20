package main

import (
	"os"
	"path/filepath"
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
	if c := command(g, true); c != "— (L18)" {
		t.Fatalf("marker and no command steps: %s", c)
	}
	if s := status([]string{"tcp"}, g, true); s != "qualified" {
		t.Fatalf("a recorded not-applicable cell does not count against qualified: %s", s)
	}
	if c := command(g, false); c != "no" {
		t.Fatalf("no marker: absence is never not-applicable: %s", c)
	}
	if s := status([]string{"tcp"}, g, false); s != "partial" {
		t.Fatalf("%s", s)
	}
	denyOnly := golden(devicemock.GoldenStep{Step: "command_denied", Event: "author_error"}, stop)
	if c := command(denyOnly, true); c != "no" {
		t.Fatalf("a marker does not excuse command steps the golden holds: %s", c)
	}
	if c := command(golden(permitted, denied, stop), true); c != "yes" {
		t.Fatalf("measured command steps win over the marker: %s", c)
	}
}

// repoWith is a repository root holding one profile, copied from the fixtures with
// its golden path and gaps set, and the fixture notes unless withNotes is false.
func repoWith(t *testing.T, g devicemock.Golden, gap, withNotes bool) string {
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
		s = strings.Replace(s, "engine_gaps: []", `engine_gaps: [{id: command_authorization_not_sent, what: "L18", sources: [{note: tests/lab/results/L99-fixture_junos.md, register: L99}]}]`, 1)
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
