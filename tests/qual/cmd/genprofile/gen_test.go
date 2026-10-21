package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/devicemock"
)

const fixture = "testdata/QUAL-1.0-fixture_junos"

func TestGenerateTheFixture(t *testing.T) {
	p, g, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	s := p.Stimulus
	if s.Steps[0].Fields.AuthenType != "pap" || s.Steps[0].MinorVersion != 1 || s.TLS.FlightDelay != 5*time.Second ||
		s.Connections.Mode != "per_step" || g.Scenarios["token_login"].Outcome != "login_ok" {
		t.Fatalf("%+v %+v", s, g)
	}
	if s.TLS.ClientHello.Extensions[len(s.TLS.ClientHello.Extensions)-1] == 41 {
		t.Fatal("the hello is a full handshake's (psk_identities 0), never a resumption's")
	}
	if err := p.Validate("testdata"); err != nil {
		t.Fatalf("a generated profile must load: %v", err)
	}
}

// Through Load, not only Validate: Load's credential check sees the written
// YAML, so a 40-hex commit or any hash that slipped in fails here (re-review C-A).
func TestAGeneratedProfileLoads(t *testing.T) {
	p, _, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := writeProfile(path, p, fixture); err != nil {
		t.Fatal(err)
	}
	if _, err := devicemock.Load(path, "testdata"); err != nil {
		t.Fatalf("a generated profile, as written, must load: %v", err)
	}
	if len(p.Vetted.Commit) != 12 {
		t.Fatalf("commits are recorded as 12 hex characters (git rev-parse --short=12): %q", p.Vetted.Commit)
	}
}

// The generated golden has every scenario, each in the shape Play plays it,
// and Judge passes a transcript of exactly that shape: so TestQual's verdict
// on a generated profile turns on port49's replies, never on a golden built
// to the wrong scenario (re-review I-G).
func TestTheGoldenCoversEveryScenarioInPlayedOrder(t *testing.T) {
	p, g, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"token_login", "wrong_credential", "store_unavailable", "single_connection",
		"tls_token_login", "tls_store_unavailable", "tls_unknown_ca", "flight_delay"}
	if !slices.Equal(p.Scenarios, want) {
		t.Fatalf("scenarios %v, want all eight", p.Scenarios)
	}
	for _, sc := range want {
		gs, ok := g.Scenarios[sc]
		if !ok || gs.Outcome == "" {
			t.Fatalf("%s: no golden", sc)
		}
		var names []string
		for _, s := range gs.Steps {
			names = append(names, s.Step)
		}
		// All of them when the play runs to the end; a prefix when a reaction stops it.
		played := devicemock.PlayedSteps(p, sc)
		if len(names) > len(played) || !slices.Equal(names, played[:len(names)]) ||
			(gs.Outcome == "login_ok" && len(names) != len(played)) {
			t.Fatalf("%s: golden steps %v, Play plays %v", sc, names, played)
		}
		tr := devicemock.Transcript{Scenario: sc, Outcome: gs.Outcome}
		for _, s := range gs.Steps {
			tr.Steps = append(tr.Steps, devicemock.StepResult{Step: s.Step, Event: s.Event, Args: s.Args})
		}
		if fails, _ := devicemock.Judge(tr, gs); len(fails) != 0 {
			t.Fatalf("%s: %q", sc, fails)
		}
	}
	tl := g.Scenarios["token_login"]
	if len(tl.Steps) != 6 || tl.Steps[3].Step != "command_denied" || tl.Steps[3].Event != "author_fail" || tl.Steps[5].Event != "acct_success" {
		t.Fatalf("token_login is the union of four lab cells, in step order: %+v", tl.Steps)
	}
	if u := g.Scenarios["tls_unknown_ca"]; u.Outcome != "handshake_refused" || u.Steps[0].Step != "login" || u.Steps[0].Event != "tls_refused" {
		t.Fatalf("tls_unknown_ca is the class event on the login: %+v", u)
	}
	if fd, tls := g.Scenarios["flight_delay"], g.Scenarios["tls_token_login"]; fd.Outcome != tls.Outcome || fd.Steps[0].Event != tls.Steps[0].Event {
		t.Fatalf("flight_delay copies tls_token_login's login: %+v %+v", fd, tls)
	}
	if o := g.Scenarios["store_unavailable"].Outcome; o != "falls_to_local" {
		t.Fatalf("a break-glass store_unavailable ends falls_to_local: %q", o)
	}
	for _, s := range p.Stimulus.Steps {
		if s.Port == "unknown" {
			t.Fatal("an account step took another channel's port; steps reads the login's own records")
		}
	}
}

func TestGeneratedReactionsCiteTheRunsOwnNote(t *testing.T) {
	p, _, _ := Generate(fixture, "testdata")
	if len(p.Reactions) == 0 {
		t.Fatal("no reactions pre-filled")
	}
	for _, r := range p.Reactions {
		if r.Status == "measured" && (len(r.Sources) == 0 || !strings.Contains(r.Sources[0].Note, "QUAL-1.0-fixture_junos")) {
			t.Fatalf("a pre-filled measured reaction cites the run's own note: %+v", r)
		}
	}
}

func copyFixture(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "QUAL-1.0-fixture_junos")
	if err := os.CopyFS(dst, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	return dst
}

// editRecords rewrites decisions.jsonl through f; f returns false to drop a record.
func editRecords(t *testing.T, dir string, f func(map[string]any) bool) {
	t.Helper()
	path := filepath.Join(dir, "decisions.jsonl")
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if f(m) {
			b, _ := json.Marshal(m)
			out = append(out, string(b))
		}
	}
	in.Close()
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// editRun rewrites run.json through f.
func editRun(t *testing.T, dir string, f func(map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, "run.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, _ = json.Marshal(m)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateRefusesForbiddenKeys(t *testing.T) {
	dir := copyFixture(t)
	f, _ := os.OpenFile(filepath.Join(dir, "decisions.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"event":"redeem","auth":{"credential_sha256":"deadbeefdeadbeefdeadbeef"}}` + "\n")
	f.Close()
	_, _, err := Generate(dir, "testdata")
	if err == nil || !strings.Contains(err.Error(), "credential_sha256") {
		t.Fatal("evidence holding a credential hash is refused, never filtered quietly")
	}
	if strings.Contains(err.Error(), "deadbeef") {
		t.Fatalf("the refusal names the key, never the value: %v", err)
	}
}

func TestGenerateNeverReadsACapture(t *testing.T) {
	dir := copyFixture(t)
	os.WriteFile(filepath.Join(dir, "x.pcap"), []byte("not read"), 0o600)
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "x.pcap") {
		t.Fatal("a capture in the evidence directory is refused: profiles never come from bodies")
	}
}

func TestStimulusEqualIgnoresReviewedParts(t *testing.T) {
	a, _, _ := Generate(fixture, "testdata")
	b, _, _ := Generate(fixture, "testdata")
	b.Reactions, b.Acceptance, b.Vetted.Commit = nil, nil, "other"
	if !StimulusEqual(a, b) {
		t.Fatal("-check compares the generated stimulus only: reviewed parts and the header may differ")
	}
	b.Stimulus.Steps[0].Port = "tty9"
	if StimulusEqual(a, b) {
		t.Fatal("a changed stimulus is a difference")
	}
}

// (a) command_permitted and command_denied come from one login and share a
// start time; a window ends at the next strictly later start, so their records
// are not lost to an empty window and still land in token_login.
func TestTiedCellsShareAWindowAndTheirRecordsReachTokenLogin(t *testing.T) {
	var r run
	if err := readJSON(filepath.Join(fixture, "run.json"), &r); err != nil {
		t.Fatal(err)
	}
	if r.Cells["command_permitted"] != r.Cells["command_denied"] {
		t.Fatal("the fixture must tie the two command cells")
	}
	win, err := cellWindows(r.Cells)
	if err != nil {
		t.Fatal(err)
	}
	cp, cd := win["command_permitted"], win["command_denied"]
	if cp != cd || cp.end.IsZero() || !cp.end.After(cp.start) {
		t.Fatalf("tied cells share one non-empty window: %+v %+v", cp, cd)
	}
	if !cp.end.Equal(win["accounting"].start) {
		t.Fatalf("the tied window ends at the next strictly later start: %v", cp.end)
	}
	_, g, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range g.Scenarios["token_login"].Steps {
		got = append(got, s.Step+":"+s.Event)
	}
	if !slices.Contains(got, "command_permitted:author_pass_add") || !slices.Contains(got, "command_denied:author_fail") {
		t.Fatalf("the tied cells' records landed in token_login: %v", got)
	}
}

// (b) the connection pattern counts the union of the scenario's cells' files.
func TestConnPatternCountsTheUnionOfTheScenariosCells(t *testing.T) {
	p, _, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if p.Stimulus.Connections.Mode != "per_step" || p.Stimulus.Connections.SingleConnectFlag {
		t.Fatalf("six connections over four cells, none of them past two in token_login alone: %+v", p.Stimulus.Connections)
	}
	// Only token_login's two connections remain; the single_connection cell carried every step on one.
	dir := copyFixture(t)
	remove(t, dir, "command_permitted.conns.json", "command_denied.conns.json", "accounting.conns.json")
	p, _, err = Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if p.Stimulus.Connections.Mode != "single_connection" || !p.Stimulus.Connections.SingleConnectFlag {
		t.Fatalf("a device that reused one connection for all steps: %+v", p.Stimulus.Connections)
	}
}

// (c) neither condition met: the mode stays empty and Load fails loudly.
func TestConnPatternWithNeitherConditionLeavesTheModeEmpty(t *testing.T) {
	dir := copyFixture(t)
	remove(t, dir, "command_permitted.conns.json", "command_denied.conns.json")
	// Four connections in all, and a single connection too short to carry every step.
	short, _ := json.Marshal([]conn{{Plain: []plainHeader{{Version: 0xc1, Type: 1}, {Version: 0xc0, Type: 2}}}})
	os.WriteFile(filepath.Join(dir, "single_connection.conns.json"), short, 0o644)
	p, _, err := Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if p.Stimulus.Connections.Mode != "" {
		t.Fatalf("a mode is never guessed: %q", p.Stimulus.Connections.Mode)
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := writeProfile(path, p, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := devicemock.Load(path, "testdata"); err == nil || !strings.Contains(err.Error(), "connections.mode") {
		t.Fatalf("Load must refuse the empty mode, naming it: %v", err)
	}
}

// (d) a step's priv_lvl is the validated record's, never a default.
func TestStepPrivLvlIsTheRecordsOwn(t *testing.T) {
	p, _, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Stimulus.Steps {
		if s.Fields.PrivLvl != 1 {
			t.Fatalf("%s: priv_lvl %d; NX-OS asks at 1 and the record says 1", s.Name, s.Fields.PrivLvl)
		}
	}
	dir := copyFixture(t)
	editRecords(t, dir, func(m map[string]any) bool {
		if m["event"] == "authorize_command" && m["verdict"] == "permit" {
			m["packet_fields"].(map[string]any)["priv_lvl"] = 7
		}
		return true
	})
	p, _, err = Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]uint8{}
	for _, s := range p.Stimulus.Steps {
		got[s.Name] = s.Fields.PrivLvl
	}
	if got["command_permitted"] != 7 || got["login"] != 1 || got["command_denied"] != 1 {
		t.Fatalf("each step carries its own record's priv_lvl: %v", got)
	}
}

func TestAStepWithoutPrivLvlIsRefused(t *testing.T) {
	dir := copyFixture(t)
	editRecords(t, dir, func(m map[string]any) bool {
		if m["event"] == "authorize_session" {
			delete(m["packet_fields"].(map[string]any), "priv_lvl")
		}
		return true
	})
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "authorize_session") {
		t.Fatalf("a missing priv_lvl is an error naming the step, never a default: %v", err)
	}
}

// (e) Junos sends no per-command authorization (L18): the command cells are
// not_applicable, no authorize_command record exists, and no command step is emitted.
func TestJunosEvidenceWithoutCommandCellsEmitsNoCommandSteps(t *testing.T) {
	for _, dropStarts := range []bool{false, true} {
		dir := copyFixture(t)
		editRecords(t, dir, func(m map[string]any) bool { return m["event"] != "authorize_command" })
		editRun(t, dir, func(m map[string]any) {
			for _, c := range []string{"command_permitted", "command_denied"} {
				m["results"].(map[string]any)[c] = "not_applicable"
				if dropStarts {
					delete(m["cells"].(map[string]any), c)
				}
			}
		})
		p, g, err := Generate(dir, "testdata")
		if err != nil {
			t.Fatalf("dropStarts=%v: %v", dropStarts, err)
		}
		var names []string
		for _, s := range p.Stimulus.Steps {
			names = append(names, s.Name)
		}
		if want := []string{"login", "authorize_session", "account_start", "account_stop"}; !slices.Equal(names, want) {
			t.Fatalf("dropStarts=%v: steps %v, want %v", dropStarts, names, want)
		}
		if tl := g.Scenarios["token_login"]; tl.Outcome != "login_ok" || len(tl.Steps) != 4 {
			t.Fatalf("dropStarts=%v: %+v", dropStarts, tl)
		}
		if err := p.Validate("testdata"); err != nil {
			t.Fatalf("dropStarts=%v: %v", dropStarts, err)
		}
		if !hasGap(p, "command_authorization_not_sent") {
			t.Fatalf("dropStarts=%v: the absent command steps are recorded as an engine gap, never left to inference: %+v", dropStarts, p.EngineGaps)
		}
	}
}

// Without not_applicable, a missing command record is an error naming the step.
func TestMissingCommandRecordsFailWhenTheCellIsNotNotApplicable(t *testing.T) {
	dir := copyFixture(t)
	editRecords(t, dir, func(m map[string]any) bool { return m["event"] != "authorize_command" })
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "command_permitted") {
		t.Fatalf("expected an error naming command_permitted: %v", err)
	}
}

// (f) a rule is measured only when a note for the same firmware measured it;
// genprofile measures none, so every generated rule is unmeasured and warns, never gates.
func TestGeneratedAcceptanceRulesAreUnmeasuredAndNeverGate(t *testing.T) {
	p, _, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Acceptance) == 0 {
		t.Fatal("the priv_lvl_range rule is pre-filled")
	}
	for _, a := range p.Acceptance {
		if a.Status != "unmeasured" {
			t.Fatalf("%s: a generated rule is unmeasured until a note for this firmware measures it: %q", a.ID, a.Status)
		}
	}
	gate, warn := devicemock.Check(p.Acceptance, "authorize_session", [][]byte{[]byte("priv-lvl=15")})
	if len(gate) != 0 || len(warn) != 1 {
		t.Fatalf("an unmeasured rule warns and never gates: %v %v", gate, warn)
	}
}

// (g) a summary from before compress_certificate_algorithms existed means "not
// offered"; one that has the field carries it into the hello.
func TestCompressCertificateAlgorithmsMissingMeansNotOffered(t *testing.T) {
	p, _, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Stimulus.TLS.ClientHello.CompressCertAlgs) != 0 {
		t.Fatalf("an old summary offers none: %v", p.Stimulus.TLS.ClientHello.CompressCertAlgs)
	}
	dir := copyFixture(t)
	path := filepath.Join(dir, "tls_token_login.tls.json")
	b, _ := os.ReadFile(path)
	var cs []map[string]any
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	cs[0]["client_hello"].(map[string]any)["compress_certificate_algorithms"] = []int{2}
	b, _ = json.Marshal(cs)
	os.WriteFile(path, b, 0o644)
	p, _, err = Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Stimulus.TLS.ClientHello.CompressCertAlgs; !slices.Equal(got, []uint16{2}) {
		t.Fatalf("a present field is carried: %v", got)
	}
}

func TestTLSUnknownCARequiresPort49sOwnRecord(t *testing.T) {
	dir := copyFixture(t)
	editRecords(t, dir, func(m map[string]any) bool { return m["event"] != "unvalidated" })
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "tls_unknown_ca") {
		t.Fatalf("expected an error naming the cell: %v", err)
	}
}

func TestARecordWithoutATimestampIsRefused(t *testing.T) {
	dir := copyFixture(t)
	editRecords(t, dir, func(m map[string]any) bool { delete(m, "ts"); return true })
	_, _, err := Generate(dir, "testdata")
	if err == nil || !strings.Contains(err.Error(), "ts") {
		t.Fatalf("expected a ts error: %v", err)
	}
}

func TestAFailedCellRefusesTheRun(t *testing.T) {
	dir := copyFixture(t)
	editRun(t, dir, func(m map[string]any) { m["results"].(map[string]any)["accounting"] = "fail" })
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "accounting") {
		t.Fatalf("expected an error naming accounting: %v", err)
	}
}

// Over TLS alone the header is hidden: an authen step's minor version is
// inferred (1 for pap, chap, mschap and mschapv2) and each inferred step is an
// engine gap.
func TestMinorVersionOverTLSAloneIsInferredAndRecordedAsAGap(t *testing.T) {
	for _, at := range []string{"pap", "mschapv2"} {
		dir := copyFixture(t)
		remove(t, dir, "token_login.conns.json", "command_permitted.conns.json", "command_denied.conns.json",
			"accounting.conns.json", "single_connection.conns.json", "wrong_credential.conns.json", "store_unavailable.conns.json")
		editRun(t, dir, func(m map[string]any) { m["transports"] = []string{"tls"} })
		editRecords(t, dir, func(m map[string]any) bool {
			if pf, ok := m["packet_fields"].(map[string]any); ok && m["event"] == "redeem" {
				pf["authen_type"] = at
			}
			return true
		})
		p, _, err := Generate(dir, "testdata")
		if err != nil {
			t.Fatal(err)
		}
		if len(p.EngineGaps) != 6 || p.EngineGaps[0].ID != "minor_version_inferred_over_tls" {
			t.Fatalf("one gap per inferred step: %+v", p.EngineGaps)
		}
		for _, s := range p.Stimulus.Steps {
			if want := uint8(map[bool]int{true: 1}[s.Name == "login"]); s.MinorVersion != want {
				t.Fatalf("%s (%s): minor %d, want %d", s.Name, at, s.MinorVersion, want)
			}
		}
	}
}

// A run with a tcp transport has the headers; one missing is an error naming
// the step and the file, never an inference.
func TestMinorVersionOverTCPNeverInfers(t *testing.T) {
	dir := copyFixture(t)
	remove(t, dir, "accounting.conns.json", "single_connection.conns.json")
	_, _, err := Generate(dir, "testdata")
	if err == nil || !strings.Contains(err.Error(), "account_start") || !strings.Contains(err.Error(), "accounting.conns.json") {
		t.Fatalf("expected an error naming the step and its conns file: %v", err)
	}
}

// TestQualify writes not_run for the TLS cells on an image with no RFC 9887
// client, and for single_connection on one with no single-connection form.
func TestATCPOnlyRunGenerates(t *testing.T) {
	dir := copyFixture(t)
	remove(t, dir, "tls_token_login.tls.json", "tls_unknown_ca.tls.json")
	editRun(t, dir, func(m map[string]any) {
		m["transports"] = []string{"tcp"}
		for _, c := range []string{"tls_token_login", "tls_store_unavailable", "tls_unknown_ca"} {
			m["results"].(map[string]any)[c] = "not_run"
			delete(m["cells"].(map[string]any), c)
		}
	})
	p, g, err := Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if p.Stimulus.TLS != nil || !slices.Equal(p.Scenarios, []string{"token_login", "wrong_credential", "store_unavailable", "single_connection"}) {
		t.Fatalf("%v %+v", p.Scenarios, p.Stimulus.TLS)
	}
	if len(g.Scenarios) != 4 {
		t.Fatalf("%v", g.Scenarios)
	}
}

func TestASingleConnectionNotRunRunGenerates(t *testing.T) {
	dir := copyFixture(t)
	remove(t, dir, "single_connection.conns.json")
	editRun(t, dir, func(m map[string]any) {
		m["results"].(map[string]any)["single_connection"] = "not_run"
		delete(m["cells"].(map[string]any), "single_connection")
	})
	p, _, err := Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.Scenarios, "single_connection") || p.Stimulus.Connections.Mode != "per_step" {
		t.Fatalf("%v %+v", p.Scenarios, p.Stimulus.Connections)
	}
}

func TestAFailedOrUngradedCellStillRefusesTheRun(t *testing.T) {
	dir := copyFixture(t)
	editRun(t, dir, func(m map[string]any) { delete(m["results"].(map[string]any), "accounting") })
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "accounting") {
		t.Fatalf("a cell with no result is refused: %v", err)
	}
}

// With no observed delay, none is written and the flight_delay scenario is
// not listed; the checklist says so.
func TestNoObservedFlightDelayWritesNoneAndSaysSo(t *testing.T) {
	dir := copyFixture(t)
	path := filepath.Join(dir, "tls_token_login.tls.json")
	b, _ := os.ReadFile(path)
	var cs []map[string]any
	json.Unmarshal(b, &cs)
	for _, c := range cs {
		delete(c, "server_flight_at")
		delete(c, "device_reply_at")
	}
	b, _ = json.Marshal(cs)
	os.WriteFile(path, b, 0o644)
	p, g, err := Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if p.Stimulus.TLS.FlightDelay != 0 || slices.Contains(p.Scenarios, "flight_delay") {
		t.Fatalf("%v %v", p.Stimulus.TLS.FlightDelay, p.Scenarios)
	}
	if _, ok := g.Scenarios["flight_delay"]; ok {
		t.Fatal("no golden for a scenario not listed")
	}
	if c := checklist(p, g); !strings.Contains(c, "no flight delay") {
		t.Fatalf("the checklist says no delay was observed:\n%s", c)
	}
}

func TestStimulusEqualIgnoresTheReviewLeftDefaults(t *testing.T) {
	a, _, _ := Generate(fixture, "testdata")
	b, _, _ := Generate(fixture, "testdata")
	b.Stimulus.TLS.ClientChain, b.Stimulus.TLS.ServerIdentity = "leaf", "ip"
	if !StimulusEqual(a, b) {
		t.Fatal("client_chain and server_identity are set in review")
	}
	if a.Stimulus.TLS.ClientChain != "leaf_and_intermediate" {
		t.Fatal("StimulusEqual must not edit its arguments")
	}
}

// The checklist names steps, events, enums and ids: what the vetter must
// confirm, and nothing from the evidence beyond that.
func TestChecklistListsWhatTheVetterMustCheck(t *testing.T) {
	p, g, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	c := checklist(p, g)
	for _, want := range []string{
		"login authen_pass -> next_step",
		"login authen_fail -> stop (login_refused)",
		"login authen_error -> failover_local (falls_to_local)",
		"measured, pre-filled",
		"priv_lvl_range: priv_lvl_range, unmeasured, tests/lab/results/QUAL-1.0-fixture_junos.md",
		"client_chain=leaf_and_intermediate",
		"server_identity=chain_only",
		"golden token_login: login_ok",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("checklist lacks %q:\n%s", want, c)
		}
	}
	for _, never := range []string{"service=junos-exec", "172.100", "show", "allow-commands"} {
		if strings.Contains(c, never) {
			t.Errorf("checklist leaks evidence %q", never)
		}
	}
}

// The command writes the profile and golden, and -check passes on them and
// fails once the committed stimulus moves.
func TestCheckComparesTheCommittedStimulus(t *testing.T) {
	ev, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatal(err)
	}
	note, err := os.ReadFile(filepath.Join(ev, "..", "tests", "lab", "results", "QUAL-1.0-fixture_junos.md"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	os.MkdirAll("tests/lab/results", 0o755)
	os.WriteFile("tests/lab/results/QUAL-1.0-fixture_junos.md", note, 0o644)
	if err := run1(ev, true); err == nil {
		t.Fatal("-check with no committed profile fails")
	}
	if err := run1(ev, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("tests", "qual", "profiles", "juniper_junos", "1.0.yaml")
	if _, err := os.Stat("tests/qual/golden/juniper_junos/1.0.json"); err != nil {
		t.Fatal(err)
	}
	if err := run1(ev, true); err != nil {
		t.Fatalf("-check on a fresh profile: %v", err)
	}
	b, _ := os.ReadFile(path)
	reviewed := strings.Replace(string(b), "client_chain: leaf_and_intermediate", "client_chain: leaf", 1)
	if reviewed == string(b) {
		t.Fatal("the written profile has no client_chain to review")
	}
	os.WriteFile(path, []byte(reviewed), 0o644)
	if err := run1(ev, true); err != nil {
		t.Fatalf("-check after a reviewed client_chain edit: %v", err)
	}
	os.WriteFile(path, []byte(strings.Replace(reviewed, "port: \"0\"", "port: tty9", 1)), 0o644)
	if err := run1(ev, true); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("-check on a moved stimulus: %v", err)
	}
}

func hasGap(p *devicemock.Profile, id string) bool {
	return slices.ContainsFunc(p.EngineGaps, func(g devicemock.EngineGap) bool { return g.ID == id })
}

func TestACompleteRunCarriesNoCommandAuthorizationGap(t *testing.T) {
	p, _, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if hasGap(p, "command_authorization_not_sent") {
		t.Fatal("command steps were played: no gap")
	}
}

func TestAnAccountRecordWithNoVerdictIsASuccess(t *testing.T) {
	ev, _, err := eventOf(&rec{Event: "account"})
	if err != nil || ev != "acct_success" {
		t.Fatalf("got %q, %v; port49d writes no verdict on an account record", ev, err)
	}
	if _, _, err := eventOf(&rec{Event: "account", Verdict: "permit"}); err == nil {
		t.Fatal("an account record with a verdict is not port49d's: refused, never read as a reply")
	}
}

// perRequestNotSent makes the fixture's tls_token_login what NX-OS 10.6(2)F's
// was (L73 cell a): the login and its accounting arrived over TLS, and no
// authorize_command for the cell's commands did; run.json says not_sent.
func perRequestNotSent(t *testing.T, dir string) {
	t.Helper()
	editRecords(t, dir, func(m map[string]any) bool {
		ts, _ := m["ts"].(string)
		return !(m["event"] == "authorize_command" && strings.HasPrefix(ts, "2026-10-20T12:04:"))
	})
	editRun(t, dir, func(m map[string]any) {
		ca, _ := m["command_authorization"].(map[string]any)
		if ca == nil {
			ca = map[string]any{}
		}
		ca["tls_token_login"] = "not_sent"
		m["command_authorization"] = ca
	})
}

// addTLSSingleConnection gives the fixture a tls_single_connection cell at
// 12:07 whose records are tls_token_login's (with its commands only when sent),
// and its command_authorization. It runs before perRequestNotSent.
func addTLSSingleConnection(t *testing.T, dir, sent string) {
	t.Helper()
	var extra []string
	editRecords(t, dir, func(m map[string]any) bool {
		if ts, _ := m["ts"].(string); strings.HasPrefix(ts, "2026-10-20T12:04:") && (sent == "sent" || m["event"] != "authorize_command") {
			c := map[string]any{}
			for k, v := range m {
				c[k] = v
			}
			c["ts"] = strings.Replace(ts, "12:04:", "12:07:", 1)
			b, _ := json.Marshal(c)
			extra = append(extra, string(b))
		}
		return true
	})
	f, err := os.OpenFile(filepath.Join(dir, "decisions.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(strings.Join(extra, "\n") + "\n")
	f.Close()
	editRun(t, dir, func(m map[string]any) {
		m["cells"].(map[string]any)["tls_single_connection"] = "2026-10-20T12:07:00.000Z"
		m["results"].(map[string]any)["tls_single_connection"] = "pass"
		ca, _ := m["command_authorization"].(map[string]any)
		if ca == nil {
			ca = map[string]any{"tls_token_login": "sent"}
		}
		ca["tls_single_connection"] = sent
		m["command_authorization"] = ca
	})
}

func stepNames(steps []devicemock.GoldenStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Step)
	}
	return out
}

// Review batch 2 I2: per-request TLS with no command authorization is a
// measured device fact citing the run's note, not an engine gap, and the
// tls_token_login golden holds no command step the device never sent.
func TestPerRequestTLSWithNoCommandAuthorizationIsADeviceFact(t *testing.T) {
	dir := copyFixture(t)
	perRequestNotSent(t, dir)
	p, g, err := Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasFact(devicemock.FactTLSPerRequestNoCommands) {
		t.Fatalf("no device fact: %+v", p.DeviceFacts)
	}
	f := p.DeviceFacts[0]
	if f.Status != "measured" || len(f.Sources) != 1 || f.Sources[0].Register != "QUAL" || !strings.Contains(f.What, "(QUAL tls_token_login)") {
		t.Fatalf("%+v", f)
	}
	for _, e := range p.EngineGaps {
		if strings.Contains(e.ID, "tls") || strings.Contains(e.What, "TLS") {
			t.Fatalf("a device fact is no engine gap: %+v", e)
		}
	}
	if got, want := stepNames(g.Scenarios["tls_token_login"].Steps), []string{"login", "authorize_session", "account_start", "account_stop"}; !slices.Equal(got, want) {
		t.Fatalf("tls_token_login golden %v, want %v", got, want)
	}
	if got := stepNames(g.Scenarios["token_login"].Steps); !slices.Contains(got, "command_denied") {
		t.Fatalf("the plain golden keeps its command steps: %v", got)
	}
	if err := p.Validate("testdata"); err != nil {
		t.Fatal(err)
	}
}

// A run whose tls_token_login sent command authorization records no fact.
func TestPerRequestTLSWithCommandAuthorizationRecordsNoFact(t *testing.T) {
	for _, ca := range []any{nil, map[string]any{"tls_token_login": "sent"}} {
		dir := copyFixture(t)
		editRun(t, dir, func(m map[string]any) {
			if ca != nil {
				m["command_authorization"] = ca
			}
		})
		p, g, err := Generate(dir, "testdata")
		if err != nil {
			t.Fatal(err)
		}
		if len(p.DeviceFacts) != 0 || !slices.Contains(stepNames(g.Scenarios["tls_token_login"].Steps), "command_permitted") {
			t.Fatalf("%v: %+v %+v", ca, p.DeviceFacts, g.Scenarios["tls_token_login"])
		}
	}
}

func TestAnUnknownCommandAuthorizationValueIsRefused(t *testing.T) {
	dir := copyFixture(t)
	editRun(t, dir, func(m map[string]any) { m["command_authorization"] = map[string]any{"tls_token_login": "maybe"} })
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "maybe") {
		t.Fatalf("want an error naming the value: %v", err)
	}
}

// The single-connection TLS cell is its own scenario, generated from its own
// window; the per-request fact's text says single-connection carried the
// commands, which an operator acts on.
func TestTLSSingleConnectionIsAScenarioOfItsOwn(t *testing.T) {
	dir := copyFixture(t)
	addTLSSingleConnection(t, dir, "sent")
	perRequestNotSent(t, dir)
	p, g, err := Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Scenarios, "tls_single_connection") {
		t.Fatalf("%v", p.Scenarios)
	}
	sc := g.Scenarios["tls_single_connection"]
	if want := []string{"login", "authorize_session", "command_permitted", "command_denied", "account_start", "account_stop"}; sc.Outcome != "login_ok" || !slices.Equal(stepNames(sc.Steps), want) {
		t.Fatalf("%+v", sc)
	}
	if f := p.DeviceFacts[0].What; !strings.Contains(f, "single-connection") || !strings.Contains(f, "(QUAL tls_single_connection)") {
		t.Fatalf("the fact does not say single-connection carried the commands: %q", f)
	}
	if err := p.Validate("testdata"); err != nil {
		t.Fatal(err)
	}
}

func TestTLSSingleConnectionWithNoCommandsIsAFactToo(t *testing.T) {
	dir := copyFixture(t)
	addTLSSingleConnection(t, dir, "not_sent")
	perRequestNotSent(t, dir)
	p, g, err := Generate(dir, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasFact(devicemock.FactTLSSingleNoCommands) || slices.Contains(stepNames(g.Scenarios["tls_single_connection"].Steps), "command_permitted") {
		t.Fatalf("%+v %+v", p.DeviceFacts, g.Scenarios["tls_single_connection"])
	}
}

// L80's cell is an observation, never a pass (ruling 2026-10-21): genprofile
// accepts its "observed" verdict without refusing the run and records the
// outcome as a measured device fact citing L80's own note. A run without the
// cell says L80 is open; "observed" on a conformance cell is refused.
func TestTheDeniedCommandCellIsAnObservedDeviceFact(t *testing.T) {
	// ran and asked: whether the denied command ran, and whether port49 was asked (review M2).
	for ran, want := range map[string]string{"": "", "true": devicemock.FactTLSPerRequestDeniedRuns, "false": devicemock.FactTLSPerRequestDeniedRefused,
		"false,asked": devicemock.FactTLSPerRequestDeniedByPort49} {
		dir := copyFixture(t)
		perRequestNotSent(t, dir)
		if ran != "" {
			editRun(t, dir, func(m map[string]any) {
				m["denied_command_ran"] = map[string]any{"tls_denied_command": ran == "true"}
				m["denied_command_asked"] = map[string]any{"tls_denied_command": strings.HasSuffix(ran, ",asked")}
				m["cells"].(map[string]any)["tls_denied_command"] = "2026-10-20T12:04:30.000Z"
				m["results"].(map[string]any)["tls_denied_command"] = "observed"
			})
		}
		p, _, err := Generate(dir, "testdata")
		if err != nil {
			t.Fatalf("ran=%q: an observed cell does not refuse the run: %v", ran, err)
		}
		if want == "" {
			if len(p.DeviceFacts) != 1 || !strings.Contains(p.DeviceFacts[0].What, "L80 is open") {
				t.Errorf("no L80 cell: %+v", p.DeviceFacts)
			}
		} else {
			i := slices.IndexFunc(p.DeviceFacts, func(f devicemock.DeviceFact) bool { return f.ID == want })
			if i < 0 {
				t.Fatalf("ran=%q: no %s fact: %+v", ran, want, p.DeviceFacts)
			}
			f := p.DeviceFacts[i]
			if f.Status != "measured" || len(f.Sources) != 1 || f.Sources[0].Register != "L80" ||
				f.Sources[0].Note != "tests/lab/results/L80-fixture_junos.md" {
				t.Errorf("ran=%q: %+v", ran, f)
			}
			if err := p.Validate("testdata"); err != nil {
				t.Errorf("ran=%q: %v", ran, err)
			}
		}
		if slices.Contains(p.Scenarios, "tls_denied_command") {
			t.Errorf("the L80 cell is a register measurement, not a mock scenario: %v", p.Scenarios)
		}
	}
	dir := copyFixture(t)
	editRun(t, dir, func(m map[string]any) { m["results"].(map[string]any)["tls_token_login"] = "observed" })
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "tls_token_login") {
		t.Fatalf("observed is for an observation cell only: %v", err)
	}
}

// The device's key_share groups, when the summary records them (review M4),
// are carried into the hello the probe builds; an older summary has none.
func TestKeyShareGroupsAreCarriedWhenRecorded(t *testing.T) {
	p, _, err := Generate(fixture, "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Stimulus.TLS.ClientHello.KeyShareGroups) != 0 {
		t.Fatalf("an old summary records none: %v", p.Stimulus.TLS.ClientHello.KeyShareGroups)
	}
	dir := copyFixture(t)
	path := filepath.Join(dir, "tls_token_login.tls.json")
	b, _ := os.ReadFile(path)
	var cs []map[string]any
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	cs[0]["client_hello"].(map[string]any)["key_share_groups"] = []int{29}
	b, _ = json.Marshal(cs)
	os.WriteFile(path, b, 0o644)
	if p, _, err = Generate(dir, "testdata"); err != nil {
		t.Fatal(err)
	}
	if got := p.Stimulus.TLS.ClientHello.KeyShareGroups; !slices.Equal(got, []uint16{29}) {
		t.Fatalf("a recorded list is carried: %v", got)
	}
}
