package l84

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOverrideLongHasTheNamedShape(t *testing.T) {
	out, err := Override("long", []Secret{{"key", "/h/key"}, {"tacacs_v2", "/h/v2"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Secrets []map[string]any `yaml:"secrets"`
		} `yaml:"services"`
		Secrets map[string]map[string]string `yaml:"secrets"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, svc := range []string{"port49d", "probe"} {
		got := doc.Services[svc].Secrets
		if len(got) != 2 || got[0]["source"] != "key" || got[0]["uid"] != "0" || got[0]["gid"] != "65532" || got[0]["target"] != "/run/secrets/key" {
			t.Errorf("%s: %v, want the long entries with uid \"0\", gid \"65532\"", svc, got)
		}
		// mode is the octal 0440: YAML 1.1 and compose read it as 288, yaml.v3 as the string
		if m := got[0]["mode"]; m != 288 && m != "0440" {
			t.Errorf("%s: mode %v, want 0440", svc, m)
		}
	}
	if doc.Secrets["key"]["file"] != "/h/key" || doc.Secrets["tacacs_v2"]["file"] != "/h/v2" {
		t.Errorf("secrets: %v", doc.Secrets)
	}
}

func TestOverrideShortNamesOnlyTheSecret(t *testing.T) {
	out, err := Override("short", []Secret{{"key", "/h/key"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "uid") || strings.Contains(out, "mode: 0") || !strings.Contains(out, "      - key\n") {
		t.Errorf("the short syntax carries options or lacks the bare name:\n%s", out)
	}
}

func TestOverrideRefusesWhatItCannotWriteSafely(t *testing.T) {
	for _, s := range []Secret{{"", "/h/x"}, {"a b", "/h/x"}, {"a", "relative"}, {"a", "/h/\"x"}, {"a/b", "/h/x"}} {
		if _, err := Override("long", []Secret{s}); err == nil {
			t.Errorf("%+v was accepted", s)
		}
	}
	if _, err := Override("medium", []Secret{{"a", "/h/a"}}); err == nil {
		t.Error("a syntax that is neither long nor short was accepted")
	}
	if _, err := Override("long", nil); err == nil {
		t.Error("no secrets was accepted")
	}
}

func TestMayOfferNeedsTheStartAndTheNoRestartCell(t *testing.T) {
	c := func(id, v string) Cell { return Cell{ID: id, Verdict: v} }
	cases := []struct {
		name  string
		cells []Cell
		mech  string
		want  bool
	}{
		{"both pass", []Cell{c("b-long", Pass), c("c-long", Pass)}, "long", true},
		{"start passes, no-restart fails", []Cell{c("b-long", Pass), c("c-long", Fail)}, "long", false},
		{"no-restart passes, start fails", []Cell{c("b-long", Fail), c("c-long", Pass)}, "long", false},
		{"not run", nil, "short", false},
		{"systemd both", []Cell{c("a-host", Pass), c("c-host", Pass)}, "systemd", true},
		{"systemd start only", []Cell{c("a-host", Pass), c("a", Pass), c("c-systemd", Pass)}, "systemd", false},
		{"the other syntax does not count", []Cell{c("b-long", Pass), c("c-long", Pass)}, "short", false},
	}
	for _, tc := range cases {
		if got := MayOffer(tc.cells, tc.mech); got != tc.want {
			t.Errorf("%s: MayOffer = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNoteIsBuiltFromTheCellsAndKeepsUnrunCellsOpen(t *testing.T) {
	cells := []Cell{
		{ID: "b-long", Verdict: Pass, Rows: []Row{{"stat in the container", "0:65532 440"}}},
		{ID: "c-long", Verdict: Fail, Rows: []Row{{"port49d recreated", "yes | the container id changed"}}},
	}
	n := Note(Env{Date: "2026-10-28", Docker: "29.1.3"}, cells)
	for _, want := range []string{
		"| (b) Compose secrets:, long syntax (uid \"0\", gid \"65532\", mode 0440) | PASS |",
		"| (c) Compose, long syntax: a second secrets: entry, no restart | FAIL |",
		"| (a) systemd LoadCredential= against fence.ReadSecret, in the Debian container | NOT RUN |",
		"yes \\| the container id changed",
		"Compose `secrets:`, long syntax: not for a device key (start PASS, no-restart FAIL)",
		"The register row stays open while any cell is NOT RUN.",
		"Compose: not recorded",
	} {
		if !strings.Contains(n, want) {
			t.Errorf("the note lacks %q:\n%s", want, n)
		}
	}
	if !strings.Contains(n, "systemd `LoadCredential=`: unmeasured (start NOT RUN, no-restart NOT RUN)") {
		t.Errorf("a mechanism with a NOT RUN cell is not said to be unmeasured:\n%s", n)
	}
	if strings.Contains(Note(Env{}, []Cell{{ID: "b-long", Verdict: Pass}, {ID: "c-long", Verdict: Pass}}), "long syntax: not for a device key") {
		t.Error("a mechanism whose cells pass is still refused")
	}
}

func TestSaveLoadMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cells.json")
	if err := Save(p, []Cell{{ID: "a", Verdict: Pass, Rows: []Row{{"x", "y"}}}}); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || len(got) != 1 || got[0].Rows[0].Observation != "y" {
		t.Fatalf("%v %v", got, err)
	}
	m := Merge([]Cell{{ID: "a", Verdict: Fail}, {ID: "b-long", Verdict: Pass}}, got)
	if Verdict(m, "a") != Pass || Verdict(m, "b-long") != Pass || len(m) != 2 {
		t.Errorf("merged: %v", m)
	}
}

func TestAnInvalidContainerCellDoesNotDecideWhatTheREADMEMaySay(t *testing.T) {
	cells := []Cell{
		{ID: "a", Verdict: Invalid}, {ID: "c-systemd", Verdict: Invalid},
		{ID: "a-host", Verdict: Pass}, {ID: "c-host", Verdict: Fail},
	}
	if MayOffer(cells, "systemd") {
		t.Error("a host cell that failed (c) still lets the README name LoadCredential=")
	}
	n := Note(Env{}, cells)
	for _, want := range []string{"in the Debian container | INVALID |", "on the runner's systemd with the shipped unit's hardening | PASS |",
		"systemd `LoadCredential=`: not for a device key (start PASS, no-restart FAIL)"} {
		if !strings.Contains(n, want) {
			t.Errorf("the note lacks %q:\n%s", want, n)
		}
	}
}
