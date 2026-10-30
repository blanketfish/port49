package l82

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestJudgeStart(t *testing.T) {
	for _, c := range []struct {
		name     string
		ready    bool
		restarts int
		want     string
	}{
		{"ready, never restarted", true, 0, Pass},
		{"not ready", false, 0, Fail},
		{"ready but it restarted", true, 1, Fail},
	} {
		if got := JudgeStart(c.ready, c.restarts); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestJudgeWholeMountDelay(t *testing.T) {
	for _, c := range []struct {
		name     string
		appeared bool
		d        time.Duration
		want     string
	}{
		{"inside the bound", true, 95 * time.Second, Pass},
		{"exactly the bound", true, WholeMountWithin, Pass},
		{"a second past it", true, WholeMountWithin + time.Second, Fail},
		{"never appeared", false, 0, Fail},
		{"never appeared, however long it waited", false, time.Hour, Fail},
	} {
		if got := JudgeWholeMountDelay(c.appeared, c.d); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestJudgeSubPath(t *testing.T) {
	for _, c := range []struct {
		name         string
		whole, inSub bool
		want         string
	}{
		{"whole changed, subPath did not: never subPath is confirmed", true, false, Pass},
		{"neither changed: the whole mount is broken too", false, false, Fail},
		{"both changed: the claim is wrong", true, true, Fail},
		{"only the subPath changed", false, true, Fail},
	} {
		if got := JudgeSubPath(c.whole, c.inSub); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestJudgeESO(t *testing.T) {
	ok := ESOResult{SecretGained: true, LoginPassed: true, Delay: 100 * time.Second}
	for _, c := range []struct {
		name string
		mod  func(*ESOResult)
		want string
	}{
		{"all of it", func(*ESOResult) {}, Pass},
		{"exactly the bound", func(r *ESOResult) { r.Delay = ESOWithin }, Pass},
		{"past the bound", func(r *ESOResult) { r.Delay = ESOWithin + time.Second }, Fail},
		{"the Secret never gained the key", func(r *ESOResult) { r.SecretGained, r.LoginPassed = false, false }, Fail},
		{"the Secret gained it but the login never passed", func(r *ESOResult) { r.LoginPassed = false }, Fail},
		{"the container restarted", func(r *ESOResult) { r.Restarted = true }, Fail},
	} {
		r := ok
		c.mod(&r)
		if got := JudgeESO(r); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func cells() []Cell {
	return []Cell{
		{ID: "a", Verdict: Pass, Rows: []Row{{"mount directory", "root 65532 755 directory"}}},
		{ID: "b", Verdict: Pass, Rows: []Row{{"delay", "41s"}}},
		{ID: "c", Verdict: Fail, Rows: []Row{{"whole mount changed", "true"}}},
		{ID: "d", Verdict: Pass, Rows: []Row{{"login delay", "77s"}}},
	}
}

var env = Env{Date: "2026-10-30", Runner: "ubuntu-24.04 20260101.1", Kind: "v0.29.0", NodeImage: "kindest/node:v1.33.1", ESOChart: "2.12.0", ESOApp: "v2.12.0"}

func TestResultsNamesEveryCellVerdictAndVersion(t *testing.T) {
	out, err := Results(env, cells())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# L82", "| (a)", "| (b)", "| (c)", "| (d)", "FAIL", "PASS", "root 65532 755 directory", "41s",
		"2026-10-30", "ubuntu-24.04 20260101.1", "v0.29.0", "kindest/node:v1.33.1", "2.12.0", "v2.12.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("the results lack %q", want)
		}
	}
}

func TestResultsMarksAMissingCellNotRunAndAnEmptyFieldNotRecorded(t *testing.T) {
	out, err := Results(Env{}, cells()[:2])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, NotRun) < 2 {
		t.Errorf("cells c and d were never run and the results do not say NOT RUN:\n%s", out)
	}
	if !strings.Contains(out, "not recorded") {
		t.Error("an empty environment field is not marked not recorded")
	}
}

func TestResultsRefuseAnythingThatLooksLikeAKey(t *testing.T) {
	for _, c := range []struct{ name, obs string }{
		{"a base64 run", "value dGhpcy1pcy1ub3QtYS1rZXktYnV0LWl0LWxvb2tzLWxpa2U9"},
		{"a hex run", "0123456789abcdef0123456789abcdef"},
		{"a token", "token: abc"},
		{"a password", "the password was set"},
	} {
		cs := cells()
		cs[0].Rows = append(cs[0].Rows, Row{"x", c.obs})
		if _, err := Results(env, cs); err == nil {
			t.Errorf("%s: the results were written", c.name)
		}
	}
	// an image digest is not a key
	e := env
	e.NodeImage = "kindest/node:v1.33.1@sha256:050072256b9a903bd914c0b2866828150cb229cea0efe5892e2b644d5dd3b34f"
	if _, err := Results(e, cells()); err != nil {
		t.Errorf("an image digest was refused: %v", err)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cells.json")
	if err := Save(p, cells()); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || len(got) != 4 || got[2].Verdict != Fail {
		t.Fatalf("Load = %v, %v", got, err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the cells file is %v, want 0644: it is uploaded as evidence", fi.Mode())
	}
}

func TestStatLine(t *testing.T) {
	got, err := StatLine("root 65532 440 regular file /run/port49/keys/tacacs_v1")
	if err != nil || got != "root:65532 0440 regular file /run/port49/keys/tacacs_v1" {
		t.Errorf("StatLine = %q, %v", got, err)
	}
	for _, bad := range []string{"", "root 65532", "root 65532 zzz regular file x"} {
		if _, err := StatLine(bad); err == nil {
			t.Errorf("StatLine(%q) did not fail", bad)
		}
	}
}

// Cell (d) measures what operators copy: the shipped example, with only the store's name changed
// (and, for the first phase, the core_v2 entry left out, so that the second phase adds it).
func example(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "port49", "examples", "external-secret.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeES(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func shippedES(t *testing.T) map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(string(example(t))))
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal("the example has no ExternalSecret")
		}
		if m["kind"] == "ExternalSecret" {
			return m
		}
	}
}

func TestExternalSecretIsTheExampleExceptTheStoreName(t *testing.T) {
	want := shippedES(t)
	want["spec"].(map[string]any)["secretStoreRef"].(map[string]any)["name"] = "l82-fake"
	b, err := ExternalSecretFromExample(example(t), "l82-fake", true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeES(t, b), jsonRoundTrip(t, want)) {
		t.Errorf("the ExternalSecret differs from the example in more than the store name:\n%s", b)
	}
	spec := want["spec"].(map[string]any)
	if r := spec["target"].(map[string]any)["creationPolicy"]; r != "Owner" {
		t.Errorf("the example's creationPolicy is %v: L82 must measure Owner", r)
	}
}

func TestExternalSecretFirstPhaseLacksOnlyTheSecondVersion(t *testing.T) {
	want := shippedES(t)
	spec := want["spec"].(map[string]any)
	spec["secretStoreRef"].(map[string]any)["name"] = "l82-fake"
	data := spec["data"].([]any)
	spec["data"] = data[:1]
	b, err := ExternalSecretFromExample(example(t), "l82-fake", false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeES(t, b), jsonRoundTrip(t, want)) {
		t.Errorf("the first phase is not the example less its core_v2 entry:\n%s", b)
	}
	if strings.Contains(string(b), "core_v2") || !strings.Contains(string(b), "core_v1") {
		t.Errorf("the first phase's keys are wrong:\n%s", b)
	}
}

func TestExternalSecretRefusesAnExampleItDoesNotUnderstand(t *testing.T) {
	for name, in := range map[string]string{
		"no ExternalSecret": "kind: SecretStore\nmetadata: {name: x}\n",
		"a cluster store":   "kind: ExternalSecret\nspec: {secretStoreRef: {name: x, kind: ClusterSecretStore}, data: [{secretKey: core_v1}, {secretKey: core_v2}]}\n",
		"no core_v2":        "kind: ExternalSecret\nspec: {secretStoreRef: {name: x, kind: SecretStore}, data: [{secretKey: core_v1}]}\n",
	} {
		if _, err := ExternalSecretFromExample([]byte(in), "s", true); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func jsonRoundTrip(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return decodeES(t, b)
}
