package l82

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
