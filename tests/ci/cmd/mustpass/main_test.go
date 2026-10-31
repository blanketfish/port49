package main

import (
	"bytes"
	"strings"
	"testing"
)

func ev(action, test string) string {
	return `{"Action":"` + action + `","Package":"p","Test":"` + test + `"}` + "\n"
}

func TestMustpassPassesWhenAllPass(t *testing.T) {
	in := ev("run", "A") + ev("pass", "A") + ev("run", "B") + ev("pass", "B")
	var errb bytes.Buffer
	if code := mustPass(strings.NewReader(in), []string{"A", "B"}, &errb); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
}

func TestMustpassFailsASkip(t *testing.T) {
	in := ev("run", "A") + ev("skip", "A") + ev("run", "B") + ev("pass", "B")
	var errb bytes.Buffer
	if code := mustPass(strings.NewReader(in), []string{"A", "B"}, &errb); code != 1 ||
		!strings.Contains(errb.String(), "A") || !strings.Contains(errb.String(), "skipped") {
		t.Fatalf("code %d: %s", code, errb.String())
	}
}

func TestMustpassFailsAFailureAndAMissingTest(t *testing.T) {
	in := ev("run", "A") + ev("fail", "A")
	var errb bytes.Buffer
	if code := mustPass(strings.NewReader(in), []string{"A", "B"}, &errb); code != 1 ||
		!strings.Contains(errb.String(), "A failed") || !strings.Contains(errb.String(), "B never ran") {
		t.Fatalf("code %d: %s", code, errb.String())
	}
}

func TestMustpassIgnoresASubtestWithTheSamePrefix(t *testing.T) {
	in := ev("pass", "A/sub") + ev("pass", "AB")
	var errb bytes.Buffer
	if code := mustPass(strings.NewReader(in), []string{"A"}, &errb); code != 1 {
		t.Fatalf("A never ran, but code %d", code)
	}
}

func TestMustpassNeedsNames(t *testing.T) {
	var errb bytes.Buffer
	if code := mustPass(strings.NewReader(""), nil, &errb); code != 2 {
		t.Fatalf("no names: code %d", code)
	}
}
