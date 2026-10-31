//go:build linux

package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// The directory commands send their one call through the agent and print the
// broker's text; a refusal exits 1 with what to do; a partial result exits 3;
// a missing or extra argument is usage (plan 7g, 9e, 12b).
func TestDirectoryCommandsSendOneCall(t *testing.T) {
	stub := newAdminStub(t, func(req agent.AdminRequest) (int, any) {
		switch {
		case strings.Contains(string(req.Body), "app:ci"):
			return 409, api.Error{Error: "admin_operation_failed", Detail: `"app:ci" is not a user: principal`}
		case req.Path == "/v1/directory/unlock":
			return 200, api.AdminResult{Text: "cleared 3 failed sign-ins"}
		case strings.HasPrefix(req.Path, "/v1/directory/import"):
			return 200, api.AdminResult{Text: "imported 1 second factors", Partial: strings.Contains(req.Path, "replace=true")}
		}
		return 200, api.AdminResult{Text: "done"}
	})
	defer func(r io.Reader) { directoryStdin = r }(directoryStdin)
	var out, errb bytes.Buffer
	if code := run([]string{"directory", "forget", "user:alice@example.com"}, &out, &errb); code != 0 ||
		strings.TrimSpace(out.String()) != "done" {
		t.Fatalf("forget: %d %q %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := run([]string{"directory", "forget", "app:ci"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "not a user: principal") {
		t.Fatalf("a refusal: %d %q", code, errb.String())
	}
	if code, so, _ := cli("directory", "unlock", "user:alice@example.com"); code != 0 || strings.TrimSpace(so) != "cleared 3 failed sign-ins" {
		t.Fatalf("unlock: %d %q", code, so)
	}
	if code, _, _ := cli("directory", "reset-second-factor", "--all"); code != 0 {
		t.Fatalf("reset --all: %d", code)
	}
	directoryStdin = strings.NewReader("x")
	if code, _, _ := cli("directory", "import"); code != 0 {
		t.Fatalf("import: %d", code)
	}
	directoryStdin = strings.NewReader("x")
	if code, so, se := cli("directory", "import", "--replace"); code != 3 || !strings.Contains(so, "imported") ||
		!strings.Contains(se, "run the same command again") {
		t.Fatalf("a partial import: %d %q %q", code, so, se)
	}
	directoryStdin = strings.NewReader("")
	if code, _, se := cli("directory", "import"); code != 1 || !strings.Contains(se, "no export on standard input") {
		t.Fatalf("an empty import: %d %q", code, se)
	}
	var paths []string
	for _, r := range stub.requests() {
		paths = append(paths, r.Path)
	}
	want := "/v1/directory/forget /v1/directory/forget /v1/directory/unlock /v1/directory/reset-second-factor " +
		"/v1/directory/import?replace=false /v1/directory/import?replace=true"
	if strings.Join(paths, " ") != want {
		t.Fatalf("the calls:\n%s\nwant\n%s", strings.Join(paths, " "), want)
	}
}

// reset-second-factor takes a principal or --all, one of them; the others take
// what their usage says: a wrong argument count is usage, exit 2.
func TestDirectoryCommandsTakeTheirArguments(t *testing.T) {
	for _, args := range [][]string{{"directory", "reset-second-factor"},
		{"directory", "reset-second-factor", "--all", "user:a@b"},
		{"directory", "reset-second-factor", "user:a@b", "user:c@d"},
		{"directory", "unlock"}, {"directory", "forget"}, {"directory", "forget", "user:a@b", "user:c@d"},
		{"directory", "import", "extra"}, {"directory"}, {"directory", "remember", "user:a@b"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d %q", args, code, errb.String())
		}
	}
}
