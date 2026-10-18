//go:build lab

package lab

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestL73Grade(t *testing.T) {
	for _, c := range []struct {
		ok, red, hf bool
		want        string
	}{
		{true, true, false, "accepted"},
		{false, false, true, "refused"},
		{false, false, false, "login failed, cause unproven"},
		{true, false, false, "login failed, cause unproven"},
	} {
		if got := l73Grade(c.ok, c.red, c.hf); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

func TestL73RefusedForNeedsTheCellsReason(t *testing.T) {
	rec := func(outcome, detail string) map[string]any {
		return map[string]any{"unvalidated": map[string]any{"tls_outcome": outcome, "detail": detail}}
	}
	aborted := rec("handshake_failed", "the device aborted the handshake (it may refuse port49's certificate; see x)")
	timedOut := rec("handshake_failed", "the TLS handshake did not complete")
	unknown := rec("unknown_ca", "x509: certificate signed by unknown authority (possibly because of ...)")
	if !l73RefusedFor([]map[string]any{aborted}, "handshake_failed", l73DeviceAborted) ||
		!l73RefusedFor([]map[string]any{unknown}, "unknown_ca", l73UnknownAuthority) {
		t.Fatal("the cell's own reason must be proven")
	}
	// A handshake_failed port49 ended itself, or another outcome, proves nothing.
	if l73RefusedFor([]map[string]any{timedOut, unknown}, "handshake_failed", l73DeviceAborted) ||
		l73RefusedFor([]map[string]any{aborted}, "unknown_ca", l73UnknownAuthority) || l73RefusedFor(nil, "unknown_ca", "") {
		t.Fatal("another reason was taken for the cell's")
	}
}

func TestL73LoginWindowsGiveEveryLoginTheSameTail(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s float64, host string) l73Conn {
		return l73Conn{Server: host + ":300", SYNAt: t0.Add(time.Duration(s * float64(time.Second)))}
	}
	// login 1 spans 1s-2s, login 2 spans 7s-8s; the tail is 5s.
	spans := []l73Span{{t0.Add(time.Second), t0.Add(2 * time.Second)}, {t0.Add(7 * time.Second), t0.Add(8 * time.Second)}}
	conns := []l73Conn{at(0.5, "h"), at(1, "h"), at(6.9, "h"), at(7, "h"), at(12.9, "h"), at(13.1, "h"), at(3, "x")}
	w := l73LoginWindows(conns, "h", spans)
	// 6.9s is 4.9s after login 1 returned and 12.9s is 4.9s after login 2: each
	// keeps its own late connection; 7s and 13.1s fall outside the other tail.
	if len(w[0]) != 2 || len(w[1]) != 2 || w[0][1].SYNAt != t0.Add(6900*time.Millisecond) || w[1][1].SYNAt != t0.Add(12900*time.Millisecond) {
		t.Fatalf("login1 %+v login2 %+v", w[0], w[1])
	}
}

func TestL73RefusalVerdict(t *testing.T) {
	for _, c := range []struct {
		id          string
		n           int
		ok, ok2, ag bool
		contra      bool
		proven      bool
	}{
		{"i-alert", 1, true, true, false, false, true},
		{"i-alert", 1, false, true, false, true, true},
		{"i-alert", 0, false, true, false, false, false}, // unproven contradicts nothing
		{"i-window", 1, true, false, true, true, true},   // the login inside the window did not land
		{"i-window", 1, true, true, true, false, true},
		{"i-error", 1, false, true, false, false, true}, // §5.7 / L4: an ERROR is final; never **no**
	} {
		contra, proven := l73RefusalVerdict(c.id, c.n, c.ok, c.ok2, c.ag)
		if (contra != "") != c.contra || proven != c.proven {
			t.Errorf("%+v: %q %v", c, contra, proven)
		}
	}
}

// Every cell method is called from TestL73, and note ends it: a live run can
// never pass while skipping cells or the evidence.
func TestL73CallsEveryCellAndEndsWithTheNote(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "l73_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var defined []string
	var called []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Recv != nil && strings.HasPrefix(fn.Name.Name, "cell") {
			defined = append(defined, fn.Name.Name)
		}
		if fn.Name.Name != "TestL73" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					called = append(called, sel.Sel.Name)
				}
			}
			return true
		})
	}
	for _, d := range defined {
		if !slices.Contains(called, d) {
			t.Errorf("TestL73 never calls %s", d)
		}
	}
	if len(defined) == 0 || len(called) == 0 || !slices.Contains(called, "note") {
		t.Fatalf("defined %v called %v", defined, called)
	}
	if i := slices.Index(called, "note"); slices.Index(called, "cellB") > i || slices.Index(called, "cellH") > i {
		t.Error("note must come after every cell")
	}
}
