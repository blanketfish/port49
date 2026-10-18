package lab

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// TestL73 starts port49d one way: startOn, on the config the cell's daemon()
// call recorded. The harness's restart paths put the standing plain config
// back (withAdminCLI, startDaemon) or wait on IOS XE for a record a refused
// handshake never makes (restart, awaitTACACS); either one measures the wrong
// daemon with no symptom. And a cell that starts a daemon first sees the
// device connect (ready, or revive before a refusal).
func TestL73DaemonRunsOnlyTheCellsConfig(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "l73_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string][]string{} // function -> the selectors it calls
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		calls[name] = append(calls[name], "")
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					calls[name] = append(calls[name], sel.Sel.Name)
				}
			}
			return true
		})
	}
	if _, ok := calls["startOn"]; !ok {
		t.Fatal("l73_test.go has no startOn, the one place TestL73 starts port49d")
	}
	for fn, names := range calls {
		for _, n := range names {
			switch {
			case n == "withAdminCLI" || n == "restart" || n == "awaitTACACS" || n == "startDaemon":
				t.Errorf("%s calls %s: port49d back on the standing config, or a wait for a record", fn, n)
			case n == "startDaemonWith" && fn != "startOn":
				t.Errorf("%s calls startDaemonWith; only startOn starts port49d", fn)
			case n == "stopDaemon" && fn != "cli" && fn != "daemon" && fn != "upload":
				t.Errorf("%s calls stopDaemon; only cli, daemon and upload stop port49d", fn)
			}
		}
		if strings.HasPrefix(fn, "cell") && slices.Contains(names, "daemon") &&
			!slices.Contains(names, "ready") && !slices.Contains(names, "revive") {
			t.Errorf("%s starts a daemon and never sees the device connect (ready or revive)", fn)
		}
	}
}

// Cells i and j put 172.100.100.2 on the bridge. The `del` that takes it off
// is registered with t.Cleanup before the `add` runs, so a Fatal, an INVALID
// or the STOP guard between the two cannot leave the address behind.
func TestL73SecondAddressCleanupPrecedesTheAdd(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "l73_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cleanup, add token.Pos
	users := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch {
			case fn.Name.Name == "addSecondAddress" && sel.Sel.Name == "Cleanup":
				cleanup = c.Pos()
			case fn.Name.Name == "addSecondAddress" && sel.Sel.Name == "CombinedOutput":
				add = c.Pos()
			case sel.Sel.Name == "addSecondAddress":
				users[fn.Name.Name] = true
			}
			return true
		})
	}
	if !cleanup.IsValid() || !add.IsValid() || cleanup > add {
		t.Fatalf("addSecondAddress: Cleanup at %v, add at %v: the del must be registered first", cleanup, add)
	}
	if !users["cellI"] || !users["cellJ"] {
		t.Fatalf("cells that call addSecondAddress: %v; want cellI and cellJ", users)
	}
}
