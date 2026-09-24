package decision

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Known is the whole vocabulary: every Reason constant declared in
// reasons.go, and nothing else.
func TestKnownIsEveryReasonConstant(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "reasons.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Reason" {
				continue
			}
			for _, v := range vs.Values {
				lit := v.(*ast.BasicLit)
				declared++
				if r := Reason(lit.Value[1 : len(lit.Value)-1]); !Known(r) {
					t.Errorf("%s is declared but not Known", r)
				}
			}
		}
	}
	if declared != len(reasons) {
		t.Errorf("reasons.go declares %d reasons; Known lists %d", declared, len(reasons))
	}
	if Known("no_grant_matched") {
		t.Error("a typo is not a reason")
	}
}
