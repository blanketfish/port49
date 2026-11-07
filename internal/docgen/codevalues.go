package docgen

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

// The closed value lists the decision-log page describes live in the code as constants and literals,
// not as exported lists. These read them from the source, so a guard test can hold a description to
// them.
const (
	reasonsSource    = "internal/decision/reasons.go"
	keyringSource    = "internal/keyring/keyring.go"
	acctSource       = "internal/daemon/acct/acct.go"
	bundleDiffSource = "internal/bundle/diff.go"
)

func parseGo(root, rel string) (*ast.File, error) {
	return parser.ParseFile(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
}

func stringLit(e ast.Expr) (string, bool) {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(l.Value)
	return s, err == nil
}

// stringConsts lists the string constants of f that keep, in source order, as name and value.
func stringConsts(f *ast.File, keep func(name string, typ ast.Expr) bool) (names, values []string) {
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i >= len(vs.Values) || !keep(n.Name, vs.Type) {
					continue
				}
				if v, ok := stringLit(vs.Values[i]); ok {
					names, values = append(names, n.Name), append(values, v)
				}
			}
		}
	}
	return names, values
}

// EventNames is the value of every Event* constant of the decision package: every event the log can carry.
func EventNames(root string) ([]string, error) {
	f, err := parseGo(root, reasonsSource)
	if err != nil {
		return nil, err
	}
	_, vals := stringConsts(f, func(n string, _ ast.Expr) bool { return strings.HasPrefix(n, "Event") })
	return vals, nil
}

// DiagnosisValues is every diagnosis an unvalidated record can carry: the keyring's Diagnosis constants
// but validated, which is the verdict of a packet that did validate.
func DiagnosisValues(root string) ([]string, error) {
	f, err := parseGo(root, keyringSource)
	if err != nil {
		return nil, err
	}
	_, vals := stringConsts(f, func(_ string, typ ast.Expr) bool {
		id, ok := typ.(*ast.Ident)
		return ok && id.Name == "Diagnosis"
	})
	var out []string
	for _, v := range vals {
		if v != "validated" {
			out = append(out, v)
		}
	}
	return out, nil
}

// AttributionValues is every string the accounting handler assigns to a record's attribution.
func AttributionValues(root string) ([]string, error) {
	f, err := parseGo(root, acctSource)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			return true
		}
		if id, ok := a.Lhs[0].(*ast.Ident); ok && id.Name == "attribution" {
			if v, ok := stringLit(a.Rhs[0]); ok {
				out = append(out, v)
			}
		}
		return true
	})
	return dedupe(out), nil
}

// SecurityChangeKinds is the kind of every change the bundle diff can mark Security, which is what an
// inventory_change record carries (a change built with no Security field is never logged).
func SecurityChangeKinds(root string) ([]string, error) {
	f, err := parseGo(root, bundleDiffSource)
	if err != nil {
		return nil, err
	}
	names, vals := stringConsts(f, func(string, ast.Expr) bool { return true })
	byName := map[string]string{}
	for i, n := range names {
		byName[n] = vals[i]
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := c.Type.(*ast.Ident); !ok || id.Name != "Change" {
			return true
		}
		kind, security := "", false
		for _, e := range c.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, _ := kv.Key.(*ast.Ident)
			switch {
			case key != nil && key.Name == "Kind":
				if id, ok := kv.Value.(*ast.Ident); ok {
					kind = byName[id.Name]
				}
			case key != nil && key.Name == "Security":
				security = true
			}
		}
		if security && kind != "" {
			out = append(out, kind)
		}
		return true
	})
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no Change marked Security", bundleDiffSource)
	}
	return dedupe(out), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
