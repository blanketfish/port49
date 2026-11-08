package docgen

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// commentPackages are the packages whose struct fields the schemas are made of; Seed reads their doc
// comments.
var commentPackages = []string{"config", "policy", "admission", "inventory", "userconfig", "keyset", "secretref",
	"platform", "limits"}

// Seed appends to each descriptions file under root an entry for every key that has none. The entry is
// the key's Go doc comment (the last path segment's yaml name, from any struct of commentPackages)
// behind "DRAFT:", which ConfigPage refuses until an author has replaced it with operator text.
func Seed(root string) error {
	docs, err := fieldDocs(root)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range Schemas() {
		if seen[s.Descriptions] {
			continue
		}
		seen[s.Descriptions] = true
		path := filepath.Join(root, filepath.FromSlash(s.Descriptions))
		desc := map[string]string{}
		if _, err := os.Stat(path); err == nil {
			if desc, err = LoadDescriptions(root, s); err != nil {
				return err
			}
		}
		var add strings.Builder
		want := []string{descDescription, descIntro}
		for _, k := range Keys(s.Root) {
			want = append(want, k.Path)
		}
		for _, p := range want {
			if _, ok := desc[p]; ok {
				continue
			}
			text := draftPrefix + " " + docs[lastSegment(p)]
			fmt.Fprintf(&add, "%s: %s\n", jsonString(p), jsonString(strings.TrimSpace(text)))
			desc[p] = text
		}
		if add.Len() == 0 {
			continue
		}
		old, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if len(old) > 0 && !strings.HasSuffix(string(old), "\n") {
			old = append(old, '\n')
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, append(old, add.String()...), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func lastSegment(path string) string { return path[strings.LastIndex(path, ".")+1:] }

// fieldDocs maps a yaml key name to the doc comment of the first struct field that carries it.
func fieldDocs(root string) (map[string]string, error) {
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, pkg := range commentPackages {
		dir := filepath.Join(root, "internal", pkg)
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			tree, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			ast.Inspect(tree, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok {
					return true
				}
				for _, fld := range st.Fields.List {
					if fld.Tag == nil || fld.Doc == nil {
						continue
					}
					tag := reflect.StructTag(strings.Trim(fld.Tag.Value, "`")).Get("yaml")
					name := strings.Split(tag, ",")[0]
					if name == "" || name == "-" {
						continue
					}
					if _, dup := out[name]; !dup {
						out[name] = oneLine(fld.Doc.Text())
					}
				}
				return true
			})
		}
	}
	return out, nil
}
