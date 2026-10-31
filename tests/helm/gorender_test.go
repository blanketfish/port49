package helm

// A small stand-in for `helm template`, so the chart is checked where helm is not installed: the
// chart's own templates run through Go's text/template with the few Helm and sprig functions they
// use, and the same checks run on its output as on real helm's (render_test.go, tag helm). It is
// not Helm: it does not validate values.schema.json, and a function the chart starts using that is
// not here fails the render rather than passing. Whatever only helm can show is marked "unverified
// until helm runs" in the task report.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

const chartDir = "../../deploy/helm/port49"

// mergeInto copies src into dst: maps merge, everything else (lists included) is replaced, as
// Helm merges a values file over the chart's defaults.
func mergeInto(dst, src map[string]any) map[string]any {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				dst[k] = mergeInto(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}

func isEmpty(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String, reflect.Slice, reflect.Map, reflect.Array:
		return rv.Len() == 0
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int64, reflect.Float64:
		return rv.IsZero()
	}
	return false
}

func toYAML(v any) string {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func indentText(n int, s string) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

// goRender renders the chart with each values file merged over values.yaml, in order.
func goRender(t *testing.T, valuesFiles ...string) []doc {
	t.Helper()
	docs, err := goRenderErr(t, valuesFiles...)
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

// goRenderErr is goRender that returns a template's own failure (a chart `fail`) instead of ending the test.
func goRenderErr(t *testing.T, valuesFiles ...string) ([]doc, error) {
	t.Helper()
	read := func(p string) map[string]any {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := yaml.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return m
	}
	values := read(filepath.Join(chartDir, "values.yaml"))
	for _, f := range valuesFiles {
		mergeInto(values, read(f))
	}
	chart := read(filepath.Join(chartDir, "Chart.yaml"))
	data := map[string]any{
		"Values":   values,
		"Release":  map[string]any{"Name": "t", "Namespace": "port49", "Service": "Helm"},
		"Chart":    map[string]any{"Name": chart["name"], "Version": chart["version"], "AppVersion": chart["appVersion"]},
		"Template": map[string]any{"BasePath": "port49/templates"},
	}
	root := template.New("port49").Option("missingkey=error")
	root.Funcs(template.FuncMap{
		"include": func(name string, d any) (string, error) {
			var b bytes.Buffer
			err := root.ExecuteTemplate(&b, name, d)
			return b.String(), err
		},
		"toYaml": toYAML,
		"toJson": func(v any) string { b, _ := json.Marshal(v); return string(b) },
		"fromYaml": func(s string) map[string]any {
			m := map[string]any{}
			if err := yaml.Unmarshal([]byte(s), &m); err != nil {
				return map[string]any{"Error": err.Error()}
			}
			return m
		},
		"mustMergeOverwrite": func(dst map[string]any, srcs ...map[string]any) map[string]any {
			for _, s := range srcs {
				mergeInto(dst, s)
			}
			return dst
		},
		"indent":  func(n int, s string) string { return indentText(n, s) },
		"nindent": func(n int, s string) string { return "\n" + indentText(n, s) },
		"quote":   func(v any) string { return strconv.Quote(fmt.Sprint(v)) },
		"default": func(d, v any) any {
			if isEmpty(v) {
				return d
			}
			return v
		},
		"int": func(v any) int {
			switch x := v.(type) {
			case int:
				return x
			case int64:
				return int(x)
			case float64:
				return int(x)
			}
			n, _ := strconv.Atoi(fmt.Sprint(v))
			return n
		},
		"required": func(msg string, v any) (any, error) {
			if isEmpty(v) {
				return nil, fmt.Errorf("%s", msg)
			}
			return v, nil
		},
		"add":  func(a, b int) int { return a + b },
		"fail": func(msg string) (string, error) { return "", fmt.Errorf("%s", msg) },
		"list": func(v ...any) []any { return v },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"sha256sum": func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) },
	})
	files, err := filepath.Glob(filepath.Join(chartDir, "templates", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates under %s: %v", chartDir, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := root.New("port49/templates/" + filepath.Base(f)).Parse(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	var docs []doc
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasPrefix(base, "_") || base == "NOTES.txt" {
			continue
		}
		var b bytes.Buffer
		if err := root.ExecuteTemplate(&b, "port49/templates/"+base, data); err != nil {
			return nil, fmt.Errorf("rendering %s: %v", base, err)
		}
		docs = append(docs, decodeDocs(t, base, b.Bytes())...)
	}
	return docs, nil
}
