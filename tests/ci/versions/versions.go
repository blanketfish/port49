// Package versions reads the version each published artifact carries and checks
// they agree with each other and with a release tag, so a release cannot ship a
// wheel, a collection and a chart that name different versions.
package versions

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The files the versions are read from, relative to the repository root.
const (
	PyPIFile   = "clients/python/pyproject.toml"
	GalaxyFile = "clients/ansible/ansible_collections/port49/client/galaxy.yml"
	ChartFile  = "deploy/helm/port49/Chart.yaml"
)

// Versions are the values as the files write them. Chart and ChartApp are
// empty while the chart does not exist.
type Versions struct{ PyPI, Galaxy, Chart, ChartApp string }

var (
	pyVersion    = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"\s*$`)
	yamlVersion  = regexp.MustCompile(`(?m)^version:\s*"?([^"\s#]+)"?\s*(?:#.*)?$`)
	yamlAppVers  = regexp.MustCompile(`(?m)^appVersion:\s*"?([^"\s#]+)"?\s*(?:#.*)?$`)
	preRelease   = regexp.MustCompile(`^(\d+(?:\.\d+)*)[-.]?(rc|a|b|alpha|beta)[-.]?(\d+)$`)
	preReleaseTo = map[string]string{"rc": "rc", "a": "a", "b": "b", "alpha": "a", "beta": "b"}
)

// Read reads the versions under root. The chart is optional: with no Chart.yaml
// its two values are empty.
func Read(root string) (Versions, error) {
	var v Versions
	py, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(PyPIFile)))
	if err != nil {
		return v, fmt.Errorf("pyproject: %w", err)
	}
	if m := pyVersion.FindSubmatch(py); m != nil {
		v.PyPI = string(m[1])
	} else {
		return v, fmt.Errorf("%s: no version line", PyPIFile)
	}
	gal, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(GalaxyFile)))
	if err != nil {
		return v, fmt.Errorf("galaxy.yml: %w", err)
	}
	if m := yamlVersion.FindSubmatch(gal); m != nil {
		v.Galaxy = string(m[1])
	} else {
		return v, fmt.Errorf("%s: no version line", GalaxyFile)
	}
	chart, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ChartFile)))
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return v, fmt.Errorf("Chart.yaml: %w", err)
	default:
		if m := yamlVersion.FindSubmatch(chart); m != nil {
			v.Chart = string(m[1])
		}
		if m := yamlAppVers.FindSubmatch(chart); m != nil {
			v.ChartApp = string(m[1])
		}
	}
	return v, nil
}

// pep440 is a version as PyPI normalises it: 0.1.0-rc1 is 0.1.0rc1.
func pep440(s string) string {
	if m := preRelease.FindStringSubmatch(s); m != nil {
		return m[1] + preReleaseTo[m[2]] + m[3]
	}
	return s
}

// Check is the findings, empty when the versions are right. With no tag, the
// values present must agree. With a tag, all four must be present and equal the
// tag without its v; PyPI's is compared as PEP 440 normalises it.
func Check(v Versions, tag string) []string {
	type item struct{ file, what, got string }
	items := []item{
		{PyPIFile, "version", v.PyPI}, {GalaxyFile, "version", v.Galaxy},
		{ChartFile, "version", v.Chart}, {ChartFile, "appVersion", v.ChartApp},
	}
	var out []string
	if tag == "" {
		var first *item
		for k := range items {
			if items[k].got == "" {
				continue
			}
			if first == nil {
				first = &items[k]
				continue
			}
			if pep440(items[k].got) != pep440(first.got) {
				out = append(out, fmt.Sprintf("%s: %s %s does not match %s's %s %s", items[k].file, items[k].what,
					items[k].got, first.file, first.what, first.got))
			}
		}
		return out
	}
	want := strings.TrimPrefix(tag, "v")
	for _, it := range items {
		w, g := want, it.got
		if it.file == PyPIFile {
			w = pep440(want)
		}
		switch {
		case it.got == "":
			out = append(out, fmt.Sprintf("%s: no %s; the release %s needs one", it.file, it.what, tag))
		case g != w:
			out = append(out, fmt.Sprintf("%s: %s %s is not the tag's %s", it.file, it.what, it.got, w))
		}
	}
	return out
}
