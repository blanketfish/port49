//go:build lab

package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// noteLine is whether one line of note holds every needle: a register
// note's table row, checked against its record cell by cell, so a word
// elsewhere in the note cannot stand in for it (pre-flight I3). Callers
// pass needles delimited by the table's cell bars, so "rest" cannot match
// inside another word nor "120" inside another number.
func noteLine(note string, needles ...string) bool {
	for _, line := range strings.Split(note, "\n") {
		all := true
		for _, n := range needles {
			all = all && n != "" && strings.Contains(line, n)
		}
		if all {
			return true
		}
	}
	return false
}

// l32Leaf is a read's leaf-01 cell as the notes write it.
func l32Leaf(l map[string]any) string {
	attrs, _ := l["attributes"].(map[string]any)
	var addrs []string
	for _, a := range asList(l["addresses"]) {
		addrs = append(addrs, fmt.Sprint(a))
	}
	return fmt.Sprintf("| leaf-01: platform `%v`, site `%v`, role `%v`, os_version `%v`, addresses `%s` |", l["platform"],
		attrs["site"], attrs["role"], attrs["os_version"], strings.Join(addrs, " "))
}

func asList(v any) []any { l, _ := v.([]any); return l }

// TestL32FixturesAreWhatTheNotesSay reads every L32 record: it carries no
// credential; it holds three probes, each answered 200 with a next naming a
// host, and six reads; and its product's note names its directory, has a
// row per probe naming the stack, the proxy and the scheme and host next
// named, a row per read naming the stack, the proxy, the API, the device
// count and seconds (or "failed"), whether a rebuilt next was said, and
// leaf-01 as read (pre-flight I3), and a row saying whether GraphQL let the
// list select id.
func TestL32FixturesAreWhatTheNotesSay(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("sot", "l32", "*", "connector.json"))
	if len(files) == 0 {
		t.Skip("no L32 records yet")
	}
	for _, f := range files {
		stack := filepath.Base(filepath.Dir(f))
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"Authorization", "nbt_", "Token "} {
			if strings.Contains(string(raw), leak) {
				t.Fatalf("%s carries %q", f, leak)
			}
		}
		var rec l32Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		note, err := os.ReadFile(filepath.Join("results", "L32-"+strings.SplitN(stack, "-", 2)[0]+".md"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(note), "tests/lab/sot/l32/"+stack+"/") {
			t.Errorf("the note does not name tests/lab/sot/l32/%s/", stack)
		}
		if len(rec.Probes) != 3 || len(rec.Reads) != 6 {
			t.Fatalf("%s: %d probes and %d reads, want 3 and 6", stack, len(rec.Probes), len(rec.Reads))
		}
		row := "| " + stack + " | "
		for _, p := range rec.Probes {
			if p.Status != 200 || p.NextHost == "" {
				t.Errorf("%s: the %s probe answered %d with next host %q: it measured nothing", stack, p.Proxy,
					p.Status, p.NextHost)
			}
			next := "| next: " + p.NextScheme + "://" + p.NextHost + " |"
			if !noteLine(string(note), row+"proxy_"+p.Proxy+" "+next) {
				t.Errorf("%s: no note row says %s through proxy_%s", stack, next, p.Proxy)
			}
		}
		for _, r := range rec.Reads {
			want := fmt.Sprintf("| %s devices, %.3f s |", strconv.Itoa(r.Devices), r.Seconds)
			if r.Error != "" {
				want = "| failed: "
			} else if r.Devices != 120 {
				t.Errorf("%s %s %s: %d devices and no error", stack, r.Proxy, r.API, r.Devices)
			}
			needles := []string{row + "proxy_" + r.Proxy + " | " + r.API + " " + want,
				"| rebuilt next said: " + yesNo(l32Said(r)) + " "}
			if r.Leaf01 != nil {
				needles = append(needles, l32Leaf(r.Leaf01))
			}
			if !noteLine(string(note), needles...) {
				t.Errorf("%s: no note row holds %q", stack, needles)
			}
		}
		id := l32IDVerdict(rec.GraphQLID)
		if rec.GraphQLID.Query == "" || !noteLine(string(note), row+"GraphQL "+id+" |") {
			t.Errorf("%s: no note row says GraphQL's device list %s", stack, id)
		}
	}
}
