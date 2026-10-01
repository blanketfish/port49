//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// noteLine is whether one line of note holds every needle: a register
// note's table row, checked against its record cell by cell, so a word
// elsewhere in the note cannot stand in for it (pre-flight I3).
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

// TestL32FixturesAreWhatTheNotesSay reads every L32 record: it carries no
// credential; it holds two probes, each answered 200 with a next naming a
// host, and four reads; and its product's note names its directory, has a
// row per probe naming the stack, the proxy and the host next named, a row
// per read naming the stack, the proxy, the API and either the device count
// or "failed" (pre-flight I3), and a row saying whether GraphQL let the
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
		if len(rec.Probes) != 2 || len(rec.Reads) != 4 {
			t.Fatalf("%s: %d probes and %d reads, want 2 and 4", stack, len(rec.Probes), len(rec.Reads))
		}
		for _, p := range rec.Probes {
			if p.Status != 200 || p.NextHost == "" {
				t.Errorf("%s: the %s probe answered %d with next host %q: it measured nothing", stack, p.Proxy,
					p.Status, p.NextHost)
			}
			if !noteLine(string(note), stack, "proxy_"+p.Proxy, p.NextHost) {
				t.Errorf("%s: no note row says next named %s through proxy_%s", stack, p.NextHost, p.Proxy)
			}
		}
		for _, r := range rec.Reads {
			want := strconv.Itoa(r.Devices)
			if r.Error != "" {
				want = "failed"
			} else if r.Devices != 120 {
				t.Errorf("%s %s %s: %d devices and no error", stack, r.Proxy, r.API, r.Devices)
			}
			if !noteLine(string(note), stack, "proxy_"+r.Proxy, r.API, want) {
				t.Errorf("%s: no note row names the %s read through proxy_%s with %q", stack, r.API, r.Proxy, want)
			}
		}
		id := "id refused"
		if rec.GraphQLID.Selectable {
			id = "id selectable"
		}
		if rec.GraphQLID.Query == "" || !noteLine(string(note), stack, "GraphQL", id) {
			t.Errorf("%s: no note row says GraphQL's device list %s", stack, id)
		}
	}
}
