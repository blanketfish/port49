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

// TestL33FixturesAreWhatTheNotesSay reads every L33 record: no secret or
// token in it; three phases and the webhook's create calls; and in its
// product's note, its directory, a row per published phase naming the
// stack, the change and its seconds to two places, a row per unpublished
// phase naming the stack, the change and "failed", a row naming the stack
// and the bad_signature count, and a row naming the stack, 503 and the 503
// listener's count (pre-flight I3; noteLine is l32_unit_test.go's).
func TestL33FixturesAreWhatTheNotesSay(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("sot", "l33", "*", "webhooks.json"))
	if len(files) == 0 {
		t.Skip("no L33 records yet")
	}
	for _, f := range files {
		stack := filepath.Base(filepath.Dir(f))
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"secret\":", "Authorization", "nbt_", "X-Hook-Signature"} {
			if strings.Contains(string(raw), leak) {
				t.Fatalf("%s carries %q", f, leak)
			}
		}
		var rec l33Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		note, err := os.ReadFile(filepath.Join("results", "L33-"+strings.SplitN(stack, "-", 2)[0]+".md"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(note), "tests/lab/sot/l33/"+stack+"/") {
			t.Errorf("the note does not name tests/lab/sot/l33/%s/", stack)
		}
		if len(rec.Phases) != 3 || len(rec.WebhookCalls) == 0 {
			t.Fatalf("%s: %d phases and %d webhook calls, want 3 and some", stack, len(rec.Phases), len(rec.WebhookCalls))
		}
		cell := func(s string) string { return "| " + s + " |" }
		for _, p := range rec.Phases {
			want := cell(fmt.Sprintf("%.2f s", p.Seconds))
			if !p.Published {
				want = cell("failed")
			} else if p.Accepted < 1 {
				t.Errorf("%s: %q published with no accepted delivery counted", stack, p.Change)
			}
			want += fmt.Sprintf(" %d accepted |", p.Accepted)
			if !noteLine(string(note), cell(stack), cell(p.Change), want) {
				t.Errorf("%s: no note row names %q with %q", stack, p.Change, want)
			}
		}
		if !noteLine(string(note), cell(stack), cell("bad_signature")+" "+strconv.Itoa(rec.BadSignature)+" in 120 s |") {
			t.Errorf("%s: no note row gives bad_signature %d", stack, rec.BadSignature)
		}
		if !noteLine(string(note), cell(stack), cell("503")+" "+strconv.Itoa(rec.Unavailable)+" in 120 s |") {
			t.Errorf("%s: no note row gives the 503 listener's %d deliveries", stack, rec.Unavailable)
		}
	}
}
