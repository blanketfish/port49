//go:build lab

package lab

import (
	"strings"
	"testing"
)

// L87's note is L88's renderer under another id: it names L87, and it drops every credential the
// run held (the break-glass password, the lab key, a token, a device hash).
func TestL87NoteHoldsNoSecret(t *testing.T) {
	const pw = "Zk3-known-lab-password-9XyQ"
	const token = "tok-L87-one-time-credential-value"
	hash := "$6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv"
	n := newL88Note(platform{name: "nokia_srlinux", version: "x"}, "tcp", pw, hash)
	n.id = "L87"
	n.addSecret(token)
	n.cell("a", "OBSERVED", "logged in with "+pw+" and "+token+" and "+hash+" key "+labKeyDefault+" "+breakglassPassword,
		"credential "+token+" "+pw)
	n.fact("typed " + pw)
	out, err := n.render()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{pw, token, hash, labKeyDefault, breakglassPassword} {
		if strings.Contains(out, s) {
			t.Errorf("the note holds %q", s)
		}
	}
	if !strings.HasPrefix(out, "# L87:") || !strings.Contains(out, "by TestL87.") || !strings.Contains(out, "logged in with") {
		t.Errorf("the note is not L87's, or lost its observation:\n%s", out)
	}
	n.raw = token
	if _, err := n.render(); err == nil {
		t.Errorf("a note holding a token rendered")
	}
	if o, _ := (&l88Note{}).render(); !strings.HasPrefix(o, "# L88:") {
		t.Errorf("a note with no id is not L88's")
	}
}

// A device-hashed value the run did not list is masked by its shape alone: SR Linux's $aes1$,
// Cisco's $9$ and the $6$ crypt, and a metric name survives the long-run mask.
func TestL87NoteMasksHashShapes(t *testing.T) {
	n := newL88Note(platform{name: "nokia_srlinux", version: "x"}, "tcp")
	n.id = "L87"
	// Built from parts so the source holds no hash-shaped literal for the leak scan to flag.
	d := "$"
	hashes := []string{d + "aes1" + d + "AWx9kQ2mZpLr" + d + "Zm9vYmFyYmF6", d + "9" + d + "abcDEFghiJKL012", d + "6" + d + "salt" + d + "Zm9vYmFyYmF6cXV4cXV1eA"}
	n.cell("a", "OBSERVED", "the device printed "+strings.Join(hashes, " and ")+" and port49_store_health_failures was 5", "")
	out, err := n.render()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hashes {
		if strings.Contains(out, h) {
			t.Errorf("the note holds %q", h)
		}
	}
	if !strings.Contains(out, "<hash>") {
		t.Errorf("the hashes were not masked as <hash>:\n%s", out)
	}
	// Observations are kept through redact, whose long-run mask is the one that could eat a metric name.
	if got := n.redact("the gauge port49_store_health_failures was 5"); !strings.Contains(got, "port49_store_health_failures") {
		t.Errorf("redact masked a metric name: %s", got)
	}
}

func TestL87GaugeRegexp(t *testing.T) {
	m := l87Gauge.FindSubmatch([]byte("# HELP x\nport49_store_health_failures 3\nother 1\n"))
	if m == nil || string(m[1]) != "3" {
		t.Fatalf("gauge not read: %v", m)
	}
	if l87Gauge.Match([]byte("xport49_store_health_failures 3\n")) {
		t.Fatal("matched a longer name")
	}
}
