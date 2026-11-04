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
	if l := (&l88Note{}); !func() bool { o, _ := l.render(); return strings.HasPrefix(o, "# L88:") }() {
		t.Errorf("a note with no id is not L88's")
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
