//go:build lab

package lab

import (
	"testing"

	"github.com/rhwendt/port49/internal/directory"
)

// TestL44Bringup is the DC's bring-up alone, with no measurement: everything
// L44 needs before it measures anything. It writes no note. Run it with
//
//	go test -tags lab ./tests/lab/ -run '^TestL44Bringup$' -count=1 -v -timeout 240m
//
// Its evidence file, L44-bringup.json, goes under tests/lab/evidence of the run's
// output root: set PORT49_LAB_DIRECTORY_OUT to keep a dry run out of the
// repository, and never `git add` it.
//
// TestL44WindowsAD is the measurement (its comment has its command).
func TestL44Bringup(t *testing.T) {
	d := newDirectories(t)
	dc := startWindowsDC(t, d)
	c := dc.win.certs
	// Not a failed bring-up: the run goes on, those cells INVALID (Step 6).
	for _, why := range dc.win.invalid {
		t.Logf("windows: INVALID (R6): a setup step failed three times; its cells will be INVALID: %s", why)
	}
	if c.aliceSID != nil {
		if _, err := directory.SIDOf(c.aliceSID); err != nil {
			t.Errorf("alice's User certificate carries no SID extension: %v", err)
		}
	}
	if _, err := directory.SIDOf(c.aliceADCS); err == nil {
		t.Errorf("alice's OfflineRouter certificate carries a SID extension; the matrix needs one without")
	}
	ev := evidence(t, d, "L44-bringup")
	if r := dc.tryBind(t, ev, "simple", dc.bindSimple(), d.password); !r.ok || r.read != 1 {
		t.Errorf("the simple bind over LDAPS, the lab's premise: %+v", r)
	}
	if why := dc.win.invalidFor("keytab"); why != "" {
		t.Logf("GSSAPI: no keytab (%s); its cells will be INVALID", why)
	} else if r := dc.tryBind(t, ev, "gssapi", dc.bindGSSAPI(), ""); !r.ok {
		t.Logf("GSSAPI as installed: %s (measured in TestL44WindowsAD, not a bring-up failure)", r.text)
	}
	ev.assertClean(t, append([]string{d.password}, d.extra...)...)
	t.Logf("windows: %s; fixture loaded, LDAPS verified, keytab and certificates issued", dc.win.version())
}
