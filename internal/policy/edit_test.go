package policy

import (
	"strings"
	"testing"
)

// Offboarding a machine subject is one command (spec §12; decision 2's cost):
// every grant row goes, then the subject block, and the result still loads
// and still passes the tests that did not name it.
func TestRemoveSubjectDeletesItsRowsAndItsBlock(t *testing.T) {
	out, r, err := RemoveSubject(spec11Raw(t), "svc_oxidized")
	if err != nil {
		t.Fatal(err)
	}
	if r.Grants != 1 || r.Tests != 2 {
		t.Fatalf("removed %+v, want one grant row and two tests", r)
	}
	if strings.Contains(string(out), "name: svc_oxidized") || strings.Contains(string(out), "subject: svc_oxidized") ||
		strings.Contains(string(out), "system:serviceaccount") {
		t.Fatalf("the subject is still named:\n%s", out)
	}
	if !strings.Contains(string(out), "# Spec §11's complete policy example") {
		t.Fatalf("comments must survive the edit:\n%s", out)
	}
	p := spec11(t, out)
	if _, ok := p.Subject("svc_oxidized"); ok {
		t.Fatal("the subject block must go with its last grant")
	}
	for _, res := range p.RunTests(noon) {
		if !res.Pass {
			t.Errorf("a remaining test fails: %+v", res.Test)
		}
	}
	if _, ok := p.Subject("noc_tier1"); !ok || len(p.Grants("noc_tier1")) != 2 {
		t.Fatal("nobody else's rows are touched")
	}
}

// A test naming the subject by one of its identities goes with it: left, it
// would load and quietly become a no_grants_matched deny.
func TestRemoveSubjectTakesTestsNamingItsIdentities(t *testing.T) {
	raw := string(spec11Raw(t)) + `  - {principal: "system:serviceaccount:netops:oxidized", device: leaf-01,
     command: "show version", expect: permit}
`
	out, r, err := RemoveSubject([]byte(raw), "svc_oxidized")
	if err != nil {
		t.Fatal(err)
	}
	if r.Tests != 3 || strings.Contains(string(out), "system:serviceaccount") {
		t.Fatalf("removed %+v:\n%s", r, out)
	}
}

func TestRemoveSubjectRefusesAnUndeclaredSubject(t *testing.T) {
	if _, _, err := RemoveSubject(spec11Raw(t), "svc_nobody"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("%v", err)
	}
}
