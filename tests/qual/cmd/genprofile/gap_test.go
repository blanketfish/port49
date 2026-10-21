package main

import (
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/devicemock"
)

// SR Linux's missing command authorization is L76 cell b's, not the Junos row's L18.
func TestNoCommandAuthorizationGapCitesItsOwnRow(t *testing.T) {
	note := devicemock.Source{Note: "tests/lab/results/QUAL-x.md", Register: "QUAL"}
	g := noCommandAuthorizationGap("nokia_srlinux", note)
	if !strings.Contains(g.What, "L76 cell b") || strings.Contains(g.What, "L18") || len(g.Sources) != 2 || g.Sources[1].Register != "L76" {
		t.Fatalf("%+v", g)
	}
	if j := noCommandAuthorizationGap("juniper_junos", note); !strings.Contains(j.What, "(L18)") || len(j.Sources) != 1 {
		t.Fatalf("%+v", j)
	}
}
