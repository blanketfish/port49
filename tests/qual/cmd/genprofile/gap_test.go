package main

import (
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/devicemock"
)

// SR Linux's missing command authorization is L76 cell b's, not the Junos row's L18.
func TestNoCommandAuthorizationGapCitesItsOwnRow(t *testing.T) {
	note := devicemock.Source{Note: "tests/lab/results/QUAL-x.md", Register: "QUAL"}
	l18 := []byte("- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)\n")
	g := noCommandAuthorizationGap("nokia_srlinux", "SR Linux 26.7.2-519", nil, note)
	if !strings.Contains(g.What, "L76 cell b") || strings.Contains(g.What, "L18") || len(g.Sources) != 2 || g.Sources[1].Register != "L76" {
		t.Fatalf("%+v", g)
	}
	if j := noCommandAuthorizationGap("juniper_junos", "vJunos-router 23.4R2-S2.1", l18, note); !strings.Contains(j.What, "(L18)") || len(j.Sources) != 1 {
		t.Fatalf("%+v", j)
	}
	// L18 never measured 26.2: its own QUAL records back the gap (final review M2).
	for _, l := range [][]byte{l18, nil} {
		if j := noCommandAuthorizationGap("juniper_junos", "vJunos-router 26.2R1.7", l, note); !strings.Contains(j.What, "(QUAL; as L18)") || len(j.Sources) != 1 {
			t.Fatalf("%+v", j)
		}
	}
}
