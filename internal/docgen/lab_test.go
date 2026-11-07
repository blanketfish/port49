package docgen

import (
	"os"
	"testing"
)

func TestLabRegisterReadsTheSpec(t *testing.T) {
	spec, err := os.ReadFile("../../docs/design/2026-08-23-policy-engine-spec.md")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := LabRegister(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg) <= 90 {
		t.Errorf("loaded %d rows, want more than 90", len(reg))
	}
	for id, open := range map[string]bool{"L4": true, "L78": true, "L45": false, "L73": false} {
		row, ok := reg[id]
		if !ok {
			t.Errorf("%s is missing from the register", id)
			continue
		}
		if row.Open != open {
			t.Errorf("%s: Open = %v, want %v", id, row.Open, open)
		}
	}
}

func TestLabRegisterSplitsEscapedPipes(t *testing.T) {
	spec := []byte("## 14. Before\n\n| **L1** | x | closed |\n\n## 15. Lab register\n\n" +
		"| ID | Claim | Platforms | Status |\n|---|---|---|---|\n" +
		"| **L7** | A claim with a `a \\| b` pipe in it | all | closed — measured 2026-01-01; `tests/lab/results/L7-x.md` |\n" +
		"| **L8** | Another \\| pipe | all | **closed** — measured |\n" +
		"| **L9a** | Plain | all | open — measure it |\n" +
		"| **L11** | x | all | closed \\| still closed here |\n" +
		"| **L12** | x | all | open — not yet \\| closed — later |\n\n## 16. After\n\n| **L10** | y | open |\n")
	reg, err := LabRegister(spec)
	if err != nil {
		t.Fatal(err)
	}
	// The pipe sits in the Status cell: a split that ignores the backslash changes the last cell.
	if got := splitCells("| **L12** | x | all | open — not yet \\| closed — later |"); len(got) != 4 {
		t.Errorf("a row with an escaped pipe split into %d cells %q, want 4", len(got), got)
	}
	want := map[string]bool{"L7": false, "L8": false, "L9a": true, "L11": false, "L12": true}
	if len(reg) != len(want) {
		t.Errorf("got %d rows %v, want %d", len(reg), reg, len(want))
	}
	for id, open := range want {
		if reg[id].Open != open {
			t.Errorf("%s: Open = %v, want %v", id, reg[id].Open, open)
		}
	}
}

func TestLabRegisterNeedsTheSection(t *testing.T) {
	if _, err := LabRegister([]byte("## 1. Nothing\n")); err == nil {
		t.Error("a spec without the register parsed")
	}
}

var suffixes = []string{"arista_eos", "cisco_nxos", "juniper_vjunos", "juniper_vjunos-router", "juniper_vsrx",
	"systemd-docker", "netbox"}

func TestNoteNamesMatchBySegments(t *testing.T) {
	for name, want := range map[string]string{
		"L88-cisco_nxos-nxos106-tls.md":                       "cisco_nxos",
		"L88-juniper_vjunos-router-vjunos26-tls.md":           "juniper_vjunos-router",
		"L4-error-juniper_vsrx.md":                            "juniper_vsrx",
		"L78-vJunos-router-26.2R1.7-juniper_vjunos-router.md": "juniper_vjunos-router",
		"L84-systemd-docker.md":                               "systemd-docker",
		"L4-L5-arista_eos.md":                                 "arista_eos",
		"L26b-keywords-juniper_vjunos.md":                     "juniper_vjunos",
	} {
		got, ok := MatchNote(name, suffixes)
		if !ok || got != want {
			t.Errorf("%s: got %q (%v), want %q", name, got, ok, want)
		}
	}
	if got, ok := MatchNote("L9-cisco_iosxe.md", suffixes); ok {
		t.Errorf("an unlisted platform matched %q", got)
	}
	if got, ok := MatchNote("L9-vjunos-router.md", suffixes); ok {
		t.Errorf("a bare vjunos-router is not a suffix's run, matched %q", got)
	}
}

func TestNotePartsSplitsTheLeadingIDs(t *testing.T) {
	ids, rest := NoteParts("L4-L5-error-juniper_vsrx.md")
	if len(ids) != 2 || ids[0] != "L4" || ids[1] != "L5" || len(rest) != 2 || rest[0] != "error" {
		t.Errorf("got %v %v", ids, rest)
	}
}
