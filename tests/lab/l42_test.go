//go:build lab

package lab

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/directory"
)

const l42Claim = "For alice (alice ∈ g-leaf ∈ g-mid ∈ netops-oncall), carol (∈ netops-oncall directly) and " +
	"dave (∈ g-loop-a, g-loop-a ∈ g-loop-b ∈ g-loop-a): which groups each nested mode returns on each directory; " +
	"whether member:1.2.840.113556.1.4.1941:= answers, errors or is refused, on the loop too, and how long it " +
	"takes; whether the user entry's memberOf lists only direct groups; and whether a directory that does not " +
	"implement the matching rule refuses the filter or answers it empty (policy engine spec §15 L42)."

// l42Want is what port49's own walk guarantees on both directories, whatever
// the directory does with the matching rule: the groups each user is in by
// `recursive` and by `direct`. in_chain is measured, not asserted.
var l42Want = map[string]map[directory.Nested][]string{
	"alice": {"recursive": {"g-leaf", "g-mid", "netops-oncall"}, "direct": {"g-leaf"}},
	"carol": {"recursive": {"netops-oncall"}, "direct": {"netops-oncall"}},
	"dave":  {"recursive": {"g-loop-a", "g-loop-b"}, "direct": {"g-loop-a"}},
}

func TestL42NestedGroups(t *testing.T) {
	d := startDirectories(t)
	for _, dir := range d.all() { // openldap, samba_ad
		t.Run(dir.name, func(t *testing.T) {
			ev := evidence(t, d, "L42-"+dir.name)
			var obs strings.Builder
			obs.WriteString(dir.configNote())
			obs.WriteString("| user | mode | groups returned | result | time |\n|---|---|---|---|---|\n")
			for _, mode := range []directory.Nested{"in_chain", "recursive", "direct"} {
				for _, user := range []string{"alice", "carol", "dave"} {
					ev.mark("L42 %s %s", user, mode)
					r := dir.resolverWith(t, dir.config(mode, dir.groupsBaseDN, dir.bindSimple(), sanEmail()), d.password, ev)
					ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
					start := time.Now()
					a, err := r.Verify(ctx, dir.principal(user))
					took := time.Since(start)
					cancel()
					groups := strings.Join(a.GroupNames, ", ")
					if groups == "" {
						groups = "(none)"
					}
					fmt.Fprintf(&obs, "| %s | %s | %s | %s | %s |\n", user, mode, groups,
						errOrOK(err), took.Round(time.Millisecond))
					if want, ok := l42Want[user][mode]; ok {
						if err != nil || !slices.Equal(a.GroupNames, want) {
							t.Errorf("%s %s: groups %v, err %v; port49's %s walk returns %v", user, mode, a.GroupNames, err, mode, want)
						}
					}
				}
			}
			ev.mark("L42 memberOf on alice's entry")
			fmt.Fprintf(&obs, "\nmemberOf on alice's entry: %s\n", strings.Join(dir.memberOf(t, "alice"), ", "))
			ev.assertClean(t, d.password)
			writeResult(t, d, "L42", dir.name, l42Claim, dir.version(t), obs.String(), "tests/lab/evidence/L42-"+dir.name+".json")
		})
	}
}
