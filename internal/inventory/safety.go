package inventory

import (
	"errors"
	"fmt"
	"slices"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/policy"
)

// checkSafety refuses next (spec §10, "Bounded change per sync"): empty, or
// admitting none under the service's policy, whatever any bound says; or with
// a source that takes more than its bound of the devices it gave prev out of
// service — removed from the bundle, kept and newly refused admission, or
// kept with no address left (port49d admits by address; pre-flight I2).
// A source prev had and the configuration no longer names is held to def,
// since its devices are leaving. prev nil, the first sync the service
// remembers, is bounded by nothing else: each port49d bounds it again.
func checkSafety(prev *Published, prevPol, next *policy.Policy, now map[string]bool, bounds map[string]int, def int,
	policyFile string) error {
	n := len(next.Devices())
	if n == 0 {
		return errors.New("the sources name no device; an empty inventory admits nothing, so it is never published " +
			"(spec §10)")
	}
	if refused := next.AdmissionRefusals(); len(refused) == n {
		return fmt.Errorf("the service's policy admits none of the %d device(s) (%s: %s); check key_groups in "+
			"policy_file %s", n, refused[0].Device.Name, refused[0].Refused, policyFile)
	}
	if prev == nil {
		return nil
	}
	newly := map[string]bool{}
	for _, r := range bundle.NewlyRefused(prevPol, next) {
		newly[r.Device.Name] = true
	}
	bare := map[string]bool{}
	for _, name := range bundle.Unaddressed(prevPol, next) {
		bare[name] = true
	}
	names := make([]string, 0, len(prev.Doc.Sources))
	for name := range prev.Doc.Sources {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		was := prev.Doc.Sources[name]
		b, ok := bounds[name]
		if !ok {
			b = def
		}
		if len(was) == 0 || b >= 100 {
			continue
		}
		removed, refused, unaddressed := 0, 0, 0
		for _, d := range was {
			switch {
			case !now[d]:
				removed++
			case newly[d]:
				refused++
			case bare[d]:
				unaddressed++
			}
		}
		if gone := removed + refused + unaddressed; gone*100 > len(was)*b {
			what := fmt.Sprintf("source %s removes %d of %d devices and refuses %d more", name, removed, len(was), refused)
			if unaddressed > 0 {
				// Pre-flight I2: port49d admits by address.
				what += fmt.Sprintf(" and leaves %d more with no address", unaddressed)
			}
			return fmt.Errorf("%s (%d%%), more than its safety.max_removed_percent (%d%%); fix the source, or, if "+
				"the change is meant, raise safety.max_removed_percent in port49-inventory.yaml and restart "+
				"port49-inventory", what, gone*100/len(was), b)
		}
	}
	return nil
}
