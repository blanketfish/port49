package policy

import (
	"time"

	"github.com/blanketfish/port49/internal/platform"
)

// ClassAges is the idle-timeout each of platformName's template classes
// carries (spec §5.6, §8; decision 55 ruling 14): for every subject and every
// inventory device of the platform it resolves the session that lands there,
// and a class takes the least positive ceiling among the sessions in it, def
// standing in for a role that names none. A class becomes zero, no
// idle-timeout line, only when every session in it is `never`; a class no
// session lands in is absent, and takes def. A subject with no grant on a
// device lands nowhere there, and a device on a platform that projects
// nothing has no class to land in.
func (p *Policy) ClassAges(platformName string, def time.Duration, now time.Time) (platform.ClassAges, error) {
	ages := platform.ClassAges{Default: def, ByClass: map[string]time.Duration{}}
	subjects := sortedKeys(p.subs)
	devs := p.Devices()
	// A subject lands in the same template class, at the same age, on every
	// device of one device class (scope.go, deviceClass), and a class takes
	// the least positive age among its sessions, else 0: a fold that does not
	// depend on order and gains nothing from a repeat. So a device class
	// is resolved on its first device that is not quarantined, and its other
	// members add nothing.
	classes, marks := p.deviceClassMarks(devs)
	for ci, members := range classes {
		if devs[members[0]].Platform != platformName {
			continue
		}
		rep := -1
		for _, i := range members {
			// A quarantined device mints nothing (spec §10), and any other
			// resolve error is a quarantine cause (checkDevices), so a refused
			// session lands in no class: skipped as ShadowedDenies, lint and
			// intersect skip it, never an error that fails the fleet.
			if _, q := p.Quarantined(devs[i].Name, now); !q {
				rep = i
				break
			}
		}
		if rep < 0 {
			continue
		}
		d := devs[rep]
		for _, name := range subjects {
			res, err := p.resolveMarked(p.subs[name], d, now, marks[ci])
			if err != nil || res.Projection == nil {
				continue
			}
			class := res.Projection.Template
			if class == "" {
				class = platform.RemoteClass
			}
			age := res.SessionAge.Of(def)
			prev, seen := ages.ByClass[class]
			switch {
			case !seen, prev == 0, age != 0 && age < prev:
				ages.ByClass[class] = age
			}
		}
	}
	return ages, nil
}
