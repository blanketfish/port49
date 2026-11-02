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
	for _, d := range p.Devices() {
		if d.Platform != platformName {
			continue
		}
		// A quarantined device mints nothing (spec §10), and any other
		// resolve error is a quarantine cause (checkDevices), so a refused
		// session lands in no class: skipped as ShadowedDenies, lint and
		// intersect skip it, never an error that fails the fleet.
		if _, q := p.Quarantined(d.Name, now); q {
			continue
		}
		for _, name := range sortedKeys(p.subs) {
			res, err := p.resolve(p.subs[name], d, now)
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
