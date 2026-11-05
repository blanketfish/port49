package policy

// The oracle: the per-device computations of Parse's joint checks, ClassAges,
// MFARequirements and Compare, frozen verbatim from base commit 1bd57ed0 (the
// branch HEAD when plan 12c Task 6b began), renamed and given the policy as an
// argument, with nothing else changed. The memoized code must give the results
// below, byte for byte, for every subject, device and instant (differential_test.go).
//
// The oracle reads p.grants and p.scopes directly: it never calls a memo,
// grantsOf, scopeNames, deviceClasses or checkDeviceOver. What it shares with
// production is the code the task does not touch: resolved, compile, project,
// layerAttributes, leftOffAttributes, jointCheck, mfaFor, selects and matches.

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/platform"
)

// oracleComposeAll is composeAll (scope.go:139-234 at 1bd57ed0).
func oracleComposeAll(p *Policy, subs []*Subject, d admission.Device, now time.Time) composition {
	sub := subs[0]
	c := composition{subject: sub, attached: map[string][]string{}}
	for _, g := range p.grants {
		if !slices.ContainsFunc(subs, func(s *Subject) bool { return s.Name == g.Subject }) {
			continue
		}
		if !g.Expires.IsZero() && !now.IsZero() && !now.Before(g.Expires) {
			continue
		}
		if ok, _ := p.scopes[g.Scope].selects(d); ok {
			c.grants = append(c.grants, g)
		}
	}
	if len(c.grants) == 0 {
		return c
	}
	sort.SliceStable(c.grants, func(i, j int) bool {
		a, b := c.grants[i], c.grants[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return strings.Join(a.Roles, ",") < strings.Join(b.Roles, ",")
	})
	escalates := false
	for _, g := range c.grants {
		escalates = escalates || p.subs[g.Subject].Enable != "none"
	}
	composed := len(subs) > 1 && escalates
	held := "" // the none subjects' contribution
	roles := map[string]bool{}
	for _, g := range c.grants {
		level := ""
		for _, r := range g.Roles {
			roles[r] = true
			if p.levelIndex(p.roles[r].Privilege) > p.levelIndex(level) {
				level = p.roles[r].Privilege
			}
		}
		if !composed || p.subs[g.Subject].Enable != "none" {
			if p.levelIndex(g.MaxPrivilege) > p.levelIndex(c.ceiling) {
				c.ceiling = g.MaxPrivilege
			}
			continue
		}
		limit := level
		if g.MaxPrivilege != "" && p.levelIndex(g.MaxPrivilege) < p.levelIndex(level) {
			limit = g.MaxPrivilege
		}
		if g.MaxPrivilege != "" && p.levelIndex(g.MaxPrivilege) > p.levelIndex(limit) {
			c.notCounted = append(c.notCounted, fmt.Sprintf("%s's max_privilege %s", g.Subject, g.MaxPrivilege))
		}
		if p.levelIndex(limit) > p.levelIndex(held) {
			held = limit
		}
	}
	if c.ceiling != "" && p.levelIndex(held) > p.levelIndex(c.ceiling) {
		c.ceiling = held
	}
	names := make([]string, 0, len(p.scopes))
	for name := range p.scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := p.scopes[name]
		ok, byIncomparable := s.selects(d)
		if !ok {
			continue
		}
		c.scopes = append(c.scopes, name)
		if byIncomparable && (len(s.Attached[sub.Domain]) > 0 || c.grantsOn(name)) {
			c.incomparable = append(c.incomparable, name)
		}
		for _, r := range s.Attached[sub.Domain] {
			roles[r] = true
			c.attached[r] = append(c.attached[r], name)
		}
	}
	for r := range roles {
		c.roles = append(c.roles, r)
		if p.levelIndex(p.roles[r].Privilege) > p.levelIndex(c.level) {
			c.level = p.roles[r].Privilege
		}
	}
	sort.Strings(c.roles)
	return c
}

// oracleResolve is resolve (resolve.go:160-166).
func oracleResolve(p *Policy, sub *Subject, d admission.Device, now time.Time) (Resolution, error) {
	c := oracleComposeAll(p, []*Subject{sub}, d, now)
	if len(c.grants) == 0 {
		return Resolution{}, ErrNoGrants
	}
	return p.resolved(sub, d, c)
}

// oracleResolveNow is resolveNow (resolve.go:139-156).
func oracleResolveNow(p *Policy, sub *Subject, d admission.Device, now time.Time) (Resolution, error) {
	c := oracleComposeAll(p, []*Subject{sub}, d, now)
	if len(c.grants) == 0 {
		return Resolution{}, ErrNoGrants
	}
	if err := p.quarantined(d, now); err != nil {
		return Resolution{}, err
	}
	if r, ok := p.admitted[d.Name]; p.AdmissionAssessed() && (!ok || r.Refused != "") {
		if !ok {
			r.Refused = "is not in the inventory admission assessed"
		}
		return Resolution{}, fmt.Errorf("%w: %s", ErrDeviceRefused, r.Refused)
	}
	return p.resolved(sub, d, c)
}

// oracleSubjectInstants is subjectInstants (lint.go:960-976).
func oracleSubjectInstants(p *Policy, sub *Subject, now time.Time) ([]time.Time, map[time.Time]string) {
	instants := []time.Time{now}
	lapsing := map[time.Time]string{}
	for _, g := range p.grants {
		if g.Subject != sub.Name || !g.Expires.After(now) {
			continue
		}
		if _, ok := lapsing[g.Expires]; ok {
			lapsing[g.Expires] += " and "
		} else {
			instants = append(instants, g.Expires)
		}
		lapsing[g.Expires] += "grant " + g.Scope + " [" + strings.Join(g.Roles, " ") + "]"
	}
	slices.SortFunc(instants[1:], func(a, b time.Time) int { return a.Compare(b) })
	return instants, lapsing
}

// oracleCheckDeviceAt is checkDeviceAt (resolve.go:735-744).
func oracleCheckDeviceAt(p *Policy, sub *Subject, d admission.Device, at time.Time) (cause string, mfa bool, pair string) {
	res, err := oracleResolve(p, sub, d, at)
	if errors.Is(err, ErrNoGrants) {
		return "", false, ""
	}
	if err != nil {
		return err.Error(), isMFAError(err), mfaPair(err)
	}
	return p.jointCheck(res, d), false, ""
}

// oracleCheckDevice is checkDevice (resolve.go:613-634).
func oracleCheckDevice(p *Policy, sub *Subject, d admission.Device, now time.Time) []QuarantineEntry {
	instants, lapsing := oracleSubjectInstants(p, sub, now)
	var out []QuarantineEntry
	open := false // whether the last entry is still failing
	for _, at := range instants {
		cause, mfa, pair := oracleCheckDeviceAt(p, sub, d, at)
		if cause != "" {
			cause = fmt.Sprintf("subject %q: %s", sub.Name, cause)
		}
		if open && cause == out[len(out)-1].Cause {
			continue
		}
		if open {
			out[len(out)-1].Until = at
		}
		open = cause != ""
		if open {
			out = append(out, QuarantineEntry{From: at, Lapsing: lapsing[at], Cause: cause, MFA: mfa, MFAPair: pair})
		}
	}
	return out
}

// oracleQuarantine is checkDevices (resolve.go:588-608), returning the map.
func oracleQuarantine(p *Policy) map[string]*Quarantine {
	quarantine := map[string]*Quarantine{}
	now := p.env.Now
	if now.IsZero() {
		now = time.Now()
	}
	for _, d := range p.env.Devices {
		for _, name := range sortedKeys(p.subs) {
			entries := oracleCheckDevice(p, p.subs[name], d, now)
			if len(entries) == 0 {
				continue
			}
			q, ok := quarantine[d.Name]
			if !ok {
				q = &Quarantine{Device: d.Name, Platform: d.Platform}
				quarantine[d.Name] = q
			}
			q.Entries = append(q.Entries, entries...)
		}
	}
	return quarantine
}

// oracleClassAges is ClassAges (classages.go:15-48).
func oracleClassAges(p *Policy, platformName string, def time.Duration, now time.Time) (platform.ClassAges, error) {
	ages := platform.ClassAges{Default: def, ByClass: map[string]time.Duration{}}
	for _, d := range p.Devices() {
		if d.Platform != platformName {
			continue
		}
		if _, q := p.Quarantined(d.Name, now); q {
			continue
		}
		for _, name := range sortedKeys(p.subs) {
			res, err := oracleResolve(p, p.subs[name], d, now)
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

// oracleMFAAt is mfaAt (mfa.go:374-385).
func oracleMFAAt(p *Policy, subject string, d admission.Device, at time.Time) (MFARequirement, bool) {
	sub, ok := p.subs[subject]
	if !ok {
		return MFARequirement{}, false
	}
	c := oracleComposeAll(p, []*Subject{sub}, d, at)
	if len(c.grants) == 0 {
		return MFARequirement{}, false
	}
	req, err := p.mfaFor(c)
	return req, err == nil
}

// oracleMFARequirements is MFARequirements (mfa.go:398-413).
func oracleMFARequirements(p *Policy, at time.Time) []DeviceMFA {
	subjects := sortedKeys(p.subs)
	var out []DeviceMFA
	for _, d := range p.Devices() {
		var reqs []MFARequirement
		for _, s := range subjects {
			r, ok := oracleMFAAt(p, s, d, at)
			if !ok || !r.Required() || slices.ContainsFunc(reqs, func(o MFARequirement) bool { return reflect.DeepEqual(o, r) }) {
				continue
			}
			reqs = append(reqs, r)
		}
		if len(reqs) > 0 {
			out = append(out, DeviceMFA{Device: d.Name, Requirements: reqs})
		}
	}
	return out
}

// oracleMintCheck is MintCheck (explain.go:228-246).
func oracleMintCheck(res Resolution, principal, device string) (code, detail string) {
	if _, _, err := engine.Encode(res.Blob); err != nil {
		return "broker_error", err.Error()
	}
	_, err := res.Blob.SessionAttributes(engine.Values{Username: res.Username, Principal: principal, Device: device})
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, engine.ErrAttributeTooLong):
		return "attribute_too_long", err.Error()
	case errors.Is(err, engine.ErrSubstitution):
		return "attribute_unsafe", err.Error()
	}
	return "broker_error", err.Error()
}

// oracleMintCheckAll is mintCheck (explain.go:270-280).
func oracleMintCheckAll(res Resolution, principals []string, device string) (code, detail string) {
	if len(principals) == 0 {
		principals = []string{""}
	}
	for _, pr := range principals {
		if code, detail := oracleMintCheck(res, pr, device); code != "" {
			return code, fmt.Sprintf("for %s: %s", pr, detail)
		}
	}
	return "", ""
}

// oracleSide is side (diff.go:413-447).
func oracleSide(p *Policy, subject string, d admission.Device, at time.Time) side {
	if _, ok := p.Quarantined(d.Name, at); ok {
		return side{quarantined: true}
	}
	sub, ok := p.subs[subject]
	if !ok {
		return side{}
	}
	res, err := oracleResolve(p, sub, d, at)
	if errors.Is(err, ErrNoGrants) {
		return side{}
	}
	if err != nil {
		return side{err: err}
	}
	if code, detail := oracleMintCheckAll(res, sub.Identity, d.Name); code != "" {
		return side{refused: code, refusedDetail: detail}
	}
	unbundled := res.Blob
	unbundled.Bundle = "diff"
	_, hash, err := engine.Encode(unbundled)
	if err != nil {
		return side{err: err}
	}
	prog, err := engine.Compile(res.Blob)
	if err != nil {
		return side{err: err}
	}
	priv := privilege{level: res.Level, ceiling: res.Ceiling, hasMax: res.HasCeiling, max: res.MaxPrivilege,
		device: NoCeiling, enable: res.Enable, reply: strings.Join(sessionReply(res), replySep), platform: d.Platform}
	if n, ok := p.devicePrivLvl(res, d.Platform); ok {
		priv.device = strconv.Itoa(int(n))
	}
	return side{prog: prog, res: res, hash: hash, priv: priv, age: res.SessionAge}
}

// oracleSides is the sideSource that resolves every subject on every device
// with the frozen functions above.
type oracleSides struct{}

func (oracleSides) side(p *Policy, subject string, _ int, d admission.Device, at time.Time) side {
	return oracleSide(p, subject, d, at)
}

func (oracleSides) mfaAt(p *Policy, subject string, _ int, d admission.Device, at time.Time) (MFARequirement, bool) {
	return oracleMFAAt(p, subject, d, at)
}
