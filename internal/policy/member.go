package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/spiffe"
)

// DirectoryMode is whether the process loading a policy resolves humans
// through a directory (plan 7g, Ruling 16): its broker's, on or off; an
// offline tool or the inventory service does not know.
type DirectoryMode int

const (
	DirectoryUnknown DirectoryMode = iota
	DirectoryOn
	DirectoryOff
)

// The trust domains, as a Subject's Domain and attached_roles name them.
const (
	DomainHumans   = "humans"
	DomainMachines = "machines"
)

// Member is a principal as the broker resolved it.
type Member struct {
	Principal string
	// Domain is the verifier's list the principal came from: DomainMachines
	// for a workload the broker resolved through the workload mapping
	// (decision 41), DomainHumans or "" for a person.
	Domain     string
	Directory  bool
	Username   string
	GroupDNs   []string
	GroupNames []string
}

// MemberOf is a principal with no directory: identity subjects alone.
func MemberOf(principal string) Member { return Member{Principal: principal} }

// ErrCompositionRefused is composition_refused (spec §5.7): the principal's
// subjects compose on the device to a reply a joint check refuses.
var ErrCompositionRefused = errors.New("policy: the principal's subjects compose to a reply a joint check refuses")

// ErrNoUsername is a directory member with no username: the broker answers
// identity_unmapped (spec §5.7), and nothing is minted.
var ErrNoUsername = errors.New("policy: the directory gave this principal no username")

// subjectsOf is every subject m matches, by name: the identity subject
// listing it, and each group subject whose group m is in (spec §2;
// decision 38).
func (p *Policy) subjectsOf(m Member) []*Subject {
	var out []*Subject
	if name, ok := p.byID[m.Principal]; ok {
		out = append(out, p.subs[name])
	}
	// A group subject matches people and a machine_group subject workloads,
	// each only its own domain's (design §7; decision 41 ruling 5).
	if domain := p.groupDomainOf(m); domain != "" {
		for _, name := range sortedKeys(p.subs) {
			if sub := p.subs[name]; sub.Group != "" && sub.Domain == domain && sub.matches(m) {
				out = append(out, sub)
			}
		}
	}
	slices.SortFunc(out, func(a, b *Subject) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// groupDomainOf is the domain whose group subjects m may match: humans for a
// user: principal the directory resolved, machines for a workload's SPIFFE ID
// resolved through the workload mapping, "" otherwise. Both the member's
// domain and the principal's form must agree, so a mislabeled member matches
// no group at all.
func (p *Policy) groupDomainOf(m Member) string {
	switch {
	case !m.Directory:
		return ""
	case m.Domain != DomainMachines && strings.HasPrefix(m.Principal, "user:") && p.env.Directory != DirectoryOff:
		return DomainHumans
	case m.Domain == DomainMachines && strings.HasPrefix(m.Principal, spiffe.Scheme) &&
		p.env.WorkloadDirectory != DirectoryOff:
		return DomainMachines
	}
	return ""
}

// DeclaredFor is the username the identity subject listing principal declares,
// "" when none lists it or it declares none (decision 41 ruling 4).
func (p *Policy) DeclaredFor(principal string) string {
	if name, ok := p.byID[principal]; ok {
		return p.subs[name].Username
	}
	return ""
}

// matches reports whether a group subject's group is one of m's: by DN,
// compared in the directory's canonical form, or by a name m's directory verified unique.
func (s *Subject) matches(m Member) bool {
	if s.groupDN != "" {
		return slices.ContainsFunc(m.GroupDNs, func(dn string) bool { return directory.CanonicalDN(dn) == s.groupDN })
	}
	return slices.ContainsFunc(m.GroupNames, func(n string) bool { return strings.EqualFold(n, s.Group) })
}

// SubjectsOf is the names of every subject m matches, sorted.
func (p *Policy) SubjectsOf(m Member) []string {
	var out []string
	for _, s := range p.subjectsOf(m) {
		out = append(out, s.Name)
	}
	return out
}

// HasRightOf reports whether any subject m matches declares right
// (Ruling 13).
func (p *Policy) HasRightOf(m Member, right string) bool {
	return slices.ContainsFunc(p.subjectsOf(m), func(s *Subject) bool { return slices.Contains(s.API, right) })
}

// ResolveMember is spec §5.1 for m on d at now: every matching subject's
// grants compose (Ruling 5). One identity subject and no directory is
// Resolve exactly as before plan 7g.
func (p *Policy) ResolveMember(m Member, d admission.Device, now time.Time) (Resolution, error) {
	subs := p.subjectsOf(m)
	if len(subs) == 0 {
		return Resolution{}, ErrNoGrants
	}
	// The directory gives the username (spec §2, decision 38); one it did not
	// give is identity_unmapped at the broker, and nothing falls back to a
	// declared name.
	if m.Directory && m.Username == "" {
		return Resolution{}, ErrNoUsername
	}
	if len(subs) == 1 && !m.Directory {
		return p.resolveNow(subs[0], d, now)
	}
	return p.resolveAll(subs, m.Username, d, now, true)
}

// ResolveSubjects is ResolveMember for subjects named directly, as a
// record names them: replay recompiles a blob from it with no directory.
func (p *Policy) ResolveSubjects(names []string, username string, d admission.Device, now time.Time) (Resolution, error) {
	var subs []*Subject
	for _, n := range names {
		s, ok := p.subs[n]
		if !ok {
			return Resolution{}, fmt.Errorf("policy: subject %q is not declared", n)
		}
		subs = append(subs, s)
	}
	return p.resolveAll(subs, username, d, now, false)
}

func (p *Policy) resolveAll(subs []*Subject, username string, d admission.Device, now time.Time,
	check bool) (Resolution, error) {
	c := p.composeAll(subs, d, now)
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
	granting := c.granting(subs)
	merged := &Subject{Name: granting[0].Name, Domain: granting[0].Domain, Username: username}
	if username == "" && !check { // replay of a record with no session username
		for _, s := range granting {
			if s.Username != "" {
				merged.Username = s.Username
			}
		}
	}
	merged.Enable, merged.TokenTTL = strongestEnable(granting), leastTTL(granting)
	res, err := p.resolved(merged, d, c)
	if err != nil {
		// Two subjects of one principal compose only here, so levels they
		// bring together that accept no common method are found only here: the
		// item is composition_refused, recorded, never a broker fault
		// (decision 45 ruling 11; replay reads it the same way, unchecked).
		if len(granting) > 1 && isMFAError(err) {
			names := make([]string, len(granting))
			for i, s := range granting {
				names[i] = s.Name
			}
			return Resolution{}, fmt.Errorf("%w: subjects %s on %s: %v", ErrCompositionRefused,
				strings.Join(names, ", "), d.Name, err)
		}
		return res, err
	}
	if len(granting) > 1 {
		res.Subject = ""
		for _, s := range granting {
			res.Subjects = append(res.Subjects, s.Name)
		}
		if check {
			if cause := p.jointCheck(res, d); cause != "" {
				if len(c.notCounted) > 0 {
					cause += "; not counted beyond the level its roles reach, because its enable is none and " +
						"another subject offers escalation (spec §5.1): " + strings.Join(c.notCounted, ", ")
				}
				return Resolution{}, fmt.Errorf("%w: subjects %s on %s: %s", ErrCompositionRefused,
					strings.Join(res.Subjects, ", "), d.Name, cause)
			}
		}
	}
	return res, nil
}

// strongestEnable is the mechanism demanding the most proof among those
// the subjects offer: token, then auto, then none (Ruling 5).
func strongestEnable(subs []*Subject) string {
	best := "none"
	for _, s := range subs {
		switch {
		case s.Enable == "token":
			return "token"
		case s.Enable == "auto":
			best = "auto"
		}
	}
	return best
}

func leastTTL(subs []*Subject) time.Duration {
	var least time.Duration
	for _, s := range subs {
		if s.TokenTTL > 0 && (least == 0 || s.TokenTTL < least) {
			least = s.TokenTTL
		}
	}
	return least
}

// GroupValues is every group: subject's value, once each, sorted: the people
// pre-warm enumerates (Ruling 20). A machine_group: is never in it.
func (p *Policy) GroupValues() []string { return p.groupValues(DomainHumans) }

// MachineGroupValues is every machine_group: subject's value, once each,
// sorted: the workloads pre-warm enumerates (decision 41 ruling 6).
func (p *Policy) MachineGroupValues() []string { return p.groupValues(DomainMachines) }

func (p *Policy) groupValues(domain string) []string {
	var out []string
	for _, s := range p.subs {
		if s.Group != "" && s.Domain == domain {
			out = append(out, s.Group)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// GroupSubjects is every group: subject's name, sorted.
func (p *Policy) GroupSubjects() []string { return p.groupSubjects(DomainHumans) }

// MachineGroupSubjects is every machine_group: subject's name, sorted.
func (p *Policy) MachineGroupSubjects() []string { return p.groupSubjects(DomainMachines) }

func (p *Policy) groupSubjects(domain string) []string {
	var out []string
	for _, name := range sortedKeys(p.subs) {
		if s := p.subs[name]; s.Group != "" && s.Domain == domain {
			out = append(out, name)
		}
	}
	return out
}

// DeclaredUsernames is every username a subject declares, by username.
func (p *Policy) DeclaredUsernames() map[string]string {
	out := map[string]string{}
	for name, s := range p.subs {
		if s.Username != "" {
			out[s.Username] = name
		}
	}
	return out
}

// SPIFFEIdentities is every spiffe:// identity a subject lists, with the
// subject that lists it: the ones the start checks against the workload
// verifier's trust domains (decision 40 ruling 16).
func (p *Policy) SPIFFEIdentities() map[string]string {
	out := map[string]string{}
	for id, name := range p.byID {
		if strings.HasPrefix(id, spiffe.Scheme) {
			out[id] = name
		}
	}
	return out
}
