package sot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rhwendt/port49/internal/admission"
)

// Config is one netbox or nautobot source as port49-inventory.yaml gives it;
// internal/inventory's Load checks every field before New sees it.
type Config struct {
	Name, Product string
	// URL is https, with a named CAFile (decision 31).
	URL, CAFile string
	Token       Secret
	// Profile, set, is taken in place of the detected one.
	Profile string
	// API is "auto" (GraphQL, REST on a 404), "graphql" or "rest".
	API      string
	PageSize int
	Mapping  Mapping
	// Log is where the source says what it found, once each: its release
	// and profile, a rebuilt next, a fact it could not read.
	Log io.Writer
}

// maxNotes bounds the notes a source remembers as said: past it, a note is
// not said again, and memory stays bounded whatever a source sends.
const maxNotes = 256

// Source is one NetBox or Nautobot source: an inventory.Source.
type Source struct {
	cfg Config
	c   *client

	mu    sync.Mutex
	said  map[string]bool
	shown string // the release, profile and API last said
	// last is the names of the devices the last successful read kept, nil
	// before one: what a read that lacks one of them must confirm is gone.
	last map[string]bool
}

// New is the source cfg describes. It reads the CA file once, so a missing
// one is said at start.
func New(cfg Config) (*Source, error) {
	c, err := newClient(cfg.URL, cfg.CAFile, cfg.Token, cfg.Product)
	if err != nil {
		return nil, fmt.Errorf("source %s: %w", cfg.Name, err)
	}
	return &Source{cfg: cfg, c: c, said: map[string]bool{}}, nil
}

func (s *Source) Name() string { return s.cfg.Name }

// listing is one read of the list: the devices kept, the profile read with,
// and the name of every device the list gave, kept or not.
type listing struct {
	inv   admission.Inventory
	p     Profile
	names map[string]bool
}

// Fetch reads every device: the release from /api/status/ and its profile,
// the list over GraphQL — checked against REST's count — or over REST, and
// each device through the mapping. A device the last read kept and this one
// lacks is asked for by name before it counts as removed (removal
// confirmation): offset paging skips a live device at a page boundary when a
// rename moves one from before the boundary to after it, or a delete before
// it meets an insert after it, and every count still holds. Still there and
// in scope, the list is read once more; a second such read fails the sync,
// so a shifting list never reads as a removal. Every request is under ctx,
// which the syncer bounds by sync_timeout. Nothing it reads can assign a
// key.
func (s *Source) Fetch(ctx context.Context) (admission.Inventory, error) {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	for try := 0; ; try++ {
		l, err := s.read(ctx)
		if err != nil {
			return admission.Inventory{}, err
		}
		skipped, err := s.skipped(ctx, l, last)
		if err != nil {
			return admission.Inventory{}, err
		}
		if !skipped {
			kept := make(map[string]bool, len(l.inv.Devices))
			for _, d := range l.inv.Devices {
				if d.Name != "" {
					kept[d.Name] = true
				}
			}
			s.mu.Lock()
			s.last = kept
			s.mu.Unlock()
			return l.inv, nil
		}
		if try == 1 {
			return admission.Inventory{}, errors.New("two reads running lacked a device the last sync read that " +
				"is still there and in scope when asked for by name: the list shifted during the read (a rename, " +
				"or a delete and an insert, across a page boundary); the next sync reads it again")
		}
	}
}

// skipped is whether some device last kept that l lacks is still there by
// name and kept by the filter: a device the read skipped, not one removed.
// It asks for each such name over REST's ?name= (L30: count 1 on every
// release), at most as many as last holds, under one maxFetch budget, and
// stops at the first still there.
func (s *Source) skipped(ctx context.Context, l listing, last map[string]bool) (bool, error) {
	b := newBudget()
	for _, name := range sortedKeys(last) {
		if l.names[name] {
			continue
		}
		devs, err := s.c.restNamed(ctx, l.p, name, b)
		if err != nil {
			return false, err
		}
		for _, raw := range devs {
			if n, _ := raw["name"].(string); n != name {
				continue
			}
			if _, keep, _ := s.cfg.Mapping.device(l.p, "rest", raw); keep {
				return true, nil
			}
		}
	}
	return false, nil
}

// read is one whole read: the release, the profile, the list and the map.
func (s *Source) read(ctx context.Context) (listing, error) {
	var status map[string]any
	if err := s.c.getJSON(ctx, s.c.at("/api/status/", nil), &status); err != nil {
		return listing{}, err
	}
	v, err := versionOf(status, s.cfg.Product)
	if err != nil {
		return listing{}, err
	}
	p, measured, err := Detect(v, s.cfg.Profile)
	if err != nil {
		return listing{}, err
	}
	if n := detectNote(v, p, measured, s.cfg.Profile); n != "" {
		s.note(n)
	}
	api := s.cfg.API
	if api == "" || api == "auto" {
		api = "graphql"
	}
	if err := s.cfg.Mapping.check(p, api); err != nil {
		return listing{}, err
	}
	var raws []map[string]any
	if api == "graphql" {
		raws, err = s.graphql(ctx, p)
		if errors.Is(err, errNoGraphQL) && (s.cfg.API == "" || s.cfg.API == "auto") {
			if cerr := s.cfg.Mapping.check(p, "rest"); cerr != nil {
				return listing{}, fmt.Errorf("GraphQL answered HTTP 404, and %w", cerr)
			}
			s.note("GraphQL answered HTTP 404, so the devices are read over REST; set api: rest to say so, or turn " +
				"GraphQL on")
			api = "rest"
		}
	}
	if api == "rest" {
		var rebuilt bool
		raws, rebuilt, err = s.c.restDevices(ctx, p, s.cfg.PageSize)
		if rebuilt {
			s.note("a page's next names another scheme, host or port than url; it is rebuilt on url, and the token " +
				"is sent nowhere else: check the proxy's Host and X-Forwarded-Proto headers")
		}
	}
	if err != nil {
		return listing{}, err
	}
	s.show(v, p, api)
	l := listing{p: p, names: make(map[string]bool, len(raws))}
	for _, raw := range raws {
		if n, _ := raw["name"].(string); n != "" {
			l.names[n] = true
		}
		d, keep, notes := s.cfg.Mapping.device(p, api, raw)
		for _, n := range notes {
			s.note(n)
		}
		if keep {
			l.inv.Devices = append(l.inv.Devices, d)
		}
	}
	// Pre-flight M14: a default path many installations leave empty
	// (Nautobot's platform.network_driver) leaves every device out, one line
	// each; say once where to look.
	devs := l.inv.Devices
	if noPlatform := len(devs) - withPlatform(devs); len(devs) > 0 && noPlatform*2 > len(devs) {
		s.note(fmt.Sprintf("%d of %d device(s) give no %s, so they have no platform and are left out: map "+
			"platform to another path (map: {platform: ...}, e.g. platform.name or platform.slug)", noPlatform,
			len(devs), s.cfg.Mapping.mapOf(p)["platform"]))
	}
	return l, nil
}

// detectNote is what the source says of the profile it reads v with, or "":
// a release no lab run measured, and a profile named by override that
// detection would not pick. A measured release read by override is not said
// to be unmeasured.
func detectNote(v Version, p Profile, measured bool, override string) string {
	if measured {
		return ""
	}
	release := productName(v.Product) + " " + v.Text
	if override == "" {
		return fmt.Sprintf("%s is not a release a lab run measured (%s); it is read with profile %s, and a field "+
			"it does not give fails the sync", release, measuredList(v.Product), p.Name)
	}
	if !isMeasured(v) {
		return fmt.Sprintf("%s is not a release a lab run measured (%s); it is read as profile %s by override, "+
			"and a field it does not give fails the sync", release, measuredList(v.Product), p.Name)
	}
	auto, _ := pick(v)
	return fmt.Sprintf("%s is read as profile %s by override; detection picks %s, and a field %s does not give "+
		"fails the sync", release, p.Name, auto, release)
}

func withPlatform(devs []admission.Device) int {
	n := 0
	for _, d := range devs {
		if d.Platform != "" {
			n++
		}
	}
	return n
}

// graphql is the GraphQL list, taken only when its length equals REST's
// count read before it and after it (pre-flight I1, amending decision 31's
// "either"): a server cap, or a page boundary lost to a concurrent delete —
// which shortens the list and the after count alike — would otherwise drop
// a live device. The next sync, or the debouncer's one more, reads it again.
func (s *Source) graphql(ctx context.Context, p Profile) ([]map[string]any, error) {
	before, err := s.c.restCount(ctx)
	if err != nil {
		return nil, err
	}
	devs, err := s.c.graphqlDevices(ctx, p, s.cfg.Mapping.selection(p), s.cfg.PageSize)
	if err != nil {
		return nil, err
	}
	after, err := s.c.restCount(ctx)
	if err != nil {
		return nil, err
	}
	if n := len(devs); n != before || before != after {
		return nil, fmt.Errorf("GraphQL gave %d devices and REST counts %d before and %d after: a page was lost, "+
			"a server capped the list, or the list changed during the sync; the next sync reads it again", n,
			before, after)
	}
	return devs, nil
}

// show says the release, the profile and the API read, when they change.
func (s *Source) show(v Version, p Profile, api string) {
	named := ""
	if s.cfg.Profile != "" {
		named = " (named)"
	}
	over := map[string]string{"graphql": "GraphQL", "rest": "REST"}[api]
	line := fmt.Sprintf("%s %s, profile %s%s, over %s", productName(v.Product), v.Text, p.Name, named, over)
	s.mu.Lock()
	defer s.mu.Unlock()
	if line != s.shown {
		s.shown = line
		fmt.Fprintf(s.cfg.Log, "port49-inventory: source %s: %s\n", s.cfg.Name, line)
	}
}

// note says text once.
func (s *Source) note(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.said[text] || len(s.said) >= maxNotes {
		return
	}
	s.said[text] = true
	fmt.Fprintf(s.cfg.Log, "port49-inventory: source %s: %s\n", s.cfg.Name, text)
}
