package sot

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

// source is a Source over a replay of stack, with m as its mapping.
func source(t *testing.T, stack string, n int, api string, m Mapping) (*Source, *sottest.Server, *bytes.Buffer) {
	t.Helper()
	s := sottest.New(t, stack, n)
	out := &bytes.Buffer{}
	src, err := New(Config{Name: "sot_" + strings.NewReplacer("-", "_", ".", "_").Replace(stack),
		Product: strings.SplitN(stack, "-", 2)[0], URL: s.URL, CAFile: s.CAFile, Token: NewSecret(token), API: api,
		PageSize: 50, Mapping: m, Log: out})
	if err != nil {
		t.Fatal(err)
	}
	return src, s, out
}

// Each recorded release, read over GraphQL with its default map and over
// REST with a map REST gives, reads all 120 devices to the same facts.
func TestEveryRecordedReleaseReadsToTheSameFacts(t *testing.T) {
	restMap := map[string]map[string]string{
		"nautobot-1.6": {"platform": "platform.slug", "site": "site.slug", "role": "role.slug"},
	}
	for _, stack := range []string{"netbox-3.7", "netbox-4", "nautobot-1.6", "nautobot-2", "nautobot-3"} {
		for _, api := range []string{"graphql", "rest"} {
			m := Mapping{Map: restMap[stack], Filter: Filter{Status: []string{"active"}}, Addresses: Addresses{Primary: true}}
			if api == "graphql" {
				m.Map = nil
			}
			src, s, out := source(t, stack, 120, api, m)
			inv, err := src.Fetch(context.Background())
			if err != nil || len(inv.Devices) != 120 {
				t.Fatalf("%s %s: %d devices, %v\n%s", stack, api, len(inv.Devices), err, out)
			}
			d := inv.Devices[119]
			if d.Name != sottest.Name(120) || d.Platform != "arista_eos" || d.Attributes["site"] != "dc1" ||
				d.Attributes["role"] != "leaf" || addrs(d.Addresses) != strings.TrimSuffix(sottest.Addr(120, 5), "/32") ||
				d.KeyRef != "" {
				t.Errorf("%s %s: %+v", stack, api, d)
			}
			// Said once: the release, the profile and the API it read.
			if !strings.Contains(out.String(), "port49-inventory: source "+src.Name()+": ") ||
				!strings.Contains(out.String(), "over "+map[string]string{"graphql": "GraphQL", "rest": "REST"}[api]) {
				t.Errorf("%s %s: said %q", stack, api, out)
			}
			for _, r := range s.Requests() {
				if r.Authorization == "" {
					t.Fatalf("%s %s: a request without the token", stack, api)
				}
			}
			if strings.Contains(out.String(), token) {
				t.Fatalf("%s %s: the token was said", stack, api)
			}
		}
	}
}

// Decision 31: a GraphQL list short of REST's count, before and after,
// fails the fetch and returns nothing that would look like devices removed.
func TestAGraphQLListShortOfTheCountFails(t *testing.T) {
	src, s, _ := source(t, "netbox-4", 120, "graphql", Mapping{Addresses: Addresses{Primary: true}})
	s.DropFromGraphQL = 1
	inv, err := src.Fetch(context.Background())
	if err == nil || len(inv.Devices) != 0 ||
		!strings.Contains(err.Error(), "GraphQL gave 119 devices and REST counts 120 before and 120 after") {
		t.Fatalf("%d devices, %v", len(inv.Devices), err)
	}
}

// Pre-flight I1: a delete between pages shifts every later page left and
// drops a live device at the boundary, while the list and the count after
// agree. Neither reader takes such a list.
func TestADeleteBetweenPagesFailsEitherRead(t *testing.T) {
	for api, want := range map[string]string{
		"graphql": "GraphQL gave 119 devices and REST counts 120 before and 119 after",
		"rest":    "REST page 1 counts 119 devices and page 0 counted 120",
	} {
		src, s, _ := source(t, "netbox-4", 120, api, Mapping{Addresses: Addresses{Primary: true}})
		s.DeleteAfterPage = 1
		inv, err := src.Fetch(context.Background())
		if err == nil || len(inv.Devices) != 0 || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %d devices, %v", api, len(inv.Devices), err)
		}
	}
}

// Pre-flight M1: a Source printed whole does not print its token.
func TestASourcePrintedWholeHoldsNoToken(t *testing.T) {
	src, _, _ := source(t, "netbox-4", 1, "graphql", Mapping{Addresses: Addresses{Primary: true}})
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, src); strings.Contains(out, token) {
			t.Fatalf("%s printed the token", verb)
		}
	}
}

// Pre-flight M14: when most devices give no platform under the map, the
// source says once where to look.
func TestAnEmptyPlatformPathIsPointedAt(t *testing.T) {
	src, _, out := source(t, "nautobot-3", 3, "graphql", Mapping{Addresses: Addresses{Primary: true},
		Map: map[string]string{"platform": "platform.name", "site": "location.name"}})
	// platform.name is "eos" on every replayed device: no note.
	src.Fetch(context.Background())
	if strings.Contains(out.String(), "give no") {
		t.Fatalf("%s", out)
	}
	src, _, out = source(t, "nautobot-3", 3, "graphql", Mapping{Addresses: Addresses{Primary: true},
		Map: map[string]string{"platform": "custom_fields.no_such_field"}})
	src.Fetch(context.Background())
	if !strings.Contains(out.String(), "3 of 3 device(s) give no custom_fields.no_such_field") {
		t.Fatalf("%s", out)
	}
}

// api auto reads REST when GraphQL answers 404, and says so once; api
// graphql does not.
func TestAMissingGraphQLFallsBackOnlyWhenAuto(t *testing.T) {
	src, s, out := source(t, "nautobot-2", 3, "auto", Mapping{Addresses: Addresses{Primary: true}})
	s.GraphQLStatus = http.StatusNotFound
	inv, err := src.Fetch(context.Background())
	if err != nil || len(inv.Devices) != 3 || !strings.Contains(out.String(), "GraphQL answered HTTP 404, so the "+
		"devices are read over REST") {
		t.Fatalf("%d %v %s", len(inv.Devices), err, out)
	}
	src, s, _ = source(t, "nautobot-2", 3, "graphql", Mapping{Addresses: Addresses{Primary: true}})
	s.GraphQLStatus = http.StatusNotFound
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "GraphQL answered HTTP 404") {
		t.Fatalf("got %v", err)
	}
	// With interfaces asked for, there is no REST to fall back to.
	src, s, _ = source(t, "nautobot-2", 3, "auto", Mapping{Addresses: Addresses{AllInterfaces: true}})
	s.GraphQLStatus = http.StatusNotFound
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "REST does not give") {
		t.Fatalf("got %v", err)
	}
	// Nothing follows the POST that got the 404: the count before it is
	// asked, and no REST list after it.
	reqs := s.Requests()
	if last := reqs[len(reqs)-1]; last.Method != http.MethodPost {
		t.Fatalf("after the 404: %+v", last)
	}
	if prev := reqs[len(reqs)-2]; prev.Method != http.MethodGet || prev.RawQuery != "limit=1" {
		t.Fatalf("before the 404: %+v", prev)
	}
}

// A next on another origin is followed on the base, and said once a source.
func TestARebuiltNextIsSaidOnce(t *testing.T) {
	src, s, out := source(t, "netbox-4", 120, "rest", Mapping{Addresses: Addresses{Primary: true}})
	s.NextHost = "proxy.internal:8443"
	for i := 0; i < 2; i++ {
		if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != 120 {
			t.Fatalf("%d %v", len(inv.Devices), err)
		}
	}
	if n := strings.Count(out.String(), "a page's next names another scheme, host or port than url; it is rebuilt "+
		"on url, and the token is sent nowhere else"); n != 1 {
		t.Fatalf("said %d times: %s", n, out)
	}
}

func TestTheProfileOverrideAndTheTypeAreHeld(t *testing.T) {
	s := sottest.New(t, "nautobot-3", 2)
	src, _ := New(Config{Name: "x", Product: "netbox", URL: s.URL, CAFile: s.CAFile, Token: NewSecret(token),
		PageSize: 50, Log: &bytes.Buffer{}})
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "answers as Nautobot") {
		t.Fatalf("got %v", err)
	}
	out := &bytes.Buffer{}
	src, _ = New(Config{Name: "x", Product: "nautobot", URL: s.URL, CAFile: s.CAFile, Token: NewSecret(token),
		Profile: Nautobot2, PageSize: 50, Mapping: Mapping{Addresses: Addresses{Primary: true}}, Log: out})
	if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != 2 ||
		!strings.Contains(out.String(), "Nautobot 3.2.6, profile nautobot_2 (named), over GraphQL") {
		t.Fatalf("%v %s", err, out)
	}
}

func TestTheReleaseIsSaidOnceWhileItHolds(t *testing.T) {
	src, _, out := source(t, "netbox-4", 3, "graphql", Mapping{Addresses: Addresses{Primary: true},
		Map: map[string]string{"platform": "platform.slug", "owner": "custom_fields.os_version"}})
	src.Fetch(context.Background())
	src.Fetch(context.Background())
	if strings.Count(out.String(), "port49-inventory: source "+src.Name()+": NetBox 4.7.1") != 1 {
		t.Fatalf("%s", out)
	}
}

// Controller ruling (Task 3 review): an override is named as one, and a
// measured release read by override is not said to be unmeasured.
func TestAnOverrideIsSaidAsOne(t *testing.T) {
	s := sottest.New(t, "nautobot-3", 2)
	out := &bytes.Buffer{}
	src, err := New(Config{Name: "x", Product: "nautobot", URL: s.URL, CAFile: s.CAFile, Token: NewSecret(token),
		Profile: Nautobot16, API: "graphql", PageSize: 50, Mapping: Mapping{Addresses: Addresses{Primary: true}},
		Log: out})
	if err != nil {
		t.Fatal(err)
	}
	src.Fetch(context.Background())
	if !strings.Contains(out.String(), "Nautobot 3.2.6 is read as profile nautobot_1_6 by override; detection "+
		"picks nautobot_2") || strings.Contains(out.String(), "not a release a lab run measured") {
		t.Fatalf("%s", out)
	}
	// An unmeasured release read by override is said to be both.
	v := Version{Product: "nautobot", Text: "2.9.1", Major: 2, Minor: 9}
	p, measured, _ := Detect(v, Nautobot2)
	if got := detectNote(v, p, measured, Nautobot2); !strings.Contains(got, "not a release a lab run measured") ||
		!strings.Contains(got, "read as profile nautobot_2 by override") {
		t.Fatalf("%s", got)
	}
}

// fetches reads src once to remember its devices, sets shift on s, and
// reads it again.
func fetches(t *testing.T, src *Source, s *sottest.Server, shift func()) (int, error) {
	t.Helper()
	if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != 120 {
		t.Fatalf("first read: %d %v", len(inv.Devices), err)
	}
	shift()
	inv, err := src.Fetch(context.Background())
	return len(inv.Devices), err
}

// lists is how many reads of the list s served from the request at from.
func lists(s *sottest.Server, from int) int {
	n := 0
	for _, r := range s.Requests()[from:] {
		if (r.Method == http.MethodPost && strings.Contains(r.Query, "offset: 0")) ||
			(r.Method == http.MethodGet && r.RawQuery == "limit=50") || r.RawQuery == "depth=1&limit=50" {
			n++
		}
	}
	return n
}

// Controller ruling (Task 5 review I-1): a rename across a page boundary, or
// a delete before it and an insert after it, skips a live device while
// every count holds. A device the last read had and this one lacks is asked
// for by name; still there and in scope, the list is read once more, and a
// second such read fails the sync with nothing that looks like a removal.
func TestASkippedDeviceIsConfirmedNotRemoved(t *testing.T) {
	for _, stack := range []string{"netbox-4", "nautobot-2"} {
		for _, api := range []string{"graphql", "rest"} {
			for _, knob := range []string{"rename", "replace"} {
				for _, shifts := range []int{1, 0} {
					name := fmt.Sprintf("%s %s %s shifts=%d", stack, api, knob, shifts)
					src, s, _ := source(t, stack, 120, api, Mapping{Filter: Filter{Status: []string{"active"}},
						Addresses: Addresses{Primary: true}})
					from := 0
					n, err := fetches(t, src, s, func() {
						from = len(s.Requests())
						s.Shifts = shifts
						if knob == "rename" {
							s.RenameAfterPage = 1
						} else {
							s.ReplaceAfterPage = 1
						}
					})
					if api == "rest" && knob == "rename" {
						// A rename keeps the device's id, which REST lists
						// twice: the read fails at that page, before any
						// device is asked for (pre-flight I1).
						if err == nil || n != 0 || !strings.Contains(err.Error(), "REST gave one device twice") {
							t.Errorf("%s: %d devices, %v", name, n, err)
						}
						continue
					}
					if shifts == 1 {
						// The second read is whole: the renamed or deleted
						// first device is confirmed gone, and the sync holds.
						if err != nil || n != 120 || lists(s, from) != 2 {
							t.Errorf("%s: %d devices, %d reads, %v", name, n, lists(s, from), err)
						}
					} else if err == nil || n != 0 || lists(s, from) != 2 ||
						!strings.Contains(err.Error(), "the list shifted during the read") ||
						strings.Contains(err.Error(), "leaf-") {
						t.Errorf("%s: %d devices, %d reads, %v", name, n, lists(s, from), err)
					}
					var asked bool
					for _, r := range s.Requests()[from:] {
						if strings.Contains(r.RawQuery, "name="+sottest.Name(51)) {
							asked = true
							if stack == "nautobot-2" && !strings.Contains(r.RawQuery, "depth=1") {
								t.Errorf("%s: asked without depth=1: %s", name, r.RawQuery)
							}
						}
					}
					if !asked {
						t.Errorf("%s: the skipped device was not asked for", name)
					}
				}
			}
		}
	}
}

// A device that is gone, or still there but out of scope, is a removal: one
// read, and the sync holds.
func TestARealRemovalPassesOnOneRead(t *testing.T) {
	src, s, _ := source(t, "netbox-4", 120, "rest", Mapping{Filter: Filter{Status: []string{"active"}},
		Addresses: Addresses{Primary: true}})
	from := 0
	n, err := fetches(t, src, s, func() { from = len(s.Requests()); s.SetDevices(119) })
	if err != nil || n != 119 || lists(s, from) != 1 {
		t.Fatalf("deleted: %d devices, %d reads, %v", n, lists(s, from), err)
	}
	// leaf-051 skipped by a rename, and offline: asked for, out of scope.
	src, s, _ = source(t, "nautobot-2", 120, "graphql", Mapping{Filter: Filter{Status: []string{"active"}},
		Addresses: Addresses{Primary: true}})
	n, err = fetches(t, src, s, func() {
		from = len(s.Requests())
		s.RenameAfterPage, s.Status = 1, map[int]string{51: "offline"}
	})
	// leaf-01, now z-leaf-01, is kept; leaf-051 is offline, and a removal.
	asked := strings.Contains(fmt.Sprint(s.Requests()[from:]), "name="+sottest.Name(51))
	if err != nil || n != 120 || lists(s, from) != 1 || !asked {
		t.Fatalf("offline: %d devices, %d reads, asked %v, %v", n, lists(s, from), asked, err)
	}
}

// The first read in process confirms nothing.
func TestTheFirstReadConfirmsNothing(t *testing.T) {
	src, s, _ := source(t, "netbox-4", 120, "rest", Mapping{Addresses: Addresses{Primary: true}})
	s.SetDevices(119)
	if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != 119 {
		t.Fatalf("%d %v", len(inv.Devices), err)
	}
	for _, r := range s.Requests() {
		if strings.Contains(r.RawQuery, "name=") {
			t.Fatalf("asked %s", r.RawQuery)
		}
	}
}

// named is how many devices s was asked for by name from the request at from.
func named(s *sottest.Server, from int) int {
	n := 0
	for _, r := range s.Requests()[from:] {
		if strings.Contains(r.RawQuery, "name=") {
			n++
		}
	}
	return n
}

// remove reads src once with n devices, then again with keep, after shift.
func remove(t *testing.T, stack, api string, n, keep int, shift func(*sottest.Server)) (*Source, *sottest.Server,
	int, int, error) {
	t.Helper()
	src, s, _ := source(t, stack, n, api, Mapping{Filter: Filter{Status: []string{"active"}},
		Addresses: Addresses{Primary: true}})
	if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != n {
		t.Fatalf("first read: %d %v", len(inv.Devices), err)
	}
	from := len(s.Requests())
	s.SetDevices(keep)
	if shift != nil {
		shift(s)
	}
	inv, err := src.Fetch(context.Background())
	return src, s, from, len(inv.Devices), err
}

// Task 8 review I1: up to maxConfirm absent devices are asked for by name;
// past it, the list is read once more, and nothing is asked by name.
func TestPastMaxConfirmTheListIsReadTwice(t *testing.T) {
	for _, absent := range []int{maxConfirm, maxConfirm + 1} {
		_, s, from, n, err := remove(t, "netbox-4", "rest", 300, 300-absent, nil)
		reads, asked := 1, absent
		if absent > maxConfirm {
			reads, asked = 2, 0
		}
		if err != nil || n != 300-absent || lists(s, from) != reads || named(s, from) != asked {
			t.Errorf("%d absent: %d devices, %d reads, %d asked, %v", absent, n, lists(s, from), named(s, from), err)
		}
	}
}

// A large genuine removal passes on two agreeing reads.
func TestALargeRemovalPassesOnTwoReads(t *testing.T) {
	for _, api := range []string{"graphql", "rest"} {
		_, s, from, n, err := remove(t, "nautobot-2", api, 600, 300, nil)
		if err != nil || n != 300 || lists(s, from) != 2 || named(s, from) != 0 {
			t.Errorf("%s: %d devices, %d reads, %d asked, %v", api, n, lists(s, from), named(s, from), err)
		}
	}
}

// A shift during a large removal makes the two reads disagree: the sync
// fails with nothing that looks like a removal, and the next, with the
// shift stopped, holds.
func TestALargeShiftFailsUntilItStops(t *testing.T) {
	src, s, from, n, err := remove(t, "nautobot-2", "graphql", 600, 300, func(s *sottest.Server) {
		s.RenameAfterPage, s.Shifts = 1, 1
	})
	if err == nil || n != 0 || lists(s, from) != 2 || named(s, from) != 0 ||
		!strings.Contains(err.Error(), "the list changed between two reads") || strings.Contains(err.Error(), "leaf-") {
		t.Fatalf("%d devices, %d reads, %v", n, lists(s, from), err)
	}
	if inv, err := src.Fetch(context.Background()); err != nil || len(inv.Devices) != 300 {
		t.Fatalf("after the shift: %d %v", len(inv.Devices), err)
	}
}

// Task 8 review M1: a name filter that was not applied answers devices of
// other names, which fails the sync rather than read every one as gone.
func TestAnIgnoredNameFilterFailsTheSync(t *testing.T) {
	_, _, _, n, err := remove(t, "netbox-4", "rest", 120, 119, func(s *sottest.Server) { s.IgnoreNameFilter = true })
	if err == nil || n != 0 || !strings.Contains(err.Error(), "the name filter was not applied") ||
		strings.Contains(err.Error(), "leaf-") {
		t.Fatalf("%d devices, %v", n, err)
	}
}
