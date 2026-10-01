package sot

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

// replay is a client of a sottest.Server for stack with n devices, and the
// profile the stack's status detects.
func replay(t *testing.T, stack string, n int) (*sottest.Server, *client, Profile) {
	t.Helper()
	s := sottest.New(t, stack, n)
	product := strings.SplitN(stack, "-", 2)[0]
	c, err := newClient(s.URL, s.CAFile, NewSecret(token), product)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := c.getJSON(context.Background(), c.at("/api/status/", nil), &status); err != nil {
		t.Fatal(err)
	}
	v, err := versionOf(status, product)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := Detect(v, "")
	if err != nil {
		t.Fatal(err)
	}
	return s, c, p
}

// basic is what every read asks for: name, status, the primary addresses.
func basic(p Profile) selection {
	s := selection{}
	s.add([]string{"id"})
	s.add([]string{"name"})
	s.add(p.status.graphql)
	s.add([]string{"primary_ip4", "address"})
	s.add([]string{"primary_ip6", "address"})
	return s
}

func TestASelectionIsSortedAndNested(t *testing.T) {
	s := selection{}
	s.add([]string{"status"})
	s.add([]string{"platform", "slug"})
	s.add([]string{"name"})
	s.add([]string{"platform", "network_driver"})
	if got := s.String(); got != "name platform { network_driver slug } status" {
		t.Fatalf("%q", got)
	}
}

// L30: each profile pages as its release took it, and the query is the
// recorded shape: NetBox 4.7.1 pagination: {offset, limit}, Nautobot
// limit/offset, NetBox 3.7.8 nothing.
func TestEveryStackListsOverGraphQLAsItPages(t *testing.T) {
	for stack, want := range map[string]int{"netbox-3.7": 1, "netbox-4": 3, "nautobot-1.6": 3, "nautobot-2": 3,
		"nautobot-3": 3} {
		s, c, p := replay(t, stack, 120)
		devs, err := c.graphqlDevices(context.Background(), p, basic(p), 50)
		if err != nil || len(devs) != 120 {
			t.Fatalf("%s: %d devices, %v", stack, len(devs), err)
		}
		posts := 0
		for _, r := range s.Requests() {
			if r.Method == http.MethodPost {
				posts++
			}
		}
		if posts != want {
			t.Errorf("%s: %d GraphQL requests, want %d", stack, posts, want)
		}
		// primary_ip6 is in no recorded fixture query (L32 measured the
		// connector asking for it on every release): every other identifier
		// was in a recorded query.
		if got := strings.Join(s.Unrecorded(), ","); got != "primary_ip6" {
			t.Errorf("%s: asked for unrecorded %q", stack, got)
		}
	}
}

// L30: NetBox 4.7.1 refuses with HTTP 200 and an errors list. A reader of
// the status alone takes it for an empty inventory; the errors come first.
func TestErrorsAreReadBeforeDataEvenOnA200(t *testing.T) {
	s, c, p := replay(t, "netbox-4", 3)
	s.GraphQL200Errors = true
	_, err := c.graphqlDevices(context.Background(), p, basic(p), 50)
	if err == nil || !strings.Contains(err.Error(), "GraphQL answered HTTP 200 with 2 error(s); the first: "+
		"Unknown argument 'limit' on field 'Query.device_list'.") {
		t.Fatalf("got %v", err)
	}
}

func TestAGraphQL404IsErrNoGraphQL(t *testing.T) {
	s, c, p := replay(t, "nautobot-2", 3)
	s.GraphQLStatus = http.StatusNotFound
	if _, err := c.graphqlDevices(context.Background(), p, basic(p), 50); err != errNoGraphQL {
		t.Fatalf("got %v", err)
	}
	s.GraphQLStatus = http.StatusForbidden
	if _, err := c.graphqlDevices(context.Background(), p, basic(p), 50); err == nil ||
		!strings.Contains(err.Error(), "answered HTTP 403") {
		t.Fatalf("got %v", err)
	}
}

// A 404 that carries GraphQL errors is a GraphQL server refusing, not
// GraphQL off: it is the server's error, and nothing falls back on it.
func TestA404WithErrorsIsNotErrNoGraphQL(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"data": null, "errors": [{"message": "no such field"}]}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "nautobot")
	_, err := c.graphqlDevices(context.Background(), profiles[Nautobot2], basic(profiles[Nautobot2]), 50)
	if err == nil || err == errNoGraphQL || !strings.Contains(err.Error(), "HTTP 404 with 1 error(s); the first: no such field") {
		t.Fatalf("got %v", err)
	}
}

// A status error names the request as the client sent it, under the url's
// path, as a GET's does.
func TestAGraphQLStatusErrorNamesThePathUnderThePrefix(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	c, _ := newClient(srv.URL+"/netbox", ca, NewSecret(token), "netbox")
	_, err := c.graphqlDevices(context.Background(), profiles[NetBox4], basic(profiles[NetBox4]), 50)
	if err == nil || !strings.Contains(err.Error(), "POST /netbox/graphql/ answered HTTP 500") {
		t.Fatalf("got %v", err)
	}
}

// A page size below 1 would never see a short page; it is refused before
// any request.
func TestAPageSizeBelowOneIsRefused(t *testing.T) {
	s, c, p := replay(t, "nautobot-2", 3)
	if _, err := c.graphqlDevices(context.Background(), p, basic(p), 0); err == nil ||
		!strings.Contains(err.Error(), "page_size must be at least 1") {
		t.Fatalf("got %v", err)
	}
	for _, r := range s.Requests() {
		if r.Method == http.MethodPost {
			t.Fatalf("asked GraphQL: %+v", r)
		}
	}
}

// A release that honours the limit and ignores the offset answers the first
// page every time; the second page fails the read, not the thousandth.
func TestAReleaseThatIgnoresTheOffsetFailsAtTheSecondPage(t *testing.T) {
	var posts atomic.Int32
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.Write([]byte(`{"data": {"devices": [{"name": "a"}, {"name": "b"}]}}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "nautobot")
	_, err := c.graphqlDevices(context.Background(), profiles[Nautobot2], basic(profiles[Nautobot2]), 2)
	if err == nil || !strings.Contains(err.Error(), "GraphQL page 1 began with the device page 0 began with (name a)") ||
		!strings.Contains(err.Error(), "ignored the offset") {
		t.Fatalf("got %v", err)
	}
	if n := posts.Load(); n != 2 {
		t.Fatalf("%d GraphQL requests, want 2", n)
	}
}

// A repeat later in a page fails at that page, by the I1 check.
func TestARepeatFailsAtThePageThatHoldsIt(t *testing.T) {
	var posts atomic.Int32
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if posts.Add(1) == 1 {
			w.Write([]byte(`{"data": {"devices": [{"id": "1", "name": "a"}, {"id": "2", "name": "b"}]}}`))
			return
		}
		w.Write([]byte(`{"data": {"devices": [{"id": "3", "name": "c"}, {"id": "2", "name": "b"}]}}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "nautobot")
	_, err := c.graphqlDevices(context.Background(), profiles[Nautobot2], basic(profiles[Nautobot2]), 2)
	if err == nil || !strings.Contains(err.Error(), "GraphQL gave one device twice (id 2)") {
		t.Fatalf("got %v", err)
	}
	if n := posts.Load(); n != 2 {
		t.Fatalf("%d GraphQL requests, want 2", n)
	}
}

func TestAnErrorMessageIsPrintedSafely(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data": null, "errors": [{"message": "bad\u001b[2J` + strings.Repeat("x", 400) + `"}]}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	_, err := c.graphqlDevices(context.Background(), profiles[NetBox4], basic(profiles[NetBox4]), 50)
	if err == nil || strings.Contains(err.Error(), "\x1b") || len(err.Error()) > 400 {
		t.Fatalf("got %q", err)
	}
}

// Pre-flight M4: a release that ignores the page size returns the whole
// list every page; the first long page fails the read.
func TestAPageLongerThanThePageSizeFails(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data": {"devices": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "nautobot")
	if _, err := c.graphqlDevices(context.Background(), profiles[Nautobot2], basic(profiles[Nautobot2]), 2); err == nil ||
		!strings.Contains(err.Error(), "ignored the page size") {
		t.Fatalf("got %v", err)
	}
}

// Pre-flight I1: a list giving one device twice, by id, is refused; two
// unnamed devices are two devices, and one unnamed device given twice is
// caught as any other.
func TestAListNamingADeviceTwiceFails(t *testing.T) {
	for body, want := range map[string]string{
		`[{"id": "1", "name": "a"}, {"id": "2", "name": null}, {"id": "3", "name": null}, {"id": "1", "name": "a"}]`: "(id 1)",
		`[{"id": "1", "name": "a"}, {"id": "2", "name": null}, {"id": "3", "name": "b"}, {"id": "2", "name": null}]`: "(id 2)",
	} {
		srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"data": {"device_list": ` + body + `}}`))
		}))
		c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
		if _, err := c.graphqlDevices(context.Background(), profiles[NetBox37], basic(profiles[NetBox37]), 50); err == nil ||
			!strings.Contains(err.Error(), "GraphQL gave one device twice "+want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data": {"device_list": [{"id": "1", "name": null}, {"id": "2", "name": null}]}}`))
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if devs, err := c.graphqlDevices(context.Background(), profiles[NetBox37], basic(profiles[NetBox37]), 50); err != nil ||
		len(devs) != 2 {
		t.Fatalf("two unnamed devices: %d, %v", len(devs), err)
	}
}

// L32 review: a device renamed between pages to a name that sorts last is
// listed twice under two names, and the device past the boundary is
// skipped, while the count holds. Keyed by id (L32: every release lets the
// list select id, a string), the read fails at the page that repeats it,
// with I1's cause, rather than at admission or not at all.
func TestARenameAcrossPagesFailsAtThePage(t *testing.T) {
	for _, stack := range []string{"netbox-4", "nautobot-1.6", "nautobot-2", "nautobot-3"} {
		s, c, p := replay(t, stack, 120)
		s.RenameAfterPage = 1
		devs, err := c.graphqlDevices(context.Background(), p, basic(p), 50)
		if err == nil || !strings.Contains(err.Error(), "GraphQL gave one device twice (id ") ||
			!strings.Contains(err.Error(), "the list changed between pages") || strings.Contains(err.Error(), "leaf-") {
			t.Errorf("%s: %d devices, %v", stack, len(devs), err)
		}
	}
}

func TestRestCountIsTheListsCount(t *testing.T) {
	_, c, _ := replay(t, "nautobot-3", 120)
	if n, err := c.restCount(context.Background()); err != nil || n != 120 {
		t.Fatalf("%d %v", n, err)
	}
}
