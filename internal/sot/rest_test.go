package sot

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

// L30: next is absolute and followed to null returns every device once, on
// every release; Nautobot 2.x and 3.x are read at ?depth=1.
func TestEveryStackListsOverRESTToANullNext(t *testing.T) {
	for _, stack := range []string{"netbox-3.7", "netbox-4", "nautobot-1.6", "nautobot-2", "nautobot-3"} {
		s, c, p := replay(t, stack, 120)
		devs, rebuilt, err := c.restDevices(context.Background(), p, 50)
		if err != nil || len(devs) != 120 || rebuilt {
			t.Fatalf("%s: %d devices, rebuilt %v, %v", stack, len(devs), rebuilt, err)
		}
		if devs[119]["name"] != sottest.Name(120) {
			t.Fatalf("%s: last %v", stack, devs[119]["name"])
		}
		for _, r := range s.Requests() {
			if r.Path == "/api/dcim/devices/" && p.depthOne != strings.Contains(r.RawQuery, "depth=1") {
				t.Fatalf("%s: %s?%s", stack, r.Path, r.RawQuery)
			}
		}
	}
}

// L30: behind a proxy, next names the proxy's host and X-Forwarded-Proto's
// scheme. A next on another origin is rebuilt on the base, so every request
// still goes to the base, and the token with it.
func TestANextOnAnotherOriginIsRebuiltOnTheBase(t *testing.T) {
	s, c, p := replay(t, "netbox-4", 120)
	s.NextHost = "netbox.attacker.example:443"
	devs, rebuilt, err := c.restDevices(context.Background(), p, 50)
	if err != nil || len(devs) != 120 || !rebuilt {
		t.Fatalf("%d devices, rebuilt %v, %v", len(devs), rebuilt, err)
	}
	base, _ := url.Parse(s.URL)
	for _, r := range s.Requests() {
		if r.Host != base.Host {
			t.Fatalf("a request went to %s", r.Host)
		}
	}
}

func TestANextOnAnotherPathIsNotFollowed(t *testing.T) {
	s, c, p := replay(t, "nautobot-2", 120)
	s.NextPath = "/api/users/tokens/"
	if _, _, err := c.restDevices(context.Background(), p, 50); err == nil ||
		!strings.Contains(err.Error(), "names another path than the device list under url") {
		t.Fatalf("got %v", err)
	}
	for _, r := range s.Requests() {
		if r.Path == "/api/users/tokens/" {
			t.Fatal("followed it")
		}
	}
}

// Decision 31: a total that differs from count fails the read; nothing is
// returned that would look like devices removed.
func TestARESTListShortOfItsCountFails(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count": 120, "next": null, "previous": null, "results": [{"name": "leaf-01"}]}`)
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if _, _, err := c.restDevices(context.Background(), profiles[NetBox4], 50); err == nil ||
		!strings.Contains(err.Error(), "REST gave 1 devices and counts 120") {
		t.Fatalf("got %v", err)
	}
}

// Pre-flight I1: an insert between pages shifts the list right and repeats
// a device; it is refused by id.
func TestARESTListRepeatingADeviceFails(t *testing.T) {
	var self string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") == "" {
			fmt.Fprintf(w, `{"count": 2, "next": %q, "previous": null, "results": [{"id": 7, "name": "a"}]}`, self)
			return
		}
		fmt.Fprint(w, `{"count": 2, "next": null, "previous": null, "results": [{"id": 7, "name": "a"}]}`)
	}))
	self = srv.URL + "/api/dcim/devices/?limit=1&offset=1"
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if devs, _, err := c.restDevices(context.Background(), profiles[NetBox4], 1); err == nil || devs != nil ||
		!strings.Contains(err.Error(), "REST gave one device twice (id 7)") {
		t.Fatalf("%v %v", devs, err)
	}
}

func TestANextThatLoopsIsRefused(t *testing.T) {
	var self string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"count": 120, "next": %q, "previous": null, "results": [{"name": "leaf-01"}]}`, self)
	}))
	self = srv.URL + "/api/dcim/devices/?limit=50&offset=50"
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if _, _, err := c.restDevices(context.Background(), profiles[NetBox4], 50); err == nil ||
		!strings.Contains(err.Error(), "names a page already read") {
		t.Fatalf("got %v", err)
	}
}

func TestFollow(t *testing.T) {
	c := &client{base: &url.URL{Scheme: "https", Host: "nb.example.com", Path: "/netbox"}}
	for next, want := range map[string]string{
		"https://nb.example.com/netbox/api/dcim/devices/?limit=50&offset=50": "followed",
		"https://NB.example.com:443/netbox/api/dcim/devices/?offset=50":      "followed",
		"http://nb.example.com/netbox/api/dcim/devices/?offset=50":           "rebuilt",
		"https://proxy.internal:8443/netbox/api/dcim/devices/?offset=50":     "rebuilt",
		"https://nb.example.com/api/dcim/devices/?offset=50":                 "another path",
		"https://user:pw@nb.example.com/netbox/api/dcim/devices/?offset=50":  "not an absolute URL",
		"/netbox/api/dcim/devices/?offset=50":                                "not an absolute URL",
	} {
		u, rebuilt, err := c.follow(next)
		switch {
		case want == "followed" && (err != nil || rebuilt):
			t.Errorf("%s: %v %v", next, rebuilt, err)
		case want == "rebuilt" && (err != nil || !rebuilt || u.Scheme != "https" || u.Host != "nb.example.com" ||
			u.RawQuery != "offset=50"):
			t.Errorf("%s: %v %v %v", next, u, rebuilt, err)
		case want != "followed" && want != "rebuilt" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: %v", next, err)
		}
	}
}

func TestARESTPageSizeBelowOneIsRefused(t *testing.T) {
	s, c, p := replay(t, "netbox-4", 3)
	if _, _, err := c.restDevices(context.Background(), p, 0); err == nil ||
		!strings.Contains(err.Error(), "page_size must be at least 1") {
		t.Fatalf("got %v", err)
	}
	for _, r := range s.Requests() {
		if r.Path == "/api/dcim/devices/" {
			t.Fatalf("asked REST: %+v", r)
		}
	}
}

// A release that ignores the offset answers the first page at every next;
// with no id to repeat, the second page fails the read by its first name,
// not the count at the end.
func TestARESTReleaseThatIgnoresTheOffsetFailsAtTheSecondPage(t *testing.T) {
	var gets atomic.Int32
	var base string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := gets.Add(1)
		fmt.Fprintf(w, `{"count": 6, "next": %q, "previous": null, "results": [{"name": "a"}, {"name": "b"}]}`,
			fmt.Sprintf("%s/api/dcim/devices/?limit=2&offset=%d", base, 2*n))
	}))
	base = srv.URL
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	_, _, err := c.restDevices(context.Background(), profiles[NetBox4], 2)
	if err == nil || !strings.Contains(err.Error(), "REST page 1 began with the device page 0 began with (name a)") ||
		!strings.Contains(err.Error(), "ignored the offset") {
		t.Fatalf("got %v", err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("%d REST requests, want 2", n)
	}
}

// A repeat by id fails at the page that holds it, not after the last.
func TestARESTRepeatFailsAtThePageThatHoldsIt(t *testing.T) {
	var gets atomic.Int32
	var base string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := gets.Add(1)
		results := `[{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]`
		if n > 1 {
			results = fmt.Sprintf(`[{"id": %d, "name": "c%d"}, {"id": 2, "name": "b"}]`, 10+n, n)
		}
		fmt.Fprintf(w, `{"count": 8, "next": %q, "previous": null, "results": %s}`,
			fmt.Sprintf("%s/api/dcim/devices/?limit=2&offset=%d", base, 2*n), results)
	}))
	base = srv.URL
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	_, _, err := c.restDevices(context.Background(), profiles[NetBox4], 2)
	if err == nil || !strings.Contains(err.Error(), "REST gave one device twice (id 2)") {
		t.Fatalf("got %v", err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("%d REST requests, want 2", n)
	}
}

// A page longer than the limit asked is a release that ignored it.
func TestARESTPageLongerThanItsLimitFails(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count": 3, "next": null, "previous": null, "results": [{"id": 1}, {"id": 2}, {"id": 3}]}`)
	}))
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if _, _, err := c.restDevices(context.Background(), profiles[NetBox4], 2); err == nil ||
		!strings.Contains(err.Error(), "REST page 0 gave 3 devices for a page of 2") {
		t.Fatalf("got %v", err)
	}
}

// Pre-flight I1: every page must count what page 0 counted.
func TestARESTCountThatMovesBetweenPagesFails(t *testing.T) {
	var gets atomic.Int32
	var base string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gets.Add(1) == 1 {
			fmt.Fprintf(w, `{"count": 4, "next": %q, "previous": null, "results": [{"id": 1}, {"id": 2}]}`,
				base+"/api/dcim/devices/?limit=2&offset=2")
			return
		}
		fmt.Fprint(w, `{"count": 3, "next": null, "previous": null, "results": [{"id": 4}]}`)
	}))
	base = srv.URL
	c, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if _, _, err := c.restDevices(context.Background(), profiles[NetBox4], 2); err == nil ||
		!strings.Contains(err.Error(), "REST page 1 counts 3 devices and page 0 counted 4") {
		t.Fatalf("got %v", err)
	}
}
