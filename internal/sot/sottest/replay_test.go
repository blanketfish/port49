package sottest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func client(t *testing.T, s *Server) *http.Client {
	t.Helper()
	raw, err := os.ReadFile(s.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(raw)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func get(t *testing.T, c *http.Client, url string, v any) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if v != nil {
		json.NewDecoder(resp.Body).Decode(v)
	}
	return resp.StatusCode
}

func post(t *testing.T, c *http.Client, url, query string, v any) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"query": query})
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, v)
	return resp.StatusCode
}

// The replay serves each stack as L30 recorded it: its release, a REST list
// of n paged to a null next, and its GraphQL list as the stack pages it.
func TestTheReplayIsTheRecordedStack(t *testing.T) {
	for stack, release := range map[string]string{"netbox-3.7": "3.7.8", "netbox-4": "4.7.1",
		"nautobot-1.6": "1.6.32", "nautobot-2": "2.4.43", "nautobot-3": "3.2.6"} {
		s := New(t, stack, 120)
		c := client(t, s)
		product := strings.SplitN(stack, "-", 2)[0]
		var status map[string]any
		if get(t, c, s.URL+"/api/status/", &status) != 200 || status[product+"-version"] != release {
			t.Fatalf("%s: status %v", stack, status[product+"-version"])
		}
		next, n := s.URL+"/api/dcim/devices/?limit=50", 0
		for next != "" {
			var page struct {
				Count   int              `json:"count"`
				Next    *string          `json:"next"`
				Results []map[string]any `json:"results"`
			}
			get(t, c, next, &page)
			n += len(page.Results)
			next = ""
			if page.Next != nil {
				next = *page.Next
			}
		}
		if n != 120 {
			t.Fatalf("%s: REST gave %d", stack, n)
		}
		list, gql := "devices", s.URL+"/api/graphql/"
		if product == "netbox" {
			list, gql = "device_list", s.URL+"/graphql/"
		}
		var r struct {
			Data   map[string][]map[string]any `json:"data"`
			Errors []any                       `json:"errors"`
		}
		if code := post(t, c, gql, "{ "+list+" { name } }", &r); code != 200 || len(r.Data[list]) != 120 {
			t.Fatalf("%s: unpaged GraphQL %d, %d devices", stack, code, len(r.Data[list]))
		}
		if r.Data[list][50]["name"] != Name(51) || Name(51) != "leaf-051" || Name(1) != "leaf-01" {
			t.Fatalf("%s: names", stack)
		}
	}
}

// L30: NetBox 4.7.1 answers limit/offset with HTTP 200 and an errors list,
// and NetBox 3.7.8 every paging shape with 400.
func TestTheReplayRefusesAsTheStackRefused(t *testing.T) {
	var r struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	s4 := New(t, "netbox-4", 3)
	if code := post(t, client(t, s4), s4.URL+"/graphql/", "{ device_list(limit: 50, offset: 0) { name } }", &r); code != 200 ||
		len(r.Errors) != 2 || !strings.Contains(r.Errors[0].Message, "Unknown argument 'limit'") {
		t.Fatalf("netbox-4: %d %+v", code, r)
	}
	s37 := New(t, "netbox-3.7", 3)
	if code := post(t, client(t, s37), s37.URL+"/graphql/", "{ device_list(pagination: {offset: 0, limit: 50}) { name } }",
		&r); code != 400 {
		t.Fatalf("netbox-3.7: %d", code)
	}
}

// What a query asked for that no recorded query did is kept, so a test can
// say the connector asked only for recorded fields.
func TestAnUnrecordedFieldIsNoted(t *testing.T) {
	s := New(t, "nautobot-2", 1)
	var r map[string]any
	post(t, client(t, s), s.URL+"/api/graphql/", "{ devices(limit: 50, offset: 0) { name primary_ip6 { address } role { name } } }", &r)
	if got := strings.Join(s.Unrecorded(), ","); got != "primary_ip6" {
		t.Fatalf("unrecorded: %q", got)
	}
}

// The refusal's code is unrecorded (401 or 403), so only refusal is held.
func TestAuthIsRequiredWhenSet(t *testing.T) {
	s := New(t, "netbox-4", 1)
	s.Auth = "Token right"
	if code := get(t, client(t, s), s.URL+"/api/status/", nil); code != 401 && code != 403 {
		t.Fatalf("%d", code)
	}
}

type restPage struct {
	Next, Previous *string
	Results        []map[string]any
}

// GraphQL answers the fields a query selected and no others, so a connector
// query that leaves one out gets a device without it.
func TestGraphQLAnswersOnlyWhatWasSelected(t *testing.T) {
	s := New(t, "nautobot-2", 3)
	var r struct {
		Data map[string][]map[string]any `json:"data"`
	}
	post(t, client(t, s), s.URL+"/api/graphql/", "{ devices { name } }", &r)
	for _, d := range r.Data["devices"] {
		if len(d) != 1 || d["name"] == nil {
			t.Fatalf("name alone selected, got %v", d)
		}
	}
	s4 := New(t, "netbox-4", 3)
	post(t, client(t, s4), s4.URL+"/graphql/", "{ device_list { name primary_ip4 { address } interfaces { name } } }", &r)
	d := r.Data["device_list"][1]
	ip, _ := d["primary_ip4"].(map[string]any)
	itf, _ := d["interfaces"].([]any)
	if len(d) != 3 || len(ip) != 1 || ip["address"] != Addr(2, 5) || len(itf) != 2 || len(itf[0].(map[string]any)) != 1 {
		t.Fatalf("netbox-4: %v", d)
	}
}

// L30 recorded a NetBox id as a number and a Nautobot id as a UUID string;
// each copy has its own id, display and url.
func TestEachDeviceIsItsOwnInTheStacksForm(t *testing.T) {
	for _, stack := range []string{"netbox-3.7", "netbox-4", "nautobot-1.6", "nautobot-2", "nautobot-3"} {
		s := New(t, stack, 2)
		s.Status = map[int]string{2: "planned"}
		var page restPage
		get(t, client(t, s), s.URL+"/api/dcim/devices/?limit=50&depth=1", &page)
		a, b := page.Results[0], page.Results[1]
		_, isString := b["id"].(string)
		if isString != strings.HasPrefix(stack, "nautobot") || a["id"] == b["id"] {
			t.Fatalf("%s: ids %v %v", stack, a["id"], b["id"])
		}
		if b["display"] != Name(2) || b["url"] == a["url"] || !strings.HasPrefix(b["url"].(string), s.URL) {
			t.Fatalf("%s: display %v url %v", stack, b["display"], b["url"])
		}
		ip := b["primary_ip4"].(map[string]any)
		if ip["address"] != Addr(2, 5) || ip["display"] != Addr(2, 5) || ip["url"] == a["primary_ip4"].(map[string]any)["url"] {
			t.Fatalf("%s: primary_ip4 %v", stack, ip)
		}
		st := b["status"].(map[string]any)
		if st["label"] != "Planned" && (st["name"] != "Planned" || st["display"] != "Planned") {
			t.Fatalf("%s: status %v", stack, st)
		}
	}
}

// previous is absolute and leaves offset out at 0, as rest-pages.json has it.
func TestPreviousIsAsRecorded(t *testing.T) {
	s := New(t, "netbox-4", 120)
	c := client(t, s)
	var first, second, third restPage
	get(t, c, s.URL+"/api/dcim/devices/?limit=50", &first)
	get(t, c, *first.Next, &second)
	get(t, c, *second.Next, &third)
	if first.Previous != nil || second.Previous == nil || *second.Previous != s.URL+"/api/dcim/devices/?limit=50" ||
		third.Previous == nil || *third.Previous != s.URL+"/api/dcim/devices/?limit=50&offset=50" {
		t.Fatalf("previous: %v %v %v", first.Previous, second.Previous, third.Previous)
	}
}

// A knob set between requests is not a race (run under -race). The page is
// larger than the server's write buffer, so the client has it before the
// handler returns.
func TestDeleteAfterPageSetBetweenRequests(t *testing.T) {
	s := New(t, "netbox-4", 120)
	c := client(t, s)
	var page restPage
	get(t, c, s.URL+"/api/dcim/devices/?limit=50", &page)
	s.DeleteAfterPage = 2
	get(t, c, s.URL+"/api/dcim/devices/?limit=50", &page)
	get(t, c, s.URL+"/api/dcim/devices/?limit=50", &page)
	if page.Results[0]["name"] != Name(2) {
		t.Fatalf("after the delete the list opens with %v", page.Results[0]["name"])
	}
}

// A string literal's words are no identifiers, recorded or asked.
func TestALiteralIsNoIdentifier(t *testing.T) {
	s := New(t, "nautobot-2", 1)
	var r map[string]any
	post(t, client(t, s), s.URL+"/api/graphql/", `{ devices(name: "zebra") { name } }`, &r)
	if got := s.Unrecorded(); len(got) != 0 {
		t.Fatalf("unrecorded: %v", got)
	}
	if s.recorded["leaf"] {
		t.Fatal("leaf, from \"leaf-01\", noted as recorded")
	}
}

// An argument no recorded list query used is refused, not answered as the
// whole list; the paging arguments are taken in either order.
func TestAnUnrecordedArgumentIsRefused(t *testing.T) {
	var r struct {
		Data   map[string][]map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	s := New(t, "nautobot-2", 5)
	c := client(t, s)
	if code := post(t, c, s.URL+"/api/graphql/", "{ devices(offset:1,limit:2) { name } }", &r); code != 200 ||
		len(r.Data["devices"]) != 2 || r.Data["devices"][0]["name"] != Name(2) {
		t.Fatalf("offset first: %d %v", code, r.Data)
	}
	for _, q := range []string{`{ devices(limit: 2) { name } }`, `{ devices(name: "leaf-01") { name } }`} {
		if code := post(t, c, s.URL+"/api/graphql/", q, &r); code != 400 {
			t.Fatalf("%s: %d", q, code)
		}
	}
	s4 := New(t, "netbox-4", 5)
	if code := post(t, client(t, s4), s4.URL+"/graphql/", `{ device_list(filters: {name: {exact: "x"}}) { name } }`, &r); code != 400 {
		t.Fatalf("filters: %d", code)
	}
	// Recorded: 4.7.1 answers name: with 200 and errors.
	r.Errors = nil
	if code := post(t, client(t, s4), s4.URL+"/graphql/", `{ device_list(name: "leaf-01") { name } }`, &r); code != 200 ||
		len(r.Errors) != 1 || r.Errors[0].Message != "Unknown argument 'name' on field 'Query.device_list'." {
		t.Fatalf("name: %d %v", code, r.Errors)
	}
}
