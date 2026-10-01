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

func TestAuthIsRequiredWhenSet(t *testing.T) {
	s := New(t, "netbox-4", 1)
	s.Auth = "Token right"
	if code := get(t, client(t, s), s.URL+"/api/status/", nil); code != 401 {
		t.Fatalf("%d", code)
	}
}
