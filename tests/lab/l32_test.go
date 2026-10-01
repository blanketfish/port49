//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/sot"
)

// l32Record is one stack's L32 run: what `next` named through each of the
// three proxies, and what the connector, as built, read through each, over
// GraphQL and REST.
type l32Record struct {
	Stack     string     `json:"stack"`
	At        time.Time  `json:"at"`
	Built     string     `json:"built"`
	Probes    []l32Probe `json:"probes"`
	Reads     []l32Read  `json:"reads"`
	GraphQLID l32IDProbe `json:"graphql_id"`
}

// l32Probe is the first page of the device list read through a proxy: the
// scheme and host its next names, and the host its first result's url names.
type l32Probe struct {
	Proxy      string `json:"proxy"`
	Status     int    `json:"status"`
	NextScheme string `json:"next_scheme"`
	NextHost   string `json:"next_host"`
	ResultHost string `json:"result_host"`
}

// l32Read is one Fetch by the connector as built, of URL (the proxy's).
type l32Read struct {
	Proxy   string         `json:"proxy"`
	URL     string         `json:"url"`
	API     string         `json:"api"`
	Seconds float64        `json:"seconds"`
	Devices int            `json:"devices"`
	Said    []string       `json:"said"`
	Leaf01  map[string]any `json:"leaf_01,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// l32IDProbe is whether the release's GraphQL device list lets a query
// select id beside name, which the connector keys the list by. Kind is the
// JSON type the first device's id came back as.
type l32IDProbe struct {
	Query      string `json:"query"`
	Status     int    `json:"status"`
	Errors     int    `json:"errors"`
	FirstError string `json:"first_error,omitempty"`
	Selectable bool   `json:"selectable"`
	Kind       string `json:"kind,omitempty"`
}

// l32Map is what an L32 read maps on stack: the paths both APIs give on its
// profile (Nautobot 1.6 gives network_driver over GraphQL only), and the
// recorded custom field.
func l32Map(stack string) map[string]string {
	if stack == "nautobot-2" || stack == "nautobot-3" {
		return map[string]string{"platform": "platform.network_driver", "site": "location.name", "role": "role.name",
			"os_version": "custom_fields.os_version"}
	}
	return map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug",
		"os_version": "custom_fields.os_version"}
}

// l32IDVerdict is what an id probe measured: "id selectable", "id refused"
// (HTTP 200 with errors), or "id unmeasured" (any other answer).
func l32IDVerdict(p l32IDProbe) string {
	switch {
	case p.Selectable:
		return "id selectable"
	case p.Status == http.StatusOK && p.Errors > 0:
		return "id refused"
	}
	return "id unmeasured"
}

// l32Said is whether a read said it rebuilt a next on url.
func l32Said(r l32Read) bool {
	for _, line := range r.Said {
		if strings.Contains(line, "rebuilt on url") {
			return true
		}
	}
	return false
}

// l32Built names what the reads ran: internal/sot as go test compiled it,
// at the checkout's commit, -dirty when the checkout has changes.
func l32Built(top string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rev, _ := exec.CommandContext(ctx, "git", "-C", top, "rev-parse", "--short", "HEAD").Output()
	sha := strings.TrimSpace(string(rev))
	if st, _ := exec.CommandContext(ctx, "git", "-C", top, "status", "--porcelain").Output(); len(st) > 0 {
		sha += "-dirty"
	}
	return "internal/sot as compiled by go test at `" + sha + "`"
}

// l32Client trusts the run's lab CA alone.
func l32Client(t *testing.T) *http.Client {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("L32_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(raw)
	return &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// l32Auth is the Authorization the connector sends (L27): never recorded.
func l32Auth() string {
	tok := os.Getenv("L27_TOKEN")
	if os.Getenv("L32_PRODUCT") == "netbox" && strings.HasPrefix(tok, "nbt_") {
		return "Bearer " + tok
	}
	return "Token " + tok
}

func l32ProbeNext(t *testing.T, proxy, base string) l32Probe {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/dcim/devices/?limit=50", nil)
	req.Header.Set("Authorization", l32Auth())
	resp, err := l32Client(t).Do(req)
	if err != nil {
		t.Fatalf("probe through %s: %v", proxy, err)
	}
	defer resp.Body.Close()
	var page struct {
		Next    string `json:"next"`
		Results []struct {
			URL string `json:"url"`
		} `json:"results"`
	}
	json.NewDecoder(resp.Body).Decode(&page)
	p := l32Probe{Proxy: proxy, Status: resp.StatusCode}
	if u, err := url.Parse(page.Next); err == nil {
		p.NextScheme, p.NextHost = u.Scheme, u.Host
	}
	if len(page.Results) > 0 {
		if u, err := url.Parse(page.Results[0].URL); err == nil {
			p.ResultHost = u.Host
		}
	}
	return p
}

// l32ProbeID asks the stack's GraphQL device list for id and name, one
// device where the release pages (L30's shapes), and records what came back.
func l32ProbeID(t *testing.T, stack, base string) l32IDProbe {
	t.Helper()
	path, q := "/api/graphql/", `{ devices(limit: 1, offset: 0) { id name } }`
	switch stack {
	case "netbox-3.7":
		path, q = "/graphql/", `{ device_list { id name } }`
	case "netbox-4":
		path, q = "/graphql/", `{ device_list(pagination: {offset: 0, limit: 1}) { id name } }`
	}
	body, _ := json.Marshal(map[string]string{"query": q})
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	req.Header.Set("Authorization", l32Auth())
	req.Header.Set("Content-Type", "application/json")
	resp, err := l32Client(t).Do(req)
	if err != nil {
		t.Fatalf("the id probe: %v", err)
	}
	defer resp.Body.Close()
	var r struct {
		Data   map[string][]map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	p := l32IDProbe{Query: q, Status: resp.StatusCode, Errors: len(r.Errors)}
	if len(r.Errors) > 0 {
		p.FirstError = r.Errors[0].Message
	}
	for _, devs := range r.Data {
		if len(devs) == 0 {
			continue
		}
		switch v := devs[0]["id"].(type) {
		case string:
			p.Selectable, p.Kind = v != "", "string"
		case float64:
			p.Selectable, p.Kind = true, "number"
		}
	}
	return p
}

// TestL32Connector reads one running stack (run.sh <stack> l32) through
// the three proxies, over GraphQL (every interface address asked for) and
// over REST, 50 to a page, with the connector as built, and writes
// tests/lab/sot/l32/<stack>/connector.json. A read that fails, reads other
// than the 120 devices the run seeded, or says a rebuilt next where the
// proxy's probe named url's own origin (or does not where it named another)
// fails the test: the claim the code rests on is then wrong (CLAUDE.md lab
// rule 4).
func TestL32Connector(t *testing.T) {
	stack := os.Getenv("L32_STACK")
	if stack == "" {
		t.Skip("run by tests/lab/sot/run.sh <stack> l32")
	}
	// The harness sets root only when it brings a platform up; this test
	// brings none.
	top, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	rec := l32Record{Stack: stack, At: time.Now().UTC(), Built: l32Built(top)}
	for _, px := range []struct{ name, url string }{{"host", os.Getenv("L32_HOST_URL")}, {"xfh", os.Getenv("L32_XFH_URL")},
		{"plain", os.Getenv("L32_PLAIN_URL")}} {
		probe := l32ProbeNext(t, px.name, px.url)
		rec.Probes = append(rec.Probes, probe)
		if probe.Status != http.StatusOK || probe.NextHost == "" {
			t.Errorf("%s: the %s probe answered %d with next host %q: it measured nothing", stack, px.name,
				probe.Status, probe.NextHost)
		}
		base, err := url.Parse(px.url)
		if err != nil {
			t.Fatal(err)
		}
		foreign := probe.NextScheme+"://"+probe.NextHost != base.Scheme+"://"+base.Host
		for _, api := range []string{"graphql", "rest"} {
			var said bytes.Buffer
			src, err := sot.New(sot.Config{Name: "l32", Product: os.Getenv("L32_PRODUCT"), URL: px.url,
				CAFile: os.Getenv("L32_CA"), Token: sot.NewSecret(os.Getenv("L27_TOKEN")), API: api, PageSize: 50,
				Mapping: sot.Mapping{Map: l32Map(stack), Filter: sot.Filter{Status: []string{"active"}},
					Addresses: sot.Addresses{Primary: true, AllInterfaces: api == "graphql"}}, Log: &said})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			t0 := time.Now()
			inv, err := src.Fetch(ctx)
			cancel()
			r := l32Read{Proxy: px.name, URL: px.url, API: api, Seconds: time.Since(t0).Seconds(),
				Said: strings.Split(strings.TrimSpace(said.String()), "\n")}
			// Only REST follows next: it says a rebuild exactly when the
			// probe's next named another origin than url.
			if want := api == "rest" && foreign; l32Said(r) != want {
				t.Errorf("%s through %s over %s: rebuilt next said %v, want %v (next %s://%s)", stack, px.name, api,
					l32Said(r), want, probe.NextScheme, probe.NextHost)
			}
			if err != nil {
				r.Error = err.Error()
				t.Errorf("%s through %s over %s: %v", stack, px.name, api, err)
			} else {
				r.Devices = len(inv.Devices)
				for _, d := range inv.Devices {
					if d.Name == "leaf-01" {
						var as []string
						for _, a := range d.Addresses {
							as = append(as, a.String())
						}
						r.Leaf01 = map[string]any{"platform": d.Platform, "attributes": d.Attributes, "addresses": as}
					}
				}
				wantAddrs := "10.0.1.5"
				if api == "graphql" {
					wantAddrs = "10.0.1.5 10.0.1.6"
				}
				if r.Devices != 120 || r.Leaf01 == nil || r.Leaf01["platform"] != "arista_eos" ||
					strings.Join(r.Leaf01["addresses"].([]string), " ") != wantAddrs {
					t.Errorf("%s through %s over %s: %d devices, leaf-01 %v", stack, px.name, api, r.Devices, r.Leaf01)
				}
			}
			rec.Reads = append(rec.Reads, r)
		}
	}
	rec.GraphQLID = l32ProbeID(t, stack, os.Getenv("L32_HOST_URL"))
	if rec.GraphQLID.Status != http.StatusOK {
		t.Errorf("%s: the id probe answered HTTP %d: %s", stack, rec.GraphQLID.Status, l32IDVerdict(rec.GraphQLID))
	}
	dir := filepath.Join(top, "tests", "lab", "sot", "l32", stack)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "connector.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
