package sottest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Request is one request a Server took.
type Request struct {
	Method, Path, RawQuery, Host, Authorization string
	// Query is a GraphQL request's query.
	Query string
}

// Server replays one stack L30 recorded (tests/lab/sot/l30/<stack>/): its
// /api/status/, and n devices shaped as its recorded leaf-01 over GraphQL and
// over REST, paged as the stack paged, each with addresses of its own
// (Addr). Set the knobs before the first request.
type Server struct {
	Stack, URL, CAFile string

	// NextHost is the host every REST next names; "" is the request's own.
	NextHost string
	// NextPath is a path every next names in place of the device list's.
	NextPath string
	// GraphQLStatus, nonzero, is the only answer GraphQL gives.
	GraphQLStatus int
	// GraphQL200Errors makes GraphQL answer HTTP 200 and an errors list, as
	// NetBox 4.7.1 answers an unknown argument (L30).
	GraphQL200Errors bool
	// DropFromGraphQL is how many devices, from the end, GraphQL leaves out.
	DropFromGraphQL int
	// Auth, set, is the one Authorization taken; any other is 401.
	Auth string
	// Status is device i's status, lower case; absent or empty is "active".
	Status map[int]string
	// DeleteAfterPage, nonzero, deletes the list's first device once that
	// many list pages (GraphQL, or REST with a limit other than 1) have been
	// served, so every later page shifts left by one, as offset paging does
	// under a concurrent delete (pre-flight I1).
	DeleteAfterPage int

	product, list, gqlPath string
	status                 map[string]any
	gqlDev                 map[string]any
	restDev, restShallow   map[string]any
	recorded               map[string]bool

	mu         sync.Mutex
	n          int
	deleted    int // devices deleted from the list's head: position j is device j+deleted
	pages      int
	log        []Request
	unrecorded map[string]bool
}

// fixtures is tests/lab/sot/l30, found from this file.
func fixtures() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "lab", "sot", "l30")
}

// ident is a GraphQL identifier.
var ident = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// New replays stack with n devices.
func New(t testing.TB, stack string, n int) *Server {
	t.Helper()
	dir := filepath.Join(fixtures(), stack)
	s := &Server{Stack: stack, product: strings.SplitN(stack, "-", 2)[0], n: n, recorded: map[string]bool{},
		unrecorded: map[string]bool{}, list: "device_list", gqlPath: "/graphql/"}
	if s.product == "nautobot" {
		s.list, s.gqlPath = "devices", "/api/graphql/"
	}
	var status struct {
		Body map[string]any `json:"body"`
	}
	read(t, filepath.Join(dir, "status.json"), &status)
	s.status = status.Body
	// leaf-01 as the stack's GraphQL answered it: the recorded query that
	// returned it, and every identifier that query and the recorded lists
	// asked for.
	var steps []struct {
		Request struct {
			Query string `json:"query"`
		} `json:"request"`
		Status int `json:"status"`
		Body   struct {
			Data map[string][]map[string]any `json:"data"`
		} `json:"body"`
	}
	read(t, filepath.Join(dir, "graphql.json"), &steps)
	for _, st := range steps {
		if st.Status == http.StatusOK && len(st.Body.Data[s.list]) == 1 {
			s.gqlDev = st.Body.Data[s.list][0]
			s.note(st.Request.Query)
		}
	}
	if s.gqlDev == nil {
		t.Fatalf("sottest: %s: no recorded GraphQL query returned leaf-01", stack)
	}
	var lists []struct {
		Query  string `json:"query"`
		Status int    `json:"status"`
		Errors any    `json:"errors"`
	}
	read(t, filepath.Join(dir, "graphql-list.json"), &lists)
	for _, l := range lists {
		if l.Status == http.StatusOK && l.Errors == nil {
			s.note(l.Query)
		}
	}
	s.restShallow = firstResult(t, filepath.Join(dir, "rest-device.json"))
	s.restDev = s.restShallow
	if p := filepath.Join(dir, "rest-device-depth1.json"); exists(p) {
		s.restDev = firstResult(t, p)
	}
	srv, ca := TLS(t, http.HandlerFunc(s.serve))
	s.URL, s.CAFile = srv.URL, ca
	return s
}

func (s *Server) note(query string) {
	for _, tok := range ident.FindAllString(query, -1) {
		s.recorded[tok] = true
	}
}

func read(t testing.TB, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("sottest: %s: %v", path, err)
	}
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// firstResult is results[0] of a recorded REST read, a call or a list of them.
func firstResult(t testing.TB, path string) map[string]any {
	t.Helper()
	type call struct {
		Body struct {
			Results []map[string]any `json:"results"`
		} `json:"body"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var one call
	if json.Unmarshal(raw, &one) == nil && len(one.Body.Results) > 0 {
		return one.Body.Results[0]
	}
	var many []call
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 && len(many[0].Body.Results) > 0 {
		return many[0].Body.Results[0]
	}
	t.Fatalf("sottest: %s holds no recorded device", path)
	return nil
}

// Name is device i's name, as L30 seeded them: leaf-01, then leaf-002...
func Name(i int) string {
	if i == 1 {
		return "leaf-01"
	}
	return fmt.Sprintf("leaf-%03d", i)
}

// Addr is device i's address on Management1 (which 5, the primary) or
// Loopback0 (which 6), with its prefix length, as the products write one.
func Addr(i, which int) string { return fmt.Sprintf("10.%d.%d.%d/32", which, i/250, i%250+1) }

func (s *Server) SetDevices(n int) { s.mu.Lock(); s.n = n; s.mu.Unlock() }

func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.log...)
}

// Unrecorded is every identifier a GraphQL query asked for that no recorded
// query of the stack asked for, sorted.
func (s *Server) Unrecorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.unrecorded))
	for k := range s.unrecorded {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	req := Request{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Host: r.Host,
		Authorization: r.Header.Get("Authorization")}
	var gql struct {
		Query string `json:"query"`
	}
	if r.Method == http.MethodPost {
		json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&gql)
		req.Query = gql.Query
	}
	s.mu.Lock()
	s.log = append(s.log, req)
	n, del := s.n, s.deleted
	s.mu.Unlock()
	if s.Auth != "" && req.Authorization != s.Auth {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Invalid token"})
		return
	}
	list := false
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/status/":
		writeJSON(w, http.StatusOK, s.status)
	case r.Method == http.MethodGet && r.URL.Path == "/api/dcim/devices/":
		s.rest(w, r, n, del)
		list = r.URL.Query().Get("limit") != "1"
	case r.Method == http.MethodPost && r.URL.Path == s.gqlPath:
		s.graphql(w, gql.Query, n, del)
		list = true
	default:
		http.NotFound(w, r)
	}
	if list {
		s.mu.Lock()
		if s.pages++; s.DeleteAfterPage > 0 && s.pages == s.DeleteAfterPage {
			s.n, s.deleted = s.n-1, s.deleted+1
		}
		s.mu.Unlock()
	}
}

func (s *Server) rest(w http.ResponseWriter, r *http.Request, n, del int) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	// Nautobot 2.x and 3.x name no related object at default depth (L27,
	// L30): without depth=1 a device is the shallow one.
	base, shallow := s.restDev, q.Get("depth") != "1" && s.product == "nautobot" && s.Stack != "nautobot-1.6"
	if shallow {
		base = s.restShallow
	}
	results := []any{}
	for j := offset + 1; j <= n && j <= offset+limit; j++ {
		results = append(results, s.device(base, j+del, "rest", shallow))
	}
	var next any
	if offset+limit < n {
		host := s.NextHost
		if host == "" {
			host = r.Host
		}
		path := "/api/dcim/devices/"
		if s.NextPath != "" {
			path = s.NextPath
		}
		nq := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset + limit)}}
		if d := q.Get("depth"); d != "" {
			nq.Set("depth", d)
		}
		next = (&url.URL{Scheme: "https", Host: host, Path: path, RawQuery: nq.Encode()}).String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n, "next": next, "previous": nil, "results": results})
}

var (
	nested = regexp.MustCompile(`\(pagination: \{offset: (\d+), limit: (\d+)\}\)`)
	args   = regexp.MustCompile(`\(limit: (\d+), offset: (\d+)\)`)
)

func errorsOf(msgs ...string) map[string]any {
	var errs []any
	for _, m := range msgs {
		errs = append(errs, map[string]any{"message": m})
	}
	return map[string]any{"data": nil, "errors": errs}
}

func (s *Server) graphql(w http.ResponseWriter, query string, n, del int) {
	s.mu.Lock()
	for _, tok := range ident.FindAllString(query, -1) {
		if !s.recorded[tok] {
			s.unrecorded[tok] = true
		}
	}
	s.mu.Unlock()
	// The refusals L30 recorded, word for word.
	limitOffset := []string{"Unknown argument 'limit' on field 'Query.device_list'.",
		"Unknown argument 'offset' on field 'Query.device_list'."}
	switch {
	case s.GraphQLStatus != 0:
		w.WriteHeader(s.GraphQLStatus)
		io.WriteString(w, "<html>not here</html>")
		return
	case s.GraphQL200Errors:
		writeJSON(w, http.StatusOK, errorsOf(limitOffset...))
		return
	case !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(query), "{")), s.list):
		// Not recorded: a query of anything but the device list.
		writeJSON(w, http.StatusBadRequest, errorsOf("Cannot query field on type 'Query'."))
		return
	}
	offset, limit := 0, n
	if m := nested.FindStringSubmatch(query); m != nil {
		switch s.Stack {
		case "netbox-4":
		case "netbox-3.7":
			writeJSON(w, http.StatusBadRequest,
				errorsOf("Unknown argument 'pagination' on field 'Query.device_list'. Did you mean 'position'?"))
			return
		default:
			// Not recorded: no run asked Nautobot for pagination; it answers
			// as an unknown argument would.
			writeJSON(w, http.StatusBadRequest, errorsOf("Unknown argument 'pagination' on field 'Query.devices'."))
			return
		}
		offset, _ = strconv.Atoi(m[1])
		limit, _ = strconv.Atoi(m[2])
	} else if m := args.FindStringSubmatch(query); m != nil {
		switch s.Stack {
		case "netbox-4":
			writeJSON(w, http.StatusOK, errorsOf(limitOffset...))
			return
		case "netbox-3.7":
			writeJSON(w, http.StatusBadRequest, errorsOf(limitOffset...))
			return
		}
		limit, _ = strconv.Atoi(m[1])
		offset, _ = strconv.Atoi(m[2])
	}
	devs := []any{}
	for j := offset + 1; j <= n-s.DropFromGraphQL && j <= offset+limit; j++ {
		devs = append(devs, s.device(s.gqlDev, j+del, "graphql", false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{s.list: devs}})
}

// device is device i: base with its name, its addresses and its status in
// the stack's spelling for api (L30), and no primary_ip6, as none was set.
func (s *Server) device(base map[string]any, i int, api string, shallow bool) map[string]any {
	d := clone(base)
	// Its own id and name: the connector refuses a list naming a device twice
	// (pre-flight I1), and every clone of leaf-01 would otherwise share its id.
	d["name"], d["id"] = Name(i), i
	if shallow {
		return d // every related object is {id, object_type, url}
	}
	mgmt, lo := Addr(i, 5), Addr(i, 6)
	if p, ok := d["primary_ip4"].(map[string]any); ok {
		p["address"] = mgmt
		if _, ok := p["host"]; ok {
			p["host"] = strings.TrimSuffix(mgmt, "/32")
		}
	}
	if ifs, ok := d["interfaces"].([]any); ok {
		for _, itf := range ifs {
			im, _ := itf.(map[string]any)
			addr := lo
			if im["name"] == "Management1" {
				addr = mgmt
			}
			ips, _ := im["ip_addresses"].([]any)
			for _, ip := range ips {
				if m, ok := ip.(map[string]any); ok {
					m["address"] = addr
				}
			}
		}
	}
	st := "active"
	if v := s.Status[i]; v != "" {
		st = v
	}
	title := strings.ToUpper(st[:1]) + st[1:]
	switch {
	case api == "graphql" && s.Stack == "netbox-3.7":
		d["status"] = strings.ToUpper(st)
	case api == "graphql" && s.product == "netbox":
		d["status"] = st
	case api == "graphql":
		d["status"] = map[string]any{"name": title}
	case s.product == "netbox" || s.Stack == "nautobot-1.6":
		d["status"] = map[string]any{"value": st, "label": title}
	default:
		if m, ok := d["status"].(map[string]any); ok {
			m["name"] = title
		}
	}
	if api == "graphql" {
		d["primary_ip6"] = nil
	}
	return d
}

func clone(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
