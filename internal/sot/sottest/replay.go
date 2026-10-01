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
// (Addr). Set a knob only between requests, never while one is in flight.
type Server struct {
	Stack, URL, CAFile string

	// NextHost is the host every REST next names; "" is the request's own.
	NextHost string
	// NextPath is a path every next names in place of the device list's.
	NextPath string
	// GraphQLStatus, nonzero, is the only answer GraphQL gives. Not
	// recorded: a fault knob, its HTML body made up.
	GraphQLStatus int
	// GraphQL200Errors makes GraphQL answer HTTP 200 and an errors list, as
	// NetBox 4.7.1 answers an unknown argument (L30).
	GraphQL200Errors bool
	// DropFromGraphQL is how many devices, from the end, GraphQL leaves out.
	DropFromGraphQL int
	// Auth, set, is the one Authorization taken; any other is 401. Not
	// recorded: no L27 or L30 run sent a bad token, and the products may
	// answer 403, so a test should not depend on which.
	Auth string
	// Status is device i's status, lower case; absent or empty is "active".
	Status map[int]string
	// DeleteAfterPage, nonzero, deletes the list's first device once that
	// many list pages (GraphQL, or REST with a limit other than 1) have been
	// served, so every later page shifts left by one: a model of offset
	// paging under a concurrent delete (pre-flight I1). Not recorded: L30
	// lists a list changing between pages under Not observed.
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

var (
	// ident is a GraphQL identifier.
	ident = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	// literal is a GraphQL string, whose words are no identifiers.
	literal = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
)

// identifiers is every identifier in query outside its string literals.
// The recorded set is per identifier, not per path: address counts as
// recorded under any parent once any recorded query asked for it.
func identifiers(query string) []string {
	return ident.FindAllString(literal.ReplaceAllString(query, `""`), -1)
}

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
	for _, tok := range identifiers(query) {
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
	n, del, deleteAfter := s.n, s.deleted, s.DeleteAfterPage
	s.mu.Unlock()
	if s.Auth != "" && req.Authorization != s.Auth {
		// Not recorded: no run sent a bad token (see Auth).
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
		if s.pages++; deleteAfter > 0 && s.pages == deleteAfter {
			s.n, s.deleted = s.n-1, s.deleted+1
		}
		s.mu.Unlock()
	}
}

func (s *Server) rest(w http.ResponseWriter, r *http.Request, n, del int) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50 // not recorded: every recorded list sent a limit
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
	host := s.NextHost
	if host == "" {
		host = r.Host
	}
	path := "/api/dcim/devices/"
	if s.NextPath != "" {
		path = s.NextPath
	}
	// link is the page at off, absolute, as L30 recorded next and previous:
	// offset left out at 0 (rest-pages.json).
	link := func(off int) string {
		nq := url.Values{"limit": {strconv.Itoa(limit)}}
		if off > 0 {
			nq.Set("offset", strconv.Itoa(off))
		}
		if d := q.Get("depth"); d != "" {
			nq.Set("depth", d)
		}
		return (&url.URL{Scheme: "https", Host: host, Path: path, RawQuery: nq.Encode()}).String()
	}
	var next, previous any
	if offset+limit < n {
		next = link(offset + limit)
	}
	if offset > 0 {
		previous = link(max(offset-limit, 0))
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n, "next": next, "previous": previous, "results": results})
}

var (
	// argGroup is a field's arguments; no recorded argument holds a paren.
	argGroup = regexp.MustCompile(`\([^)]*\)`)
	// arg is one argument, its value a scalar or one brace group.
	arg = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\{[^}]*\}|[^,\s{}]+)`)
	// selToken is a selection set's token.
	selToken = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*|[{}]`)
)

// selection is a query's selection set: each field, and nil for a leaf.
type selection map[string]selection

// selectionOf is query's top-level selection set, its literals and
// arguments set aside; nil if query does not open with one.
func selectionOf(query string) selection {
	toks := selToken.FindAllString(argGroup.ReplaceAllString(literal.ReplaceAllString(query, `""`), ""), -1)
	if len(toks) == 0 || toks[0] != "{" {
		return nil
	}
	sel, _ := parseSelection(toks, 0)
	return sel
}

// parseSelection parses the set opened at toks[i], and returns it and the
// index past its close.
func parseSelection(toks []string, i int) (selection, int) {
	sel := selection{}
	for i++; i < len(toks) && toks[i] != "}"; {
		name := toks[i]
		i++
		var sub selection
		if i < len(toks) && toks[i] == "{" {
			sub, i = parseSelection(toks, i)
		}
		sel[name] = sub
	}
	return sel, i + 1
}

// project is v with only the fields sel selects, as a GraphQL server answers:
// a field the query left out is absent, however the recorded leaf-01 had it.
func project(v any, sel selection) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, sub := range sel {
			if val, ok := x[k]; ok {
				if sub != nil {
					val = project(val, sub)
				}
				out[k] = val
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = project(e, sel)
		}
		return out
	}
	return v
}

// argsOf is the arguments query gives the list field, by name.
func argsOf(query, list string) map[string]string {
	m := regexp.MustCompile(`^\s*\{\s*` + list + `\s*(\([^)]*\))?`).FindStringSubmatch(literal.ReplaceAllString(query, `""`))
	if m == nil {
		return map[string]string{}
	}
	return argsIn(m[1])
}

// argsIn is the arguments in text, an argument group or a brace group.
func argsIn(text string) map[string]string {
	out := map[string]string{}
	if text = strings.TrimSpace(text); len(text) >= 2 {
		text = text[1 : len(text)-1] // the group's own parens or braces
	}
	for _, a := range arg.FindAllStringSubmatch(text, -1) {
		out[a[1]] = a[2]
	}
	return out
}

// offsetLimit is the offset and limit in args, both required.
func offsetLimit(args map[string]string) (int, int, bool) {
	offset, err1 := strconv.Atoi(args["offset"])
	limit, err2 := strconv.Atoi(args["limit"])
	return offset, limit, err1 == nil && err2 == nil && len(args) == 2
}

func errorsOf(msgs ...string) map[string]any {
	var errs []any
	for _, m := range msgs {
		errs = append(errs, map[string]any{"message": m})
	}
	return map[string]any{"data": nil, "errors": errs}
}

func (s *Server) graphql(w http.ResponseWriter, query string, n, del int) {
	s.mu.Lock()
	for _, tok := range identifiers(query) {
		if !s.recorded[tok] {
			s.unrecorded[tok] = true
		}
	}
	s.mu.Unlock()
	// The refusals L30 recorded, word for word.
	limitOffset := []string{"Unknown argument 'limit' on field 'Query.device_list'.",
		"Unknown argument 'offset' on field 'Query.device_list'."}
	sel := selectionOf(query)
	fields, isList := sel[s.list]
	switch {
	case s.GraphQLStatus != 0:
		w.WriteHeader(s.GraphQLStatus)
		io.WriteString(w, "<html>not here</html>")
		return
	case s.GraphQL200Errors:
		writeJSON(w, http.StatusOK, errorsOf(limitOffset...))
		return
	case !isList || len(sel) != 1 || fields == nil:
		// Not recorded: a query of anything but the device list.
		writeJSON(w, http.StatusBadRequest, errorsOf("Cannot query field on type 'Query'."))
		return
	}
	// Unpaged, the list is every device. Not recorded past 120: L30 lists a
	// GraphQL list larger than any server-side cap under Not observed.
	offset, limit := 0, n
	args := argsOf(query, s.list)
	_, nestedArg := args["pagination"]
	switch {
	case len(args) == 0:
	case nestedArg && len(args) == 1:
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
		var ok bool
		if offset, limit, ok = offsetLimit(argsIn(args["pagination"])); !ok {
			writeJSON(w, http.StatusBadRequest, errorsOf("Not recorded: a pagination shape no L30 list query used."))
			return
		}
	case len(args) == 2 && args["limit"] != "" && args["offset"] != "":
		switch s.Stack {
		case "netbox-4":
			writeJSON(w, http.StatusOK, errorsOf(limitOffset...))
			return
		case "netbox-3.7":
			writeJSON(w, http.StatusBadRequest, errorsOf(limitOffset...))
			return
		}
		var ok bool
		if offset, limit, ok = offsetLimit(args); !ok {
			writeJSON(w, http.StatusBadRequest, errorsOf("Not recorded: a limit or offset no L30 list query used."))
			return
		}
	default:
		// NetBox 4.7.1 answered an argument it does not know (name:) with
		// 200 and errors (L30, graphql.json).
		var unknown []string
		for a := range args {
			if a != "pagination" && a != "filters" {
				unknown = append(unknown, "Unknown argument '"+a+"' on field 'Query.device_list'.")
			}
		}
		if s.Stack == "netbox-4" && len(unknown) > 0 {
			sort.Strings(unknown)
			writeJSON(w, http.StatusOK, errorsOf(unknown...))
			return
		}
		// Recorded (netbox-4 filters:, Nautobot name: answered 200), not
		// replayed: the replay does not filter, so it refuses rather than
		// answer the whole list. A lone limit and any other argument alike.
		writeJSON(w, http.StatusBadRequest, errorsOf("Not replayed: an argument shape the replay does not filter by."))
		return
	}
	devs := []any{}
	for j := offset + 1; j <= n-s.DropFromGraphQL && j <= offset+limit; j++ {
		devs = append(devs, project(s.device(s.gqlDev, j+del, "graphql", false), fields))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{s.list: devs}})
}

// device is device i: base with its name, its addresses and its status in
// the stack's spelling for api (L30), and no primary_ip6, as none was set.
func (s *Server) device(base map[string]any, i int, api string, shallow bool) map[string]any {
	d := clone(base)
	// Its own id, name, display and url: the connector refuses a list naming
	// a device twice (pre-flight I1), and every clone of leaf-01 would
	// otherwise share its id. The id is in the stack's recorded form, a
	// number on NetBox and a UUID string on Nautobot (L30 rest-device*.json).
	id, ipID := s.id(i, 8), s.id(i, 9)
	d["name"], d["id"] = Name(i), id
	if _, ok := d["display"]; ok {
		d["display"] = Name(i)
	}
	if _, ok := d["url"]; ok {
		d["url"] = fmt.Sprintf("%s/api/dcim/devices/%v/", s.URL, id)
	}
	p, _ := d["primary_ip4"].(map[string]any)
	if p != nil {
		if _, ok := p["id"]; ok {
			p["id"] = ipID
		}
		if _, ok := p["url"]; ok {
			p["url"] = fmt.Sprintf("%s/api/ipam/ip-addresses/%v/", s.URL, ipID)
		}
	}
	if shallow {
		return d // every related object is {id, object_type, url}
	}
	mgmt, lo := Addr(i, 5), Addr(i, 6)
	if p != nil {
		p["address"] = mgmt
		if _, ok := p["host"]; ok {
			p["host"] = strings.TrimSuffix(mgmt, "/32")
		}
		if _, ok := p["display"]; ok {
			p["display"] = mgmt
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
			m["name"], m["display"] = title, title
		}
	}
	if api == "graphql" {
		d["primary_ip6"] = nil
	}
	return d
}

// id is object i's id in the stack's form; variant keeps one kind of
// object's UUIDs apart from another's (8 devices, 9 addresses).
func (s *Server) id(i, variant int) any {
	if s.product == "nautobot" {
		return fmt.Sprintf("00000000-0000-4000-%d000-%012d", variant, i)
	}
	return i
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
