package sot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// errNoGraphQL is a GraphQL endpoint that answered 404: GraphQL is turned
// off, or the release has none. Source.Fetch falls back to REST on it when
// the source's api is auto.
var errNoGraphQL = errors.New("GraphQL answered HTTP 404")

// selection is a GraphQL selection set, built from field paths.
type selection map[string]selection

func (s selection) add(path []string) {
	for _, k := range path {
		next, ok := s[k]
		if !ok {
			next = selection{}
			s[k] = next
		}
		s = next
	}
}

// String is the set with its keys sorted, so a query is the same text for
// the same fields: "a b { c d }".
func (s selection) String() string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k
		if len(s[k]) > 0 {
			parts[i] = k + " { " + s[k].String() + " }"
		}
	}
	return strings.Join(parts, " ")
}

// listQuery is the device list query on p, in the argument spelling and
// order L30 recorded: NetBox 4.7.1 `pagination: {offset, limit}`, Nautobot
// `limit`, `offset`, NetBox 3.7.8 none.
func (p Profile) listQuery(sel selection, offset, limit int) string {
	args := ""
	switch p.paging {
	case pageNested:
		args = fmt.Sprintf("(pagination: {offset: %d, limit: %d})", offset, limit)
	case pageArgs:
		args = fmt.Sprintf("(limit: %d, offset: %d)", limit, offset)
	}
	return fmt.Sprintf("{ %s%s { %s } }", p.list, args, sel)
}

// graphqlDevices is every device over GraphQL, page by page where p pages,
// to a short page. A page longer than pageSize (a release that ignored the
// paging arguments, pre-flight M4), a list past maxFetch bytes (M3), and a
// list naming a device twice (a page boundary shifted under a concurrent
// insert, I1) fail it. The caller checks the count (Source.graphql).
func (c *client) graphqlDevices(ctx context.Context, p Profile, sel selection, pageSize int) ([]map[string]any, error) {
	u := c.at(p.graphqlPath, nil)
	b := newBudget()
	var out []map[string]any
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("GraphQL gave more than %d pages", maxPages)
		}
		body, err := json.Marshal(map[string]string{"query": p.listQuery(sel, len(out), pageSize)})
		if err != nil {
			return nil, err
		}
		a, err := c.do(ctx, http.MethodPost, u, body, true)
		if err != nil {
			return nil, err
		}
		if err := b.spend(len(a.body)); err != nil {
			return nil, err
		}
		devs, err := p.graphqlPage(a)
		if err != nil {
			return nil, err
		}
		if p.paging != pageNone && len(devs) > pageSize {
			return nil, fmt.Errorf("GraphQL page %d gave %d devices for a page of %d: the release ignored the page "+
				"size, so its paging cannot be trusted", page, len(devs), pageSize)
		}
		out = append(out, devs...)
		if len(out) > maxDevices {
			return nil, fmt.Errorf("GraphQL gave more than %d devices", maxDevices)
		}
		if p.paging == pageNone || len(devs) < pageSize {
			return out, distinct(out, "name", "GraphQL")
		}
	}
}

// distinct refuses a list that holds one device twice, by key ("id" over
// REST, "name" over GraphQL, which is not asked for an id: L27 and L30
// recorded none in a query). Offset paging across a concurrent change
// repeats or skips the device at a page boundary (pre-flight I1); a repeat
// fails here, naming the cause, rather than at admission's "two devices are
// both named". An empty key is skipped: NetBox allows a device no name.
func distinct(devs []map[string]any, key, api string) error {
	seen := map[string]bool{}
	for _, d := range devs {
		k := ""
		switch v := d[key].(type) {
		case string:
			k = v
		case json.Number:
			k = v.String()
		}
		if k == "" {
			continue
		}
		if seen[k] {
			return fmt.Errorf("%s gave one device twice (%s %s): the list changed between pages; the next sync "+
				"reads it again", api, key, printable(k))
		}
		seen[k] = true
	}
	return nil
}

// graphqlPage reads one answer: its errors before its data, whatever the
// HTTP status, since NetBox 4.7.1 refuses an argument with HTTP 200 and an
// errors list (L30). An error message is the source's text: printed safely,
// and only the first.
func (p Profile) graphqlPage(a answer) ([]map[string]any, error) {
	var r struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	dec := json.NewDecoder(bytes.NewReader(a.body))
	dec.UseNumber()
	derr := dec.Decode(&r)
	if derr == nil && len(r.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL answered HTTP %d with %d error(s); the first: %s", a.status, len(r.Errors),
			printable(r.Errors[0].Message))
	}
	switch {
	case a.status == http.StatusNotFound:
		return nil, errNoGraphQL
	case a.status != http.StatusOK:
		return nil, statusError("POST "+p.graphqlPath, a.status)
	case derr != nil:
		return nil, errors.New("GraphQL answered something that is not JSON")
	}
	raw, ok := r.Data[p.list]
	if !ok {
		return nil, fmt.Errorf("GraphQL's data has no %s", p.list)
	}
	var devs []map[string]any
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&devs); err != nil {
		return nil, fmt.Errorf("GraphQL's %s is not a list of devices", p.list)
	}
	return devs, nil
}

// restCount is the device count REST gives: GET /api/dcim/devices/?limit=1,
// its count (L27, L30: count/next/previous/results on every release).
func (c *client) restCount(ctx context.Context) (int, error) {
	var page struct {
		Count *int `json:"count"`
	}
	if err := c.getJSON(ctx, c.at("/api/dcim/devices/", url.Values{"limit": {"1"}}), &page); err != nil {
		return 0, err
	}
	if page.Count == nil || *page.Count < 0 {
		return 0, errors.New("GET /api/dcim/devices/ gives no count")
	}
	return *page.Count, nil
}
