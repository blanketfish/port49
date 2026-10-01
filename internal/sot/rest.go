package sot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// restDevices is every device over REST, following next to null (L30:
// absolute on every release, and every device once). rebuilt says whether
// some next named another origin and was rebuilt on the base, which the
// caller says once. Every page must give the first page's count, the total
// must equal it, and no device may appear twice by id (pre-flight I1): a
// delete between pages shifts the rest left and drops a live device at the
// boundary, and its count moves. As over GraphQL, a page longer than
// pageSize (a release that ignored the limit, M4), a page that begins as the
// one before it did (a release that ignored the offset), and a repeat fail
// it at the page that shows it. The pages' bytes are bounded together by
// maxFetch (M3).
func (c *client) restDevices(ctx context.Context, p Profile, pageSize int) ([]map[string]any, bool, error) {
	if pageSize < 1 {
		return nil, false, errors.New("page_size must be at least 1")
	}
	q := url.Values{"limit": {strconv.Itoa(pageSize)}}
	if p.depthOne {
		// Nautobot 2.4.43 and 3.2.6 named no related object at default
		// depth (L27, L30).
		q.Set("depth", "1")
	}
	u := c.at("/api/dcim/devices/", q)
	read := map[string]bool{}
	seen := keys{}
	b := newBudget()
	var devs []map[string]any
	rebuilt, count, first := false, -1, ""
	for page := 0; u != nil; page++ {
		if page >= maxPages {
			return nil, rebuilt, fmt.Errorf("REST gave more than %d pages", maxPages)
		}
		read[u.String()] = true
		a, err := c.do(ctx, http.MethodGet, u, nil, false)
		if err != nil {
			return nil, rebuilt, err
		}
		if a.status != http.StatusOK {
			return nil, rebuilt, statusError(what(http.MethodGet, u), a.status)
		}
		if err := b.spend(len(a.body)); err != nil {
			return nil, rebuilt, err
		}
		var body struct {
			Count   *int             `json:"count"`
			Next    *string          `json:"next"`
			Results []map[string]any `json:"results"`
		}
		dec := json.NewDecoder(bytes.NewReader(a.body))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			return nil, rebuilt, fmt.Errorf("REST page %d is not the JSON asked for", page)
		}
		if body.Count == nil || *body.Count < 0 {
			return nil, rebuilt, fmt.Errorf("REST page %d gives no count", page)
		}
		if count >= 0 && *body.Count != count {
			return nil, rebuilt, fmt.Errorf("REST page %d counts %d devices and page 0 counted %d: the list changed "+
				"during the sync; the next sync reads it again", page, *body.Count, count)
		}
		count = *body.Count
		if len(body.Results) > pageSize {
			return nil, rebuilt, fmt.Errorf("REST page %d gave %d devices for a page of %d: the release ignored the "+
				"limit, so its paging cannot be trusted", page, len(body.Results), pageSize)
		}
		// The repeat and loop checks first: a device repeated by id is I1's
		// shifted boundary, and a next naming a page read is a loop, each
		// named as such. The first-device check then catches a release that
		// ignored the offset on a list that gives no id.
		if err := seen.add(body.Results, "id", "REST"); err != nil {
			return nil, rebuilt, err
		}
		u = nil
		if body.Next != nil && *body.Next != "" {
			next, r, err := c.follow(*body.Next)
			if err != nil {
				return nil, rebuilt, fmt.Errorf("REST page %d: %w", page, err)
			}
			if read[next.String()] {
				return nil, rebuilt, fmt.Errorf("REST page %d's next names a page already read", page)
			}
			u, rebuilt = next, rebuilt || r
		}
		if len(body.Results) > 0 {
			k, key := keyOf(body.Results[0], "id"), "id"
			if k == "" {
				k, key = keyOf(body.Results[0], "name"), "name"
			}
			if k != "" && key+" "+k == first {
				return nil, rebuilt, fmt.Errorf("REST page %d began with the device page %d began with (%s %s): the "+
					"release ignored the offset, so its paging cannot be trusted", page, page-1, key, printable(k))
			}
			first = key + " " + k
		}
		devs = append(devs, body.Results...)
		if len(devs) > maxDevices {
			return nil, rebuilt, fmt.Errorf("REST gave more than %d devices", maxDevices)
		}
	}
	if len(devs) != count {
		return nil, rebuilt, fmt.Errorf("REST gave %d devices and counts %d: the list changed during the sync, or "+
			"a page was lost; the next sync reads it again", len(devs), count)
	}
	return devs, rebuilt, nil
}

// follow is the URL a page's next names, on the base, its path and query
// kept; rebuilt says its scheme, host or port was not the base's (decision
// 31). It is always built on the base, so a next naming the base's host in
// another case or with its default port is sent as url spells it. Every product builds next from the host the
// request arrived under (L30), so behind a proxy that rewrites Host it names
// another origin, and following it would send the token there. Its path
// must be the base's device list, so a next cannot steer a read anywhere
// else on the source either.
func (c *client) follow(next string) (*url.URL, bool, error) {
	n, err := url.Parse(next)
	if err != nil || !n.IsAbs() || n.Host == "" || n.Opaque != "" || n.User != nil || n.Fragment != "" {
		return nil, false, errors.New("its next is not an absolute URL; not followed")
	}
	if n.Path != c.base.Path+"/api/dcim/devices/" {
		return nil, false, fmt.Errorf("its next names another path than the device list under url (%s); not "+
			"followed", printable(n.Path))
	}
	r := *c.base
	r.Path, r.RawPath, r.RawQuery = n.Path, "", n.RawQuery
	same := n.Scheme == c.base.Scheme && strings.EqualFold(n.Hostname(), c.base.Hostname()) && portOf(n) == portOf(c.base)
	return &r, !same, nil
}

// portOf is u's port, its scheme's when it names none.
func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
