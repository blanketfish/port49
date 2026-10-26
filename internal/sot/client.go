package sot

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/egress"
	"github.com/rhwendt/port49/internal/printsafe"
)

// maxResponse bounds one answer's body: a GraphQL page of page_size devices
// with their interfaces is a few MiB, and 64 MiB is inventory_file's bound.
// A variable for the tests.
var maxResponse int64 = 64 << 20

// maxFetch bounds the bytes one fetch reads summed over its pages
// (pre-flight M3): the page and device caps do not bound bytes, and a broken
// or compromised source must not exhaust the service's memory. A variable
// for the tests.
var maxFetch int64 = 256 << 20

// budget is what is left of maxFetch for one fetch's list.
type budget struct{ left int64 }

func newBudget() *budget { return &budget{left: maxFetch} }

// spend takes n bytes of a page, or refuses the fetch.
func (b *budget) spend(n int) error {
	if b.left -= int64(n); b.left < 0 {
		return fmt.Errorf("the device list is larger than %d MiB, the most one sync reads: filter the source, or "+
			"split it into two sources", maxFetch>>20)
	}
	return nil
}

const (
	// maxErrorBody bounds what is read of an answer that is neither a 200 nor
	// GraphQL's: it is drained, never printed.
	maxErrorBody = 64 << 10
	maxCAFile    = 1 << 20
	// maxPrinted bounds one string of the source's that is printed: a GraphQL
	// error message, a path a next named.
	maxPrinted = 200
	// maxPages and maxDevices bound one list, so a source that pages forever
	// ends the sync rather than the service's memory.
	maxPages   = 1000
	maxDevices = 100_000
)

// proxy is the transport's proxy (egress.Proxy); a variable for the tests.
var proxy = egress.Proxy

// dialTimeout bounds a dial and a TLS handshake; the sync's deadline bounds
// the rest. A variable for the tests.
var dialTimeout = 10 * time.Second

// client asks one source of truth over https as one identity, its token. It
// follows no redirect, so the token goes to the configured base and nowhere
// else (decision 31); the CA file is read at each handshake, so a rotated CA
// needs no restart, as the service client's is (plan 6b Task 12).
type client struct {
	base *url.URL
	auth Secret
	http *http.Client
}

// answer is one reply: its status and its body.
type answer struct {
	status int
	body   []byte
}

// CheckURL is the source url rule: https, a host, and no user information,
// query or fragment. A path is kept, for a source served under a prefix. The
// errors quote nothing of raw: user information and a query are where a
// token gets pasted.
func CheckURL(raw string) error {
	_, err := parseBase(raw)
	return err
}

func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("url must be https://host[:port][/path]")
	}
	if u.User != nil {
		return nil, errors.New("url carries user information; the source is asked with the token token_secret_ref " +
			"names, so remove it")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("url carries a query or a fragment; it is https://host[:port][/path]")
	}
	u.Path, u.RawPath = strings.TrimSuffix(u.Path, "/"), ""
	return u, nil
}

// newClient is a client of base. product picks the token's scheme: a NetBox
// v2 token (nbt_<key>.<token>) is Bearer, every other is Token (L27).
func newClient(base, caFile string, token Secret, product string) (*client, error) {
	u, err := parseBase(base)
	if err != nil {
		return nil, err
	}
	if _, err := readCA(caFile); err != nil {
		return nil, err
	}
	scheme := "Token "
	if product == "netbox" && strings.HasPrefix(token.Reveal(), "nbt_") {
		scheme = "Bearer "
	}
	host := u.Hostname()
	dialer := &net.Dialer{Timeout: dialTimeout}
	tr := &http.Transport{
		Proxy:       proxy,
		DialContext: dialer.DialContext,
		// The CA file is read at each handshake, direct or through the
		// proxy's tunnel, so a rotated CA needs no restart. A proxied HTTPS
		// request never calls DialTLSContext: the transport dials the proxy,
		// sends CONNECT, then handshakes with this config. InsecureSkipVerify
		// only hands verification to VerifyConnection, which verifies the
		// chain against that pool and the name against the source's host:
		// RootCAs is never nil, so never the host's roots unless the CA file
		// is the host's bundle.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				pool, err := readCA(caFile)
				if err != nil {
					return err
				}
				if len(cs.PeerCertificates) == 0 {
					return errors.New("the source sent no certificate")
				}
				inter := x509.NewCertPool()
				for _, c := range cs.PeerCertificates[1:] {
					inter.AddCert(c)
				}
				_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
					DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
				return err
			}},
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: 2 * time.Minute, MaxIdleConnsPerHost: 2,
		// DefaultTransport's: port49 closes an idle connection before the
		// source, or a proxy in front of it, does, and a rotated CA reaches
		// the next dial.
		IdleConnTimeout: 90 * time.Second}
	return &client{base: u, auth: NewSecret(scheme + token.Reveal()), http: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// readCA is the CA file's certificates, read bounded. A file with none is an
// error: an empty pool is never a reason to fall back.
func readCA(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("ca_file: none given; name the CA bundle that issues the source's certificate " +
			"(the host's own bundle file is a valid choice for a public one)")
	}
	// As the service client reads its CA (internal/inventory/client.go): a
	// regular file, opened without blocking and bounded, so a FIFO at ca_file
	// is refused rather than hanging a dial (pre-flight M2). A symbolic link
	// is followed, so a distribution's bundle link still works.
	raw, err := config.ReadRegular(path, maxCAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("ca_file %s holds no PEM certificate", path)
	}
	return pool, nil
}

// at is path under the base, with q as its query.
func (c *client) at(path string, q url.Values) *url.URL {
	u := *c.base
	u.Path, u.RawPath, u.RawQuery = c.base.Path+path, "", q.Encode()
	return &u
}

// what names a request in an error: its method and path. A path a next
// named is the source's text, so it is printed through printable.
func what(method string, u *url.URL) string { return method + " " + printable(u.Path) }

// do sends one request with the token and reads its answer: a 200's body, or
// with full a body whatever the status (GraphQL's errors), up to maxResponse;
// any other answer's up to maxErrorBody, never printed. It sends to the
// base's origin alone, whoever built u (decision 31).
func (c *client) do(ctx context.Context, method string, u *url.URL, body []byte, full bool) (answer, error) {
	if u.Scheme != c.base.Scheme || u.Host != c.base.Host {
		return answer{}, fmt.Errorf("%s is not on url; the token is sent to url alone", what(method, u))
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Authorization", c.auth.Reveal())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			// net/http's ResponseHeaderTimeout: the source took over 2
			// minutes to begin an answer, which a large page does (pre-flight
			// M3). A dial or handshake timeout reads otherwise.
			return answer{}, fmt.Errorf("%s: no answer began within 2m: lower page_size", what(method, u))
		}
		if strings.Contains(err.Error(), "Proxy Authentication Required") {
			// A 407 answers the CONNECT, so it is the egress proxy's: said
			// apart from the source's own 401, which names the token. Fixed
			// text, so neither the proxy's credentials nor its URL print.
			return answer{}, fmt.Errorf("%s: the egress proxy refused HTTPS_PROXY's credentials; the token was not sent",
				what(method, u))
		}
		return answer{}, clean(what(method, u), err)
	}
	defer resp.Body.Close()
	limit := int64(maxErrorBody)
	if full || resp.StatusCode == http.StatusOK {
		limit = maxResponse
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return answer{}, clean(what(method, u), err)
	}
	if int64(len(raw)) > limit {
		if limit == maxResponse {
			return answer{}, fmt.Errorf("%s answered more than %d bytes", what(method, u), limit)
		}
		raw = raw[:limit]
	}
	return answer{resp.StatusCode, raw}, nil
}

// getJSON GETs u and decodes a 200's JSON into v, numbers as json.Number.
func (c *client) getJSON(ctx context.Context, u *url.URL, v any) error {
	a, err := c.do(ctx, http.MethodGet, u, nil, false)
	if err != nil {
		return err
	}
	if a.status != http.StatusOK {
		return statusError(what(http.MethodGet, u), a.status)
	}
	dec := json.NewDecoder(bytes.NewReader(a.body))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		// Never the body: it is the source's text.
		return fmt.Errorf("%s answered something that is not the JSON asked for", what(http.MethodGet, u))
	}
	return nil
}

// statusError is an answer that is not a 200, with what to do about it.
func statusError(what string, status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%s answered HTTP %d: the token token_secret_ref names was refused, or may not read "+
			"devices; it is not printed", what, status)
	case status >= 300 && status < 400:
		return fmt.Errorf("%s answered HTTP %d, a redirect, which is not followed: set url to where it points", what,
			status)
	}
	return fmt.Errorf("%s answered HTTP %d", what, status)
}

// printable is s, the source's text, as one line of at most maxPrinted
// bytes (printsafe.Line).
func printable(s string) string { return printsafe.Line(s, maxPrinted) }

// cleanError is an error whose text is printable: a TLS error can carry the
// names in a certificate whoever answers the address chose.
type cleanError struct {
	text string
	err  error
}

func (e *cleanError) Error() string { return e.text }
func (e *cleanError) Unwrap() error { return e.err }

// clean is err after what. A *url.Error is unwrapped to its cause: its own
// text quotes the whole URL, a next's query included, and printable's cut
// would land in the cause the operator needs.
func clean(what string, err error) error {
	cause := err
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		cause = ue.Err
	}
	return &cleanError{text: what + ": " + printable(cause.Error()), err: err}
}
