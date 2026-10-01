package inventory

import (
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
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Client reads the service's API over mutual TLS: port49d's fetcher, and the
// port49 tool. The service's certificate is verified against the CA file
// alone, for the name or address the URL gives; the CA file and the client
// certificate are read from their files at each handshake, so a rotated CA
// or a renewed workload certificate is used without a restart (pre-flight
// minor 6). It follows no redirect: it asks the service it was given.
type Client struct {
	base *url.URL
	http *http.Client
}

const (
	// maxCAFile bounds the CA file's read.
	maxCAFile = 1 << 20
	// maxErrorReply bounds the read of a reply that is not a 200: the
	// service's is one short JSON error code.
	maxErrorReply = 4 << 10
	// maxVersionReply, maxJudgementReply and bundle.MaxDocument bound a 200's
	// body, per ask: a version is a few hundred bytes, a sync's result or a
	// diff is a line per change (16 MiB is some 50,000), and only a bundle is
	// a document.
	maxVersionReply   = 64 << 10
	maxJudgementReply = 16 << 20
	// maxPrinted bounds one string of the service's, or one error, printed.
	maxPrinted = 4096
)

// dialTimeout bounds a dial and a handshake: a black-holed service costs 10s,
// not the kernel's minutes (pre-flight minor 5). A variable for the test.
var dialTimeout = 10 * time.Second

// ErrNoConnection is a dial or a TLS handshake that failed: the ask was never
// sent, so the service did nothing for it.
var ErrNoConnection = errors.New("no connection to the inventory service")

// Printable is s, the service's text, as one line: a control character, a
// format character (a bidi override), a line or paragraph separator, or an
// invalid byte is `?`, never terminal control or a forged line, and past
// maxPrinted bytes it is cut and marked.
func Printable(s string) string { return printsafe.Line(s, maxPrinted) }

// cleanError is an error whose text is Printable: a transport or TLS error
// can carry what the service presented — a certificate's names, which anyone
// answering its address chooses — and that is not printed or logged raw.
// errors.Is and errors.As still reach the cause.
type cleanError struct {
	text string
	err  error
}

func (e *cleanError) Error() string { return e.text }
func (e *cleanError) Unwrap() error { return e.err }

// clean is err with Printable text; every error the client returns is one.
func clean(err error) error {
	if err == nil || err == ErrNoBundle {
		return err
	}
	return &cleanError{text: Printable(err.Error()), err: err}
}

// NewClient is a client of the service at rawURL, https and with no user
// information, query or fragment. The CA file and the client certificate
// are read once here, so a mistake is said at start-up, and again at every
// handshake. The client sets no deadline of its own on an ask beyond
// ResponseHeaderTimeout, 6 minutes, which outlasts a sync the service bounds
// by sync_timeout: a caller's context bounds the rest.
func NewClient(rawURL, caFile, certFile, keyFile string) (*Client, error) {
	c, err := newClient(rawURL, caFile, certFile, keyFile)
	return c, clean(err)
}

func newClient(rawURL, caFile, certFile, keyFile string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("inventory.service.url must be https://host[:port]")
	}
	if u.User != nil {
		// Not printed: whatever is there is a credential.
		return nil, errors.New("inventory.service.url carries user information; the service authenticates by " +
			"certificate, so remove it")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		// Not printed either: a query is where a token would be pasted.
		return nil, errors.New("inventory.service.url carries a query or a fragment; it is https://host[:port]")
	}
	if _, err := readCA(caFile); err != nil {
		return nil, err
	}
	if _, err := keyfile.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("tls_cert_file %s, tls_key_file %s: %w", certFile, keyFile, err)
	}
	host := u.Hostname()
	dialer := &net.Dialer{}
	tr := &http.Transport{
		// Each connection's TLS config is built at its dial from the files
		// as they are then, and verified by crypto/tls in full: the chain to
		// a root in the CA file — RootCAs is never nil, so never the host's
		// roots — for server auth, and the URL's host name or address.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			pool, err := readCA(caFile)
			if err != nil {
				return nil, err
			}
			cert, err := keyfile.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("tls_cert_file %s, tls_key_file %s: %w", certFile, keyFile, err)
			}
			ctx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrNoConnection, err)
			}
			conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host,
				Certificates: []tls.Certificate{cert}})
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, fmt.Errorf("%w: %w", ErrNoConnection, err)
			}
			return conn, nil
		},
		ResponseHeaderTimeout: 6 * time.Minute, MaxIdleConnsPerHost: 2}
	return &Client{base: u, http: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// readCA is the CA file's certificates, read as a regular file, bounded. A
// file with none is an error: an empty pool is never a reason to fall back.
func readCA(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, errors.New("ca_file: none given; the client trusts the one CA that issues the service's certificate")
	}
	raw, err := config.ReadRegular(caFile, maxCAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("ca_file %s holds no certificate", caFile)
	}
	return pool, nil
}

// do asks path, with query as the URL's query, set on its own: JoinPath
// would escape a `?` written into the path (conflict scan F13).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, hdr map[string]string) (*http.Response, error) {
	u := *c.base
	u.Path, u.RawPath = strings.TrimSuffix(u.Path, "/")+path, ""
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.http.Do(req)
}

// answer decodes a 200's JSON, at most max bytes, into v, or says what
// the service refused with: its error code when that is one printable word,
// never its body. A no_bundle answer is ErrNoBundle, as the service's own
// Diff says it.
func answer(resp *http.Response, v any, max int64) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorReply))
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "no_bundle" {
			return ErrNoBundle
		}
		if !bundle.NameOK(e.Error) || len(e.Error) > 64 {
			e.Error = "an unreadable error"
		}
		return fmt.Errorf("the inventory service answered %d (%s)", resp.StatusCode, e.Error)
	}
	body, err := readBounded(resp.Body, max)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		// Positions only: the body is the service's text.
		return errors.New("the inventory service's answer is not the JSON asked for")
	}
	return nil
}

// readBounded reads a 200's body, refusing one larger than max.
func readBounded(r io.Reader, max int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("the inventory service sent more than %d bytes", max)
	}
	return raw, nil
}

func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	var v VersionInfo
	resp, err := c.do(ctx, "GET", "/v1/bundle/version", nil, nil)
	if err != nil {
		return v, clean(err)
	}
	return v, clean(answer(resp, &v, maxVersionReply))
}

// Bundle is the sealed document, unless etag is the service's, which is
// notModified. The document is not yet trusted: the caller opens it
// (bundle.Open) against its verify keys before using anything in it.
func (c *Client) Bundle(ctx context.Context, etag string) ([]byte, string, bool, error) {
	raw, newETag, notModified, err := c.bundle(ctx, etag)
	return raw, newETag, notModified, clean(err)
}

func (c *Client) bundle(ctx context.Context, etag string) ([]byte, string, bool, error) {
	hdr := map[string]string{}
	if etag != "" {
		hdr["If-None-Match"] = etag
	}
	resp, err := c.do(ctx, "GET", "/v1/bundle", nil, hdr)
	if err != nil {
		return nil, "", false, err
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return nil, etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, answer(resp, nil, 0)
	}
	defer resp.Body.Close()
	raw, err := readBounded(resp.Body, bundle.MaxDocument)
	if err != nil {
		return nil, "", false, err
	}
	return raw, resp.Header.Get("ETag"), false, nil
}

// BundleAt is bundle seq from the service's history, sealed and not yet
// trusted: the caller opens it (bundle.Open) against its verify keys.
func (c *Client) BundleAt(ctx context.Context, seq int64) ([]byte, error) {
	resp, err := c.do(ctx, "GET", "/v1/bundle", url.Values{"sequence": {strconv.FormatInt(seq, 10)}}, nil)
	if err != nil {
		return nil, clean(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, clean(answer(resp, nil, 0))
	}
	defer resp.Body.Close()
	raw, err := readBounded(resp.Body, bundle.MaxDocument)
	if err != nil {
		return nil, clean(err)
	}
	return raw, nil
}

func (c *Client) Sync(ctx context.Context) (Result, error) {
	var r Result
	resp, err := c.do(ctx, "POST", "/v1/sync", nil, nil)
	if err != nil {
		return r, clean(err)
	}
	return r, clean(answer(resp, &r, maxJudgementReply))
}

func (c *Client) Diff(ctx context.Context, from int64) (DiffResult, error) {
	var d DiffResult
	resp, err := c.do(ctx, "GET", "/v1/bundle/diff", url.Values{"from": {strconv.FormatInt(from, 10)}}, nil)
	if err != nil {
		return d, clean(err)
	}
	return d, clean(answer(resp, &d, maxJudgementReply))
}
