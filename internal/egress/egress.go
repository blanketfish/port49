// Package egress is how port49 reaches the outside for a fetch it makes: the
// environment's proxy (HTTPS_PROXY, NO_PROXY), described for a start line,
// never with its credentials (decision 53 ruling 7).
package egress

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

// ErrBadProxy names no part of the value: a proxy URL carries a password.
var ErrBadProxy = errors.New("HTTPS_PROXY does not parse as a proxy URL; percent-encode '#', '/', '?' and '%' in its password")

// parseProxy reads an HTTPS_PROXY value the way the transport will, and
// refuses what the transport would misread: a '#', '/' or '?' in a password
// moves the credentials into the fragment, path or query, or into a host such
// as "http:", and a proxy then fails with a host nobody configured. The error
// never carries the value.
func parseProxy(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// A bare host:port is read as http://host:port.
		if u, err = url.Parse("http://" + raw); err != nil {
			return nil, ErrBadProxy
		}
	}
	switch {
	case u.Opaque != "", u.RawQuery != "", u.ForceQuery, u.Fragment != "", u.Path != "" && u.Path != "/",
		u.Hostname() == "", strings.HasSuffix(u.Host, ":"), strings.Contains(u.Hostname(), ":") && !strings.HasPrefix(u.Host, "["):
		return nil, ErrBadProxy
	}
	return u, nil
}

// httpsProxy is the HTTPS_PROXY value, read now rather than once per process.
func httpsProxy() string {
	raw := os.Getenv("HTTPS_PROXY")
	if raw == "" {
		raw = os.Getenv("https_proxy")
	}
	return raw
}

// ProxyFor is the proxy a transport using Proxy takes to reach target: the
// environment's, or nil for none. target is the URL the fetch dials: an
// OIDC verifier's issuer, a k8s verifier's JWKS URL, a source's url. An
// HTTPS_PROXY that does not parse as a proxy URL is an error, never "no
// proxy": the transport would drop it silently or dial a host nobody
// configured.
func ProxyFor(target string) (*url.URL, error) {
	if raw := httpsProxy(); raw != "" {
		if _, err := parseProxy(raw); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return Proxy(req)
}

// Proxy is a transport's Proxy: the environment's, held to parseProxy
// first. A value the transport would misread — a '/', '?' or '#' in the
// password moving the credentials into the path, the query or the host — is
// refused, never dialled: dialled, it reaches a host nobody configured, and
// its DNS lookup can carry part of the password. An error the transport
// would print, which quotes the value, is replaced by ErrBadProxy too. The
// environment is read at each call, so a change needs no restart.
func Proxy(req *http.Request) (*url.URL, error) {
	if raw := httpsProxy(); raw != "" {
		if _, err := parseProxy(raw); err != nil {
			return nil, ErrBadProxy
		}
	}
	u, err := httpproxy.FromEnvironment().ProxyFunc()(req.URL)
	if err != nil {
		return nil, ErrBadProxy
	}
	return u, nil
}

// Describe is the start line's words for u: its scheme and host, and that it
// carries credentials, never the credentials; or directly.
func Describe(u *url.URL) string {
	if u == nil {
		return "directly (no HTTPS_PROXY)"
	}
	with := ""
	if u.User != nil {
		with = " (with credentials)"
	}
	return "through the proxy " + u.Scheme + "://" + u.Host + with + " (HTTPS_PROXY)"
}
