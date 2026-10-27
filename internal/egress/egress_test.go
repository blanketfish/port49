package egress

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Review I1: a proxy URL that does not parse as one is refused without
// saying any of it, and the start line names scheme and host only.
func TestAProxyURLIsValidatedAndNeverPrinted(t *testing.T) {
	const pw = "FAKE-pw"
	for _, raw := range []string{
		"http://svc:" + pw + "#x@proxy.example.com:3128",
		"http://svc:" + pw + "/x@proxy.example.com:3128",
		"http://svc:" + pw + "?x@proxy.example.com:3128",
		"http://svc:" + pw + "@proxy.example.com:3128:badport",
		"http://svc:" + pw + "@proxy.example.com:badport",
		"http://svc:" + pw + "%zz@proxy.example.com:3128",
		"http://svc:" + pw + "@proxy.example.com:3128/path",
	} {
		u, err := parseProxy(raw)
		if err == nil || strings.Contains(err.Error(), pw) {
			t.Errorf("%q: %v, %v", strings.ReplaceAll(raw, pw, "***"), u, err)
		}
		t.Setenv("HTTPS_PROXY", raw)
		if got, err := ProxyFor("https://idp.example.com"); err == nil || got != nil || strings.Contains(err.Error(), pw) {
			t.Errorf("ProxyFor with %q: %v, %v", strings.ReplaceAll(raw, pw, "***"), got, err)
		}
	}
	for raw, want := range map[string]string{
		"http://svc:" + pw + "@proxy.example.com:3128": "through the proxy http://proxy.example.com:3128 (with credentials) (HTTPS_PROXY)",
		"http://proxy.example.com:3128":                "through the proxy http://proxy.example.com:3128 (HTTPS_PROXY)",
		"proxy.example.com:3128":                       "through the proxy http://proxy.example.com:3128 (HTTPS_PROXY)",
	} {
		u, err := parseProxy(raw)
		if err != nil {
			t.Errorf("%q: %v", strings.ReplaceAll(raw, pw, "***"), err)
			continue
		}
		if got := Describe(u); got != want || strings.Contains(got, pw) {
			t.Errorf("Describe = %q, want %q", got, want)
		}
	}
}

func TestDescribeNamesNoCredentials(t *testing.T) {
	u := &url.URL{Scheme: "http", User: url.UserPassword("svc", "FAKE-proxy-secret"), Host: "proxy.example.com:3128"}
	if got := Describe(u); strings.Contains(got, "FAKE-proxy-secret") || strings.Contains(got, "svc") ||
		!strings.Contains(got, "proxy.example.com:3128") {
		t.Fatalf("Describe(%v) = %q", u.Host, got)
	}
	if got := Describe(nil); got != "directly (no HTTPS_PROXY)" {
		t.Fatalf("no proxy: %q", got)
	}
}

// A proxy URL the transport cannot read is refused in fixed words: the
// value carries a password (Review Focus 1).
func TestABadProxyIsNeverPrinted(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://user:FAKE-pw#x@proxy:3128")
	_, err := ProxyFor("https://netbox.example.com")
	if err != nil && strings.Contains(err.Error(), "FAKE-pw") {
		t.Fatal("the refusal carries the proxy password")
	}
	if !errors.Is(err, ErrBadProxy) {
		t.Fatalf("%v", err)
	}
}

// A value net/url reads without error but wrongly — a '/' in the password
// makes the host "u:123" — is refused by the transport's Proxy too, so the
// transport never dials a host nobody configured, with part of the password
// in its DNS lookup (pre-flight I10; identity.go's F3).
func TestAMisreadProxyIsRefusedByTheTransport(t *testing.T) {
	for _, v := range []string{"http://u:123/x@proxy:3128", "http://user:pa?ss@proxy:3128", "http://user:FAKE-pw#x@proxy:3128"} {
		t.Setenv("HTTPS_PROXY", v)
		req, _ := http.NewRequest(http.MethodGet, "https://netbox.example.com/api/", nil)
		u, err := Proxy(req)
		if !errors.Is(err, ErrBadProxy) || u != nil || strings.Contains(err.Error(), "123") || strings.Contains(err.Error(), "FAKE") {
			t.Errorf("%q: %v %v", strings.ReplaceAll(v, "FAKE-pw", "***"), u, err)
		}
	}
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
	req, _ := http.NewRequest(http.MethodGet, "https://netbox.example.com/api/", nil)
	if u, err := Proxy(req); err != nil || u == nil || u.Host != "proxy.example.com:3128" {
		t.Fatalf("a good proxy: %v %v", u, err)
	}
	// NO_PROXY is honoured.
	t.Setenv("NO_PROXY", "netbox.example.com")
	if u, err := Proxy(req); err != nil || u != nil {
		t.Fatalf("NO_PROXY: %v %v", u, err)
	}
}
