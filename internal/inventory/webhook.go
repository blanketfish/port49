package inventory

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	// maxWebhookBody bounds one delivery: the largest L27 and L30 recorded,
	// Nautobot 3.2.6's device update, is 18,972 bytes.
	maxWebhookBody = 1 << 20
	// webhookWindow is how far a delivery's timestamp may be from this
	// host's clock, either way. L27 and L30 recorded arrivals 0.03 s to 9.4 s
	// after it; a delivery older than the window is a replay or a backlog the
	// schedule covers.
	webhookWindow = 5 * time.Minute
	// maxSeen bounds the signatures remembered against a replay.
	maxSeen = 4096
)

// Webhook outcomes: port49_inventory_webhooks_total's outcome label.
const (
	HookAccepted       = "accepted"
	HookDuplicate      = "duplicate"
	HookStale          = "stale"
	HookBadSignature   = "bad_signature"
	HookUnsigned       = "unsigned"
	HookTooLarge       = "too_large"
	HookBadBody        = "bad_body"
	HookBadContentType = "bad_content_type"
	HookUnknownSource  = "unknown_source"
	HookBadPath        = "bad_path"
	// HookTLSHandshake counts a TLS handshake that failed: counted, never
	// logged, since the listener faces the source of truth's network and a
	// scanner would otherwise write a line per probe (pre-flight M10).
	HookTLSHandshake = "tls_handshake"
)

// hookHint is what a refusal's line tells the operator to do.
var hookHint = map[string]string{
	HookStale: "its timestamp is more than 5m from this host's clock: check NTP on both hosts; the scheduled sync " +
		"covers the change",
	HookBadSignature:   "the webhook's secret in the source must be the value webhook_secret_env names",
	HookUnsigned:       "set the webhook's secret in the source; port49-inventory takes only signed deliveries",
	HookTooLarge:       "a delivery is at most 1 MiB",
	HookBadBody:        "its body has no timestamp port49-inventory reads",
	HookBadContentType: "the webhook's HTTP content type must be application/json",
	HookUnknownSource:  "no source of that name takes webhooks: the payload URL ends /v1/webhook/<source name>",
	HookBadPath:        "the payload URL is https://<webhook_listen>/v1/webhook/<source name>",
}

// Webhooks takes NetBox's and Nautobot's deliveries (spec §10; decision 31).
// A delivery is authenticated by X-Hook-Signature, HMAC-SHA512 of its body
// under its source's webhook secret (L27, L30), and then only triggers a
// sync of that source (Notify): nothing in it reaches the bundle, so its
// order, which is not change order on Nautobot (L27, L30), orders nothing,
// and its timestamp is read only for freshness.
type Webhooks struct {
	Secrets map[string][]byte
	Notify  func(source string)
	Now     func() time.Time
	Log     io.Writer
	Metrics *Metrics

	mu   sync.Mutex
	seen map[string]time.Time
	told map[string]bool
	ok   map[string]bool
}

func (h *Webhooks) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/webhook/{source}", h.deliver)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { h.refuse(w, r, "", HookBadPath, http.StatusNotFound) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A path that is not clean is refused before the mux, which would
		// answer it with a redirect.
		if p := r.URL.Path; p == "" || p[0] != '/' || path.Clean(p) != p {
			h.refuse(w, r, "", HookBadPath, http.StatusNotFound)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// deliver checks a delivery cheapest first: it reads the body, capped,
// only once the path names a source and a signature is present and well
// formed, and parses it only after the signature verifies.
func (h *Webhooks) deliver(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	secret, ok := h.Secrets[source]
	if !ok {
		// The name is the caller's text: neither counted under it nor said.
		h.refuse(w, r, "", HookUnknownSource, http.StatusUnauthorized)
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		h.refuse(w, r, source, HookBadContentType, http.StatusUnsupportedMediaType)
		return
	}
	sigHex := r.Header.Get("X-Hook-Signature")
	if sigHex == "" {
		h.refuse(w, r, source, HookUnsigned, http.StatusUnauthorized)
		return
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != sha512.Size {
		h.refuse(w, r, source, HookBadSignature, http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			h.refuse(w, r, source, HookTooLarge, http.StatusRequestEntityTooLarge)
			return
		}
		h.refuse(w, r, source, HookBadBody, http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha512.New, secret)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), sig) {
		h.refuse(w, r, source, HookBadSignature, http.StatusUnauthorized)
		return
	}
	var b struct {
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(body, &b) != nil {
		h.refuse(w, r, source, HookBadBody, http.StatusBadRequest)
		return
	}
	at, err := parseHookTime(b.Timestamp)
	if err != nil {
		h.refuse(w, r, source, HookBadBody, http.StatusBadRequest)
		return
	}
	now := h.Now()
	if d := now.Sub(at); d > webhookWindow || d < -webhookWindow {
		h.refuse(w, r, source, HookStale, http.StatusBadRequest)
		return
	}
	if !h.remember(source+"\x00"+hex.EncodeToString(sig), now) {
		h.Metrics.Webhooks.WithLabelValues(source, HookDuplicate).Inc()
		writeJSON(w, http.StatusAccepted, map[string]string{"outcome": HookDuplicate})
		return
	}
	h.accepted(source, r)
	h.Notify(source)
	writeJSON(w, http.StatusAccepted, map[string]string{"outcome": HookAccepted})
}

// hookLayouts are the two timestamp spellings L27 and L30 recorded:
// NetBox's (2026-09-30T15:43:34.000898+00:00) and Nautobot's
// (2026-09-30 15:52:04.757496+00:00).
var hookLayouts = []string{"2006-01-02T15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999Z07:00"}

func parseHookTime(s string) (time.Time, error) {
	for _, l := range hookLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("not a timestamp")
}

// remember reports whether key, a source and a signature, is new inside
// twice the window — the span a delivery stays fresh — and remembers it.
// At maxSeen, expired keys are dropped, and then the soonest to expire.
func (h *Webhooks) remember(key string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen == nil {
		h.seen = map[string]time.Time{}
	}
	if until, ok := h.seen[key]; ok && now.Before(until) {
		return false
	}
	if len(h.seen) >= maxSeen {
		for k, until := range h.seen {
			if !now.Before(until) {
				delete(h.seen, k)
			}
		}
	}
	if len(h.seen) >= maxSeen {
		// Still full of live entries (a bulk import): the soonest to expire
		// goes, so the newest delivery is always remembered (pre-flight M11).
		var oldest string
		for k, until := range h.seen {
			if oldest == "" || until.Before(h.seen[oldest]) {
				oldest = k
			}
		}
		delete(h.seen, oldest)
	}
	h.seen[key] = now.Add(2 * webhookWindow)
	return true
}

// refuse answers code, counts the outcome, and says it once per source and
// outcome while fewer than maxTold are remembered. The line names the
// source (configuration) and the sender's address, never the body, the
// signature, the secret or the path.
func (h *Webhooks) refuse(w http.ResponseWriter, r *http.Request, source, outcome string, code int) {
	h.Metrics.Webhooks.WithLabelValues(source, outcome).Inc()
	h.mu.Lock()
	if h.told == nil {
		h.told = map[string]bool{}
	}
	key := outcome + "\x00" + source
	say := !h.told[key] && len(h.told) < maxTold
	if say {
		h.told[key] = true
	}
	h.mu.Unlock()
	if say {
		what := "a delivery for source " + source
		if source == "" {
			what = "a delivery that names no source taking webhooks"
		}
		fmt.Fprintf(h.Log, "port49-inventory: webhook: refused %s from %s (%s): %s\n", what, remoteHost(r), outcome,
			hookHint[outcome])
	}
	// Every 401 has one body, so an unauthenticated caller cannot tell a
	// configured source's name (unsigned, bad_signature) from another
	// (unknown_source); the outcome is the metric's and the line's
	// (pre-flight M9).
	body := outcome
	if code == http.StatusUnauthorized {
		body = "unauthorized"
	}
	writeJSON(w, code, map[string]string{"error": body})
}

// accepted counts a delivery taken, and says the first a source sends, and
// the first after a refusal of that source was said.
func (h *Webhooks) accepted(source string, r *http.Request) {
	h.Metrics.Webhooks.WithLabelValues(source, HookAccepted).Inc()
	h.mu.Lock()
	if h.ok == nil {
		h.ok = map[string]bool{}
	}
	first, again := !h.ok[source], false
	h.ok[source] = true
	for k := range h.told {
		if strings.HasSuffix(k, "\x00"+source) {
			delete(h.told, k)
			again = true
		}
	}
	h.mu.Unlock()
	switch {
	case first:
		fmt.Fprintf(h.Log, "port49-inventory: webhook: source %s's deliveries authenticate (first from %s); each "+
			"triggers a sync of %s\n", source, remoteHost(r), source)
	case again:
		fmt.Fprintf(h.Log, "port49-inventory: webhook: source %s's deliveries authenticate again (from %s)\n", source,
			remoteHost(r))
	}
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "an unknown address"
	}
	return host
}

// WebhookServer serves h on addr over TLS under cert, asking no client
// certificate: no product can present one (decision 31). HTTP/1.1 only.
func WebhookServer(addr string, cert tls.Certificate, h http.Handler, errLog *log.Logger) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ErrorLog: errLog,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10, DisableGeneralOptionsHandler: true,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
			ClientAuth: tls.NoClientCert},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
}

// WebhookErrorLog is the webhook server's net/http error log: a TLS
// handshake error is counted (outcome tls_handshake, source "") and dropped;
// any other line is said once, while fewer than maxTold are remembered
// (pre-flight M10).
func WebhookErrorLog(m *Metrics, out io.Writer) *log.Logger {
	return log.New(&errorLine{m: m, out: out, said: map[string]bool{}}, "", 0)
}

type errorLine struct {
	m    *Metrics
	out  io.Writer
	mu   sync.Mutex
	said map[string]bool
}

func (e *errorLine) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if strings.Contains(line, "TLS handshake error") {
		e.m.Webhooks.WithLabelValues("", HookTLSHandshake).Inc()
		return len(p), nil
	}
	e.mu.Lock()
	say := !e.said[line] && len(e.said) < maxTold
	if say {
		e.said[line] = true
	}
	e.mu.Unlock()
	if say {
		fmt.Fprintf(e.out, "port49-inventory: webhook: %s\n", line)
	}
	return len(p), nil
}
