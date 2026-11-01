package inventory

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
)

// VersionInfo is GET /v1/bundle/version: what a daemon compares with what it
// holds, every poll_interval, before it asks for anything larger.
type VersionInfo struct {
	Sequence     int64     `json:"sequence"`
	ETag         string    `json:"etag"`
	Bundle       string    `json:"bundle"`
	PolicySHA256 string    `json:"policy_sha256"`
	PublishedAt  time.Time `json:"published_at"`
}

// DiffResult is GET /v1/bundle/diff?from=<sequence>.
type DiffResult struct {
	From    int64           `json:"from"`
	To      int64           `json:"to"`
	Summary string          `json:"summary"`
	Changes []bundle.Change `json:"changes"`
}

// API is the service's HTTP API (spec §10), behind Server's mutual TLS. Every
// path names its caller (CallerOf); Readers may read, Syncers may read and
// sync. It has no health path: /healthz and /readyz are on metrics_listen,
// where a probe needs no client certificate.
type API struct {
	Syncer           *Syncer
	Readers, Syncers []string
	Now              func() time.Time
	Log              io.Writer
	Metrics          *Metrics

	mu   sync.Mutex
	told map[string]bool
}

// maxTold bounds the refusals remembered as said: past it, a refusal is
// counted and not said, so a caller cycling certificates cannot grow memory.
const maxTold = 256

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundle", a.gate(false, a.bundle))
	mux.HandleFunc("GET /v1/bundle/version", a.gate(false, a.version))
	mux.HandleFunc("GET /v1/bundle/diff", a.gate(false, a.diff))
	mux.HandleFunc("GET /v1/devices/{address}", a.gate(false, a.device))
	mux.HandleFunc("POST /v1/sync", a.gate(true, a.sync))
	// A path that matches no route is refused like any other: named first.
	mux.HandleFunc("/", a.gate(false, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}))
	return a.canonical(mux)
}

// canonical refuses, 400, a path that is not already clean — `//`, a `.` or
// `..` segment, encoded or not, a trailing slash — before the mux sees it,
// so the mux never answers one with an ungated redirect. It is counted and
// said once, with a fixed label: the path is the caller's text.
func (a *API) canonical(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "" || p[0] != '/' || path.Clean(p) != p {
			a.Metrics.APIRefused.WithLabelValues("bad_path").Inc()
			if a.tell("bad_path") {
				fmt.Fprintln(a.Log, "port49-inventory: api: refused a path that is not canonical (bad_path); "+
					"a client asks for a clean path, with no empty or dot segment")
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_path"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type handler func(w http.ResponseWriter, r *http.Request, caller string)

// gate names the caller and refuses one without the right: a sync needs
// syncers, anything else readers or syncers. The name matches an entry
// exactly: `*` and globs are only text. No path reads a request body, so it
// is bounded to nothing.
func (a *API) gate(sync bool, h handler) http.HandlerFunc {
	right := "read"
	if sync {
		right = "sync"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 0)
		caller, err := CallerOf(r.TLS, a.Now())
		if err != nil {
			a.refuse(w, "untrusted", "an unnamed caller ("+err.Error()+")", right)
			return
		}
		if !slices.Contains(a.Syncers, caller) && (sync || !slices.Contains(a.Readers, caller)) {
			a.refuse(w, "forbidden", caller, right)
			return
		}
		h(w, r, caller)
	}
}

// refuse answers 403 and says it once per reason and caller. The line names
// the right asked for, never the path: a decoded path is the caller's text,
// and one caller cycling paths must not use up maxTold for everyone
// (pre-flight minor 3). caller is CallerOf's name, printable by construction.
func (a *API) refuse(w http.ResponseWriter, reason, caller, right string) {
	a.Metrics.APIRefused.WithLabelValues(reason).Inc()
	if a.tell(reason + " " + caller) {
		fmt.Fprintf(a.Log, "port49-inventory: api: refused %s (%s) %s; readers and syncers in port49-inventory.yaml "+
			"decide who may call\n", caller, right, reason)
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
}

// tell reports whether key is new, remembering it, while fewer than maxTold
// are remembered: each refusal is said once, and memory stays bounded.
func (a *API) tell(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.told == nil {
		a.told = map[string]bool{}
	}
	if a.told[key] || len(a.told) >= maxTold {
		return false
	}
	a.told[key] = true
	return true
}

// bundle is GET /v1/bundle: the bundle published, or with ?sequence=N bundle
// N from the history (spec §12, `inventory export --from`). The query takes
// sequence alone, in its one decimal spelling.
func (a *API) bundle(w http.ResponseWriter, r *http.Request, caller string) {
	p := a.Syncer.Current()
	if q := r.URL.Query(); len(q) > 0 {
		v, ok := q["sequence"]
		seq, err := int64(0), error(nil)
		if ok && len(q) == 1 && len(v) == 1 {
			seq, err = strconv.ParseInt(v[0], 10, 64)
		}
		// One spelling per sequence: `+1` and `01` are not 1.
		if !ok || len(q) != 1 || len(v) != 1 || err != nil || seq < 1 || strconv.FormatInt(seq, 10) != v[0] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not_a_sequence"})
			return
		}
		switch p, err = a.Syncer.At(seq); {
		case errors.Is(err, ErrNoBundle):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
			return
		case errors.Is(err, ErrNotKept):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_kept"})
			return
		case err != nil:
			// The service's own text, for its operator, once per caller.
			if a.tell("bundle_at_failed " + caller) {
				fmt.Fprintf(a.Log, "port49-inventory: api: bundle %d: %s\n", seq, oneLine(err))
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
	}
	if p == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
		return
	}
	etag := bundle.ETag(p.Raw)
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(p.Raw)
}

func (a *API) version(w http.ResponseWriter, _ *http.Request, _ string) {
	p := a.Syncer.Current()
	if p == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
		return
	}
	writeJSON(w, http.StatusOK, VersionInfo{Sequence: p.Doc.Sequence, ETag: bundle.ETag(p.Raw), Bundle: p.Doc.Bundle,
		PolicySHA256: p.Doc.PolicySHA256, PublishedAt: p.Doc.PublishedAt})
}

func (a *API) diff(w http.ResponseWriter, r *http.Request, caller string) {
	from, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if err != nil || from < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from_not_a_sequence"})
		return
	}
	rep, to, err := a.Syncer.Diff(from)
	switch {
	case errors.Is(err, ErrNoBundle):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_bundle"})
		return
	case errors.Is(err, ErrNotKept):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_kept"})
		return
	case err != nil:
		// The service's own text — paths, a policy error — is for its
		// operator, not the caller; said once per caller, so a broken
		// policy file polled by every reader is one line each.
		if a.tell("diff_failed " + caller) {
			fmt.Fprintf(a.Log, "port49-inventory: api: diff from %d: %s\n", from, oneLine(err))
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, DiffResult{From: from, To: to, Summary: rep.Summary(), Changes: rep.Changes})
}

func (a *API) device(w http.ResponseWriter, r *http.Request, _ string) {
	addr, err := netip.ParseAddr(r.PathValue("address"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not_an_address"})
		return
	}
	v, ok := a.Syncer.Describe(addr)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *API) sync(w http.ResponseWriter, r *http.Request, caller string) {
	fmt.Fprintf(a.Log, "port49-inventory: sync requested by %s\n", caller)
	writeJSON(w, http.StatusOK, a.Syncer.Sync(r.Context(), "api"))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// Server serves h over mutual TLS on addr (spec §10): a client certificate
// is required on every path and verified against anchor, the one trust
// anchor. A nil anchor is refused: crypto/tls would verify a client against
// the host's system roots. HTTP/1.1 only (a non-nil TLSNextProto).
// WriteTimeout covers a POST /v1/sync waiting for a slow source.
func Server(addr string, cert tls.Certificate, anchor *x509.CertPool, h http.Handler, errLog *log.Logger) (*http.Server, error) {
	if anchor == nil {
		return nil, errors.New("port49-inventory: api: no client trust anchor; client_ca_file names the one CA " +
			"that issues callers' certificates")
	}
	return &http.Server{Addr: addr, Handler: h, ErrorLog: errLog,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 6 * time.Minute,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		// OPTIONS * goes to h, which refuses it (bad_path), not to net/http's
		// ungated 200.
		DisableGeneralOptionsHandler: true,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientCAs: anchor,
			ClientAuth: tls.RequireAndVerifyClientCert},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}, nil
}
