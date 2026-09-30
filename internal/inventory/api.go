package inventory

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
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
	return mux
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
	a.mu.Lock()
	if a.told == nil {
		a.told = map[string]bool{}
	}
	key := reason + " " + caller
	say := !a.told[key] && len(a.told) < maxTold
	if say {
		a.told[key] = true
	}
	a.mu.Unlock()
	if say {
		fmt.Fprintf(a.Log, "port49-inventory: api: refused %s (%s) %s; readers and syncers in port49-inventory.yaml "+
			"decide who may call\n", caller, right, reason)
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
}

func (a *API) bundle(w http.ResponseWriter, r *http.Request, _ string) {
	p := a.Syncer.Current()
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

func (a *API) diff(w http.ResponseWriter, r *http.Request, _ string) {
	from, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if err != nil || from < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from_not_a_sequence"})
		return
	}
	rep, err := a.Syncer.Diff(from)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_kept", "detail": oneLine(err)})
		return
	}
	writeJSON(w, http.StatusOK, DiffResult{From: from, To: a.Syncer.Current().Doc.Sequence, Summary: rep.Summary(),
		Changes: rep.Changes})
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
// anchor. HTTP/1.1 only (a non-nil TLSNextProto). WriteTimeout covers a POST
// /v1/sync waiting for a slow source.
func Server(addr string, cert tls.Certificate, anchor *x509.CertPool, h http.Handler, errLog *log.Logger) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ErrorLog: errLog,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 6 * time.Minute,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientCAs: anchor,
			ClientAuth: tls.RequireAndVerifyClientCert},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
}
