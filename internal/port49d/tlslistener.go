package port49d

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/daemon/server"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
)

// tlsFileMax bounds each of the listener's files: a chain or a CA bundle is
// kilobytes.
const tlsFileMax = 1 << 20

// tlsListener holds the RFC 9887 listener's files as loaded, and swaps them
// whole when something the Material carries changes and it loads (spec §13
// decision 50 ruling 15). The key file's bytes are hashed to tell a change
// and never kept, said or logged.
//
// A Material is swapped only when an input changed: a tick or a SIGHUP that
// finds the same bytes, the same devices flagged and the same settings keeps
// the same pointer, so the tickets it issued still resume.
type tlsListener struct {
	cfg          config.TLSListenerConfig
	status       devicecert.StatusFunc
	cached       devicecert.CachedStatusFunc
	allowUnknown bool
	devices      func() []admission.Device // the admitted devices now; nil is none
	now          func() time.Time
	say          func(format string, args ...any)

	cur        atomic.Pointer[server.Material]
	serverLeaf atomic.Pointer[x509.Certificate]

	// follow, when set, brings the status checker's issuer set to the
	// anchors and intermediates the files in force name, and says what is
	// uncovered. It does nothing when the trust and the issuer files are as
	// it last saw them. A nil follow is no checker.
	follow func(anchors, inters []*x509.Certificate) error

	mu           sync.Mutex
	files        tlsFiles // the last set that loaded
	anchors      string   // describe of the anchors in force
	followFailed string
	pending      []admission.Device // swapping's union, until inventoryChanged
	hasPending   bool
	sighup       bool              // the config note was said
	fsum         [32]byte          // its hash
	state        [32]byte          // the hash of every input cur was built from
	flagged      map[string]string // devices said unidentifiable, and the reason said
	failed       string
}

// newTLSListener loads the files, or refuses with an error naming the one
// at fault: nothing is published on failure.
func newTLSListener(cfg config.TLSListenerConfig, status devicecert.StatusFunc, cached devicecert.CachedStatusFunc,
	allowUnknown bool, devices func() []admission.Device, now func() time.Time,
	say func(string, ...any)) (*tlsListener, error) {
	l := &tlsListener{cfg: cfg, status: status, cached: cached, allowUnknown: allowUnknown, devices: devices, now: now,
		say: say}
	files, sum, err := l.read()
	if err != nil {
		return nil, err
	}
	if _, err := l.apply("", files, sum, l.current()); err != nil {
		return nil, err
	}
	return l, nil
}

// current is the admitted devices now: those of an inventory about to be
// put in force (swapping) until it is (inventoryChanged), so a reload that
// lands between the two cannot judge the old inventory alone.
func (l *tlsListener) current() []admission.Device {
	if l.hasPending {
		return l.pending
	}
	if l.devices == nil {
		return nil
	}
	return l.devices()
}

// Material is the set in force, for server.TLS. It is never nil once
// newTLSListener returns.
func (l *tlsListener) Material() *server.Material { return l.cur.Load() }

// ServerLifetimeLeft is the fraction of its own lifetime the server
// certificate in force has left (devicecert.LifetimeLeft).
func (l *tlsListener) ServerLifetimeLeft() float64 {
	return devicecert.LifetimeLeft(l.serverLeaf.Load(), l.now())
}

// reload reads the files again. A set that loads replaces the one in force
// if anything it carries changed, and is said; one that does not is said
// once per distinct failure, and the set in force stays. Either way the
// devices the rule cannot identify follow the inventory now, and the status
// checker follows the trust set in force.
func (l *tlsListener) reload(why string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if why == "SIGHUP" && !l.sighup {
		l.sighup = true
		l.say("tls_listener: config changes take effect at restart; files reload now")
	}
	files, sum, err := l.read()
	swapped := false
	if err == nil {
		swapped, err = l.apply(why, files, sum, l.current())
	}
	if err != nil {
		l.refuse(why, err)
		// The files in force stay, but a changed inventory must still reach
		// them: a stale flag would admit a device the rule cannot tell apart.
		if _, err := l.apply(why, l.files, l.fsum, l.current()); err != nil {
			l.refuse(why, err)
		}
	} else {
		if l.failed != "" && !swapped {
			l.say("tls_listener: %s: the files load again; the set in force is unchanged", why)
		}
		l.failed = ""
	}
	l.followTrust(why)
}

// inventoryChanged recomputes the devices the rule cannot identify after the
// inventory in force changed (a reload or a sync), from the files in force.
func (l *tlsListener) inventoryChanged(why string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending, l.hasPending = nil, false
	if _, err := l.apply(why, l.files, l.fsum, l.current()); err != nil {
		l.refuse(why, err)
	}
}

// swapping is told the admitted devices of an inventory about to be put in
// force, before it is: a clash it creates is flagged before the first
// connection can be admitted under it. The devices judged are those in force
// and those coming, so a device whose twin is on its way out stays flagged
// until the swap is done; inventoryChanged then judges the new set alone.
func (l *tlsListener) swapping(next []admission.Device) {
	l.mu.Lock()
	defer l.mu.Unlock()
	names := map[string]bool{}
	for _, d := range next {
		names[d.Name] = true
	}
	union := slices.Clone(next)
	for _, d := range l.current() {
		if !names[d.Name] {
			union = append(union, d)
		}
	}
	l.pending, l.hasPending = union, true
	if _, err := l.apply("inventory", l.files, l.fsum, union); err != nil {
		l.refuse("inventory", err)
	}
}

// followTrust brings the status checker's issuer set to the trust the files
// in force name, when that or the issuer files changed. The caller holds mu.
func (l *tlsListener) followTrust(why string) {
	if l.follow == nil {
		return
	}
	anchors, inters, err := trustOf(l.cfg, l.files)
	if err != nil {
		return // apply said it
	}
	err = l.follow(anchors, inters)
	switch msg := fmt.Sprint(err); {
	case err == nil:
		if l.followFailed != "" {
			l.say("tls_listener: %s: the certificate status issuers load again", why)
		}
		l.followFailed = ""
	case msg != l.followFailed:
		l.followFailed = msg
		var fe *followError
		if errors.As(err, &fe) && fe.rotated {
			l.say("tls_listener: %s: the certificate status sources keep the issuers they had, and devices under a "+
				"new CA are declined status_unavailable until this is fixed: %s", why, printsafe.Line(msg, 400))
		} else {
			l.say("tls_listener: %s: the certificate status sources keep the issuers they had: %s", why,
				printsafe.Line(msg, 400))
		}
	}
}

// trustOf is the anchors and the intermediates the files hold.
func trustOf(cfg config.TLSListenerConfig, f tlsFiles) (anchors, inters []*x509.Certificate, err error) {
	if anchors, err = tlsCACerts("client_ca_file", cfg.ClientCAFile, f.ca); err != nil {
		return nil, nil, err
	}
	if cfg.IntermediatesFile != "" {
		if inters, err = tlsCACerts("intermediates_file", cfg.IntermediatesFile, f.inter); err != nil {
			return nil, nil, err
		}
	}
	return anchors, inters, nil
}

// refuse says a load that did not take, once per distinct failure.
func (l *tlsListener) refuse(why string, err error) {
	if msg := err.Error(); msg != l.failed {
		l.failed = msg
		l.say("tls_listener: %s: not reloaded, the files in force stay; kept: anchors %s (the new set did not "+
			"load): %s", why, l.anchors, msg)
	}
}

// watch reloads every reload_interval until ctx ends.
func (l *tlsListener) watch(ctx context.Context) {
	every := l.cfg.ReloadInterval
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.reload("reload_interval")
		}
	}
}

type tlsFiles struct{ cert, key, ca, inter []byte }

// read reads the four files, each a regular file within tlsFileMax, and
// their joint hash.
func (l *tlsListener) read() (tlsFiles, [32]byte, error) {
	var f tlsFiles
	h := sha256.New()
	for _, x := range []struct {
		key, path string
		into      *[]byte
	}{{"cert_file", l.cfg.CertFile, &f.cert}, {"key_file", l.cfg.KeyFile, &f.key},
		{"client_ca_file", l.cfg.ClientCAFile, &f.ca}, {"intermediates_file", l.cfg.IntermediatesFile, &f.inter}} {
		if x.path == "" {
			continue
		}
		b, err := config.ReadRegular(x.path, tlsFileMax)
		if err != nil {
			return tlsFiles{}, [32]byte{}, fmt.Errorf("tls_listener.%s %s: %w", x.key, x.path, err)
		}
		*x.into = b
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return f, sum, nil
}

// rule is tls_listener.device_identity as devicecert reads it.
func (l *tlsListener) rule() devicecert.Rule {
	id := l.cfg.DeviceIdentity
	return devicecert.Rule{DNSName: slices.Contains(id.Match, "dns_name"),
		IPAddress: slices.Contains(id.Match, "ip_address"), DNSSuffixes: id.DNSSuffixes}
}

// fingerprint hashes everything a Material carries: the files, the devices
// the rule cannot identify, and the settings it is built under.
func (l *tlsListener) fingerprint(fsum [32]byte, unid map[string]string) [32]byte {
	h := sha256.New()
	put := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	h.Write(fsum[:])
	for _, k := range slices.Sorted(maps.Keys(unid)) {
		put(k)
		put(unid[k])
	}
	r := l.rule()
	put(fmt.Sprint(r.DNSName, r.IPAddress, r.DNSSuffixes, l.allowUnknown))
	put(strings.Join(tlsServerNames(l.cfg), "\x00"))
	put(fmt.Sprint(l.cfg.HandshakeTimeout, l.cfg.SessionTicketLifetime))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// apply builds a Material from files and devs, the admitted devices, and
// swaps it in when any input differs from the one in force; it reports
// whether it did. why is "" at the start. The caller holds mu, or is
// newTLSListener.
func (l *tlsListener) apply(why string, files tlsFiles, fsum [32]byte, devs []admission.Device) (bool, error) {
	var unid map[string]string
	if devs != nil {
		unid = l.rule().Unidentifiable(devs)
	}
	if unid == nil {
		unid = map[string]string{}
	}
	fp := l.fingerprint(fsum, unid)
	if l.cur.Load() != nil && fp == l.state {
		return false, nil
	}
	m, leaf, desc, err := l.build(files, unid)
	if err != nil {
		return false, err
	}
	sameFiles := l.cur.Load() != nil && fsum == l.fsum
	l.cur.Store(m)
	l.serverLeaf.Store(leaf)
	l.files, l.fsum, l.state = files, fsum, fp
	l.anchors = desc.anchors
	switch {
	case why == "":
		l.say("tls_listener: %s", desc.all)
	case sameFiles:
		l.say("tls_listener: %s: files unchanged; devices the rule cannot identify recomputed (%d)", why, len(unid))
	default:
		l.say("tls_listener: %s: reloaded: %s", why, desc.all)
	}
	l.sayExpired(leaf)
	l.sayUnidentifiable(unid)
	return true, nil
}

// sayUnidentifiable names each device flagged since the last time it was
// said, once, with its reason. A device that stops being flagged and is
// flagged again is named again.
func (l *tlsListener) sayUnidentifiable(unid map[string]string) {
	for _, name := range slices.Sorted(maps.Keys(unid)) {
		if l.flagged[name] == unid[name] {
			continue
		}
		l.say("tls_listener: device %s cannot be identified: %s; its connections are declined identity_mismatch "+
			"until that changes", printsafe.Line(name, 200), unid[name])
	}
	l.flagged = unid
}

// buildDesc describes a Material: all of it, and its anchors alone.
type buildDesc struct{ all, anchors string }

// build makes one Material from the files' bytes and the devices the rule
// cannot identify, and describes it.
func (l *tlsListener) build(f tlsFiles, unid map[string]string) (*server.Material, *x509.Certificate, buildDesc, error) {
	cert, err := tls.X509KeyPair(f.cert, f.key)
	if err != nil {
		// crypto/tls's text names the fault, never the key's bytes.
		return nil, nil, buildDesc{}, fmt.Errorf("tls_listener.cert_file %s and key_file %s do not load as a pair (%s)",
			l.cfg.CertFile, l.cfg.KeyFile, printsafe.Line(err.Error(), 200))
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, buildDesc{}, fmt.Errorf("tls_listener.cert_file %s: %w", l.cfg.CertFile, err)
	}
	anchors, err := tlsCACerts("client_ca_file", l.cfg.ClientCAFile, f.ca)
	if err != nil {
		return nil, nil, buildDesc{}, err
	}
	var inters []*x509.Certificate
	if l.cfg.IntermediatesFile != "" {
		if inters, err = tlsCACerts("intermediates_file", l.cfg.IntermediatesFile, f.inter); err != nil {
			return nil, nil, buildDesc{}, err
		}
	}
	pool := x509.NewCertPool()
	for _, a := range anchors {
		pool.AddCert(a)
	}
	base := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true}
	var guard *server.TicketGuard
	tickets := "off"
	if l.cfg.SessionTicketLifetime > 0 {
		guard = server.NewTicketGuard(l.cfg.SessionTicketLifetime, l.now)
		if err := guard.Apply(base); err != nil {
			return nil, nil, buildDesc{}, fmt.Errorf("tls_listener: session ticket keys: %w", err)
		}
		tickets = "single-use, " + l.cfg.SessionTicketLifetime.String()
	}
	ver := &devicecert.Verifier{Anchors: pool, Intermediates: inters, Status: l.status, CachedStatus: l.cached,
		AllowUnknown: l.allowUnknown, Now: l.now, Rule: l.rule()}
	names := make([]string, 0, len(anchors))
	for _, a := range anchors {
		names = append(names, describeCert(a))
	}
	anchorList := strings.Join(names, ", ")
	desc := fmt.Sprintf("anchors %s; %d stored intermediates; server certificate %s expires %s; session tickets %s; "+
		"%d devices the rule cannot identify", strings.Join(names, ", "), len(inters), describeCert(leaf),
		leaf.NotAfter.UTC().Format(time.RFC3339), tickets, len(unid))
	return &server.Material{Config: base, Verifier: ver, Unidentifiable: unid, Tickets: guard}, leaf,
		buildDesc{all: desc, anchors: anchorList}, nil
}

func (l *tlsListener) sayExpired(leaf *x509.Certificate) {
	if now := l.now(); now.After(leaf.NotAfter) {
		l.say("tls_listener: the server certificate expired at %s: devices that check it refuse this listener "+
			"until cert_file is replaced", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
}

// tlsServerNames are the SNI names a ClientHello may ask for: lower case,
// with no trailing dot, whatever the config carries. The config's slice is
// not touched.
func tlsServerNames(cfg config.TLSListenerConfig) []string {
	out := make([]string, 0, len(cfg.ServerNames))
	for _, n := range cfg.ServerNames {
		out = append(out, strings.ToLower(strings.TrimSuffix(n, ".")))
	}
	return out
}

// tlsCACerts parses every CERTIFICATE block in b, the contents of the file at
// path that key names, and refuses one that is not a CA certificate: an
// anchor or an intermediate signs, and a leaf there would admit only itself
// while reading as a CA. A file with no certificate is refused too.
func tlsCACerts(key, path string, b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tls_listener.%s %s: certificate %d: %w", key, path, len(out)+1, err)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf("tls_listener.%s %s: %s is not a CA certificate", key, path,
				printsafe.Line(c.Subject.String(), 200))
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tls_listener.%s %s holds no certificate", key, path)
	}
	return out, nil
}

// describeCert is a certificate's subject and the first 16 hex digits of
// its SHA-256, as the start and reload lines name it.
func describeCert(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return printsafe.Line(c.Subject.String(), 120) + " (sha256 " + hex.EncodeToString(sum[:8]) + ")"
}

// deviceStatus adapts the TLS listener's certstatus.Checker to devicecert:
// Check after a handshake, which may wait on a responder within the
// handshake's deadline, and CheckCached at each packet, which never does
// (rulings 8, 9).
func deviceStatus(c *certstatus.Checker) (devicecert.StatusFunc, devicecert.CachedStatusFunc) {
	return func(ctx context.Context, chain []*x509.Certificate) (devicecert.Status, string) {
			return statusOf(c.Check(ctx, chain))
		}, func(chain []*x509.Certificate) (devicecert.Status, string) {
			return statusOf(c.CheckCached(chain))
		}
}

// statusOf maps a verdict onto devicecert's. Only Good is good: Revoked is
// revoked, and anything else, a verdict this code has never seen included,
// is unknown, which refuses (or, under on_unavailable: allow, admits and
// alarms).
func statusOf(r certstatus.Result) (devicecert.Status, string) {
	switch r.Verdict {
	case certstatus.Good:
		return devicecert.StatusGood, ""
	case certstatus.Revoked:
		return devicecert.StatusRevoked, fmt.Sprintf("%s %s: the certificate at depth %d was revoked at %s",
			r.Source, r.Name, r.Depth, r.RevokedAt.UTC().Format(time.RFC3339))
	}
	if r.Detail == "" {
		return devicecert.StatusUnknown, "the certificate status checker gave a verdict port49d does not know"
	}
	return devicecert.StatusUnknown, r.Detail
}

// tlsListenerOf builds the RFC 9887 listener's material and its status
// checker from cfg.TLSListener: nil, nil without one. devices is the
// admitted devices now, for the rule's unidentifiable list. The files are
// read once: the checker's trust and the material's anchors are the same
// bytes.
func tlsListenerOf(cfg config.Config, m *metrics.Metrics, say func(string, ...any),
	devices func() []admission.Device) (*tlsListener, *certstatus.Checker, error) {
	tc := cfg.TLSListener
	if tc == nil {
		return nil, nil, nil
	}
	l := &tlsListener{cfg: *tc, devices: devices, now: time.Now, say: say}
	l.allowUnknown = tc.CertificateStatus != nil && tc.CertificateStatus.OnUnavailable == "allow"
	files, sum, err := l.read()
	if err != nil {
		return nil, nil, err
	}
	anchors, inters, err := trustOf(*tc, files) // the error names the file it is about (pre-flight M12)
	if err != nil {
		return nil, nil, err
	}
	var checker *certstatus.Checker
	if cs := tc.CertificateStatus; cs != nil && !cs.Disabled {
		// Its own subdirectory of state_dir, so it never writes the file an
		// in-process broker's checker keeps under the same CRL name (ruling 8).
		// WriteAtomic does not create it.
		stateDir := config.TLSListenerStateDir(tc)
		if stateDir != "" {
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				return nil, nil, fmt.Errorf("tls_listener.state_dir: %w", err)
			}
		}
		statusConfig := func(trusted []*x509.Certificate) (certstatus.Config, error) {
			ccfg, err := certStatusConfig(*cs, trusted, stateDir, "tls_listener.client_ca_file or "+
				"intermediates_file", "the TLS listener")
			if err != nil {
				return ccfg, fmt.Errorf("tls_listener.certificate_status.%w", err)
			}
			ccfg.Component = "tls_listener" // its lines' prefix and its metrics' component label
			return ccfg, nil
		}
		ccfg, err := statusConfig(append(slices.Clone(anchors), inters...))
		if err != nil {
			return nil, nil, err
		}
		checker = certstatus.New(ccfg, time.Now, m, say)
		for _, err := range checker.LoadPersisted() {
			say("tls_listener: certificate status: %s", printsafe.Line(err.Error(), 300))
		}
		l.status, l.cached = deviceStatus(checker)
		l.follow = followStatus(checker, statusConfig, ccfg, anchors, inters, say)
	}
	if _, err := l.apply("", files, sum, l.current()); err != nil {
		return nil, nil, err
	}
	return l, checker, nil
}

// followStatus is tlsListener.follow for chk: when the anchors, the
// intermediates or the issuer certificates the CRL sources name differ from
// what chk was last given, it makes the sources again from the files in
// force, which verifies each issuer against the new trust (certStatusConfig),
// and hands them to chk, so a list is verified against the new set and a
// rotation needs no restart (ruling 15). A new anchor no source can answer
// for is said once, with what to add. A set that does not verify leaves the
// sources in force and is the error.
func followStatus(chk *certstatus.Checker, statusConfig func([]*x509.Certificate) (certstatus.Config, error),
	was certstatus.Config, anchors, inters []*x509.Certificate, say func(string, ...any)) func(a, i []*x509.Certificate) error {
	key := trustKey(anchors, inters, was)
	trustOnly := trustKey(anchors, inters, certstatus.Config{})
	known := anchors
	return func(a, i []*x509.Certificate) error {
		ccfg, err := statusConfig(append(slices.Clone(a), i...))
		if err != nil {
			return &followError{err: err, rotated: trustKey(a, i, certstatus.Config{}) != trustOnly}
		}
		trustOnly = trustKey(a, i, certstatus.Config{})
		if k := trustKey(a, i, ccfg); k == key {
			return nil
		} else {
			key = k
		}
		chk.SetCRLSources(ccfg.CRLs)
		say("tls_listener: certificate status: the trust set changed (%d anchors, %d intermediates); the CRL "+
			"sources follow it and are fetched now", len(a), len(i))
		for _, anchor := range a {
			if slices.ContainsFunc(known, func(k *x509.Certificate) bool { return bytes.Equal(k.Raw, anchor.Raw) }) ||
				ccfg.OCSP != nil || !uncoveredAnchor(ccfg, anchor) {
				continue
			}
			sum := sha256.Sum256(anchor.Raw)
			say("tls_listener: certificate status: no source can answer for the new anchor %s (sha256 %s): devices "+
				"under it are declined status_unavailable. Add a crls entry whose issuer_file is that CA, or an "+
				"ocsp block, to tls_listener.certificate_status; that config edit takes effect at restart",
				printsafe.Line(anchor.Subject.String(), 200), hex.EncodeToString(sum[:]))
		}
		known = a
		return nil
	}
}

// followError is a status config that did not verify; rotated is whether the
// trust set changed since the sources were last followed, so that devices
// under a new CA are the ones declined.
type followError struct {
	err     error
	rotated bool
}

func (e *followError) Error() string { return e.err.Error() }
func (e *followError) Unwrap() error { return e.err }

// trustKey hashes the trust set and the issuer certificates the sources name.
func trustKey(anchors, inters []*x509.Certificate, c certstatus.Config) string {
	h := sha256.New()
	for _, set := range [][]*x509.Certificate{anchors, inters} {
		for _, x := range set {
			h.Write(x.Raw)
		}
		h.Write([]byte{0})
	}
	for _, src := range c.CRLs {
		h.Write([]byte(src.Name))
		h.Write(src.Issuer.Raw)
	}
	return string(h.Sum(nil))
}

// sayEvery is how often a device's refusal, or the gathered
// status_unavailable line, is said on stderr.
const sayEvery = 10 * time.Minute

// refusalSayer says each device's TLS refusal on stderr at most once per
// device and outcome every ten minutes (ruling 16): the decision log has
// every one. A status_unavailable is port49's own and reaches every device
// at once, so it is said for the first device and then gathered: run says
// one line every ten minutes with how many devices were declined and up to
// five names, as announceTransports does (pre-flight M9).
type refusalSayer struct {
	now func() time.Time
	say func(string, ...any)

	mu         sync.Mutex
	last       map[string]time.Time
	gathered   map[string]bool // device names declined status_unavailable since the last line
	detail     string          // the last such refusal's detail
	statusSaid time.Time       // when a status_unavailable line was last said
}

func (r *refusalSayer) said(device, source string, v devicecert.Verdict) {
	name := device
	if name == "" {
		name = "an unknown device"
	}
	now := r.now()
	r.mu.Lock()
	if v.Outcome == devicecert.StatusUnavailable {
		quiet := now.Sub(r.statusSaid) >= sayEvery && len(r.gathered) == 0
		if quiet {
			r.statusSaid = now
		} else {
			if r.gathered == nil {
				r.gathered = map[string]bool{}
			}
			r.gathered[name], r.detail = true, v.Detail
		}
		r.mu.Unlock()
		if quiet {
			r.say("tls_listener: %s (%s) declined: status_unavailable: %s; devices declined so from now on are "+
				"counted and said together every 10m", name, source, v.Detail)
		}
		return
	}
	key := device + "\x00" + source + "\x00" + string(v.Outcome)
	if r.last == nil {
		r.last = map[string]time.Time{}
	}
	if at, ok := r.last[key]; ok && now.Sub(at) < sayEvery {
		r.mu.Unlock()
		return
	}
	r.last[key] = now
	r.mu.Unlock()
	r.say("tls_listener: %s (%s) refused: %s: %s (said once per 10m)", name, source, v.Outcome, v.Detail)
}

// flush says the status_unavailable refusals gathered since the last line
// as one line, and nothing when there were none.
func (r *refusalSayer) flush() {
	r.mu.Lock()
	names := slices.Sorted(maps.Keys(r.gathered))
	detail := r.detail
	r.gathered, r.detail = nil, ""
	if len(names) > 0 {
		r.statusSaid = r.now()
	}
	r.mu.Unlock()
	if len(names) == 0 {
		return
	}
	shown, more := names, ""
	if len(shown) > 5 {
		shown, more = shown[:5], fmt.Sprintf(" and %d more", len(names)-5)
	}
	r.say("tls_listener: %d devices declined status_unavailable in the last 10m (%s): %s%s", len(names), detail,
		strings.Join(shown, ", "), more)
}

// run flushes every ten minutes until ctx ends.
func (r *refusalSayer) run(ctx context.Context) {
	t := time.NewTicker(sayEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.flush()
		}
	}
}

// announceTransports is the start's lines about the RFC 9887 listener and
// the devices each transport counts (decision 50 rulings 1 and 4).
func announceTransports(w io.Writer, cfg config.Config, live *policy.Live, ln, tln net.Listener, chk *certstatus.Checker) {
	n, names := transportCount(cfg, live)
	if tln != nil {
		tc := cfg.TLSListener
		status := "disabled (tls_listener.certificate_status.disabled)"
		if chk != nil {
			unavailable := "refused (declined)"
			if tc.CertificateStatus.OnUnavailable == "allow" {
				unavailable = "allowed, alarmed"
			}
			status = "from " + chk.Describe() + "; a status that cannot be established is " + unavailable
		}
		fmt.Fprintf(w, "port49d: RFC 9887 listener on %s (TLS 1.3, mutual certificates; device identity by %s; "+
			"certificate status %s), %d devices transport tls\n", tln.Addr(), strings.Join(tc.DeviceIdentity.Match, " or "),
			status, n["tls"])
	}
	if ln != nil && tln != nil {
		fmt.Fprintf(w, "port49d: notice: RFC 9887 §5.1.1 does not recommend TLS and non-TLS TACACS+ on one host; "+
			"here each device's record names one transport and the other listener declines it "+
			"(transport_mismatch), so blocking %s cannot move a device to %s. Two limits: that is only as strong "+
			"as each record's transport field (a sync flipping tls to tcp is recorded transport_changed, not "+
			"blocked); and this one process holds both the shared keys and the TLS key, so a compromise of "+
			"this host exposes both\n", tln.Addr(), ln.Addr())
	}
	if !servesTLS(cfg) && n["tls"] > 0 {
		fmt.Fprintf(w, "port49d: %d devices have transport tls and port49d serves no tls_listener; their "+
			"connections here are declined transport_mismatch: %s\n", n["tls"], strings.Join(names["tls"], ", "))
	}
	if cfg.Listen == "" && n["tcp"] > 0 {
		fmt.Fprintf(w, "port49d: %d devices have transport tcp and port49d serves no RFC 8907 listener "+
			"(listen: none); their connections here are declined transport_mismatch: %s\n", n["tcp"],
			strings.Join(names["tcp"], ", "))
	}
}

func servesTLS(cfg config.Config) bool { return cfg.TLSListener != nil }

// admittedDevices are the devices admission admits now: from the policy in
// force or, with no broker, the inventory port49d admits from.
func admittedDevices(cfg config.Config, live *policy.Live) []admission.Device {
	var out []admission.Device
	if live != nil {
		return policyDevices(live.Load())
	}
	for _, d := range cfg.Inventory.Devices {
		if len(d.Addresses) == 0 || cfg.Admission == nil {
			continue
		}
		if r, ok := cfg.Admission.Lookup(d.Addresses[0]); ok && r.Refused == "" {
			out = append(out, d)
		}
	}
	return out
}

// policyDevices are the devices pol admits.
func policyDevices(pol *policy.Policy) []admission.Device {
	var out []admission.Device
	for _, d := range pol.Devices() {
		if r, ok := pol.Admitted(d.Name); ok && r.Refused == "" {
			out = append(out, d)
		}
	}
	return out
}

// transportCount is the admitted devices by transport, with up to five
// names of each.
func transportCount(cfg config.Config, live *policy.Live) (map[string]int, map[string][]string) {
	n, names := map[string]int{}, map[string][]string{}
	for _, d := range admittedDevices(cfg, live) {
		t := d.EffectiveTransport()
		n[t]++
		if len(names[t]) < 5 {
			names[t] = append(names[t], d.Name)
		}
	}
	return n, names
}

// unservedOf is how many admitted devices have a transport this port49d
// runs no listener for.
func unservedOf(cfg config.Config, live *policy.Live) int {
	n, _ := transportCount(cfg, live)
	u := 0
	if !servesTLS(cfg) {
		u += n["tls"]
	}
	if cfg.Listen == "" {
		u += n["tcp"]
	}
	return u
}

// serveListeners runs the RFC 8907 listener, the RFC 9887 one, or both,
// and returns once each has: the first to fail ends the run (cancel), so
// the spool is never stopped while either still serves.
func serveListeners(ctx context.Context, cancel context.CancelFunc, ln net.Listener, deps server.Deps,
	tln net.Listener, tlsDeps *server.TLS) error {
	errs := make(chan error, 2)
	n := 0
	if ln != nil {
		n++
		go func() { errs <- server.Serve(ctx, ln, deps) }()
	}
	if tln != nil {
		n++
		td := deps
		td.TLS = tlsDeps
		go func() { errs <- server.Serve(ctx, tln, td) }()
	}
	var first error
	for range n {
		if err := <-errs; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	return first
}

// newTLSDeps is server.TLS for tl: the SNI names folded as the config
// allows them, the material read at each Accept and packet, and the expiry
// and refusal sinks.
func newTLSDeps(tc config.TLSListenerConfig, tl *tlsListener, expiry *devicecert.Expiry, said *refusalSayer) *server.TLS {
	return &server.TLS{Material: tl.Material, ServerNames: tlsServerNames(tc), HandshakeTimeout: tc.HandshakeTimeout,
		Seen: expiry.Seen, Said: said.said}
}

// hookTLSReload wires the reloader to the TLS listener: its files are
// re-read at SIGHUP (decision 50 ruling 15), and its list of devices the
// rule cannot identify follows each swap of the policy or the inventory,
// which can change who is admitted. A swap that changes how many devices
// have a transport this port49d does not serve says so (ruling 4). tl is
// nil with no tls_listener.
func hookTLSReload(r *reloader, tl *tlsListener, cfg config.Config, live *policy.Live) {
	if tl != nil {
		r.onHUP = func() { tl.reload("SIGHUP") }
		// Before the swap, so no connection is admitted under a clash the
		// new inventory creates; after it, the exact flags of the new set.
		r.beforeSwap = func(pol *policy.Policy) { tl.swapping(policyDevices(pol)) }
	}
	lastUnserved := unservedOf(cfg, live)
	r.onSwap = func(*policy.Policy) {
		if tl != nil {
			tl.inventoryChanged("inventory")
		}
		if u := unservedOf(cfg, live); u != lastUnserved {
			lastUnserved = u
			announceTransports(stderr, cfg, live, nil, nil, nil)
		}
	}
}
