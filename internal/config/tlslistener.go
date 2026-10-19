package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ListenNone is listen's value that turns the RFC 8907 listener off (spec
// §13 decision 50 ruling 1; RFC 9887 §5.2).
const ListenNone = "none"

// TLSListenerConfig is tls_listener: (spec §13 decision 50): TACACS+ over
// TLS 1.3 with mutual certificates (RFC 9887), on a listener of its own.
type TLSListenerConfig struct {
	Listen string `yaml:"listen"` // default ":300"
	// CertFile is the server certificate chain, PEM, leaf first; KeyFile its
	// key. Both re-read every ReloadInterval and at SIGHUP (ruling 15).
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ClientCAFile is the device CA certificates, PEM: the anchors a device
	// certificate must chain to. IntermediatesFile, optional, is issuing CAs
	// held here so a device that sends only its leaf verifies (RFC 9887
	// §3.4.1).
	ClientCAFile      string               `yaml:"client_ca_file"`
	IntermediatesFile string               `yaml:"intermediates_file"`
	DeviceIdentity    DeviceIdentityConfig `yaml:"device_identity"`
	// ServerNames, when set, are the SNI names a ClientHello may ask for
	// (ruling 10). Lower-cased at load.
	ServerNames           []string      `yaml:"server_names"`
	HandshakeTimeout      time.Duration `yaml:"handshake_timeout"`       // default 10s; 1s to 30s
	SessionTicketLifetime time.Duration `yaml:"session_ticket_lifetime"` // default 0s (off); up to 1h
	// ExpiryWarningFraction is expiry_warning_fraction (ruling 16): a device
	// certificate with less than this fraction of its own lifetime left is
	// named once a day. Read through tlsListenerYAML so an absent key (0.33,
	// the last third, past where ACME and cert-manager renew) is told from 0
	// (off).
	ExpiryWarningFraction float64       `yaml:"-"`
	ReloadInterval        time.Duration `yaml:"reload_interval"` // default 1m; 10s to 1h
	// StateDir keeps certificate_status's verified CRLs across a restart, in
	// its subdirectory tls_listener/ (TLSListenerStateDir), crl-<name>.der;
	// required with crls.
	StateDir          string                   `yaml:"state_dir"`
	CertificateStatus *CertificateStatusConfig `yaml:"certificate_status"`
}

// DeviceIdentityConfig is tls_listener.device_identity (ruling 6).
type DeviceIdentityConfig struct {
	Match       []string `yaml:"match"`        // dns_name, ip_address; default both
	DNSSuffixes []string `yaml:"dns_suffixes"` // lower-cased, dots trimmed at load
}

// tlsListenerYAML tells an absent expiry_warning_fraction (the default)
// from an explicit 0 (off).
type tlsListenerYAML struct {
	TLSListenerConfig        `yaml:",inline"`
	ExpiryWarningFractionSet *float64 `yaml:"expiry_warning_fraction"`
}

// TLSListenerStateDir is where the RFC 9887 listener's checker keeps its
// lists: a subdirectory of state_dir of its own, so it never writes the
// crl-<name>.der an in-process broker's checker keeps under the same name,
// even when both name one directory (decision 50 ruling 8).
func TLSListenerStateDir(t *TLSListenerConfig) string {
	if t.StateDir == "" {
		return ""
	}
	return filepath.Join(t.StateDir, "tls_listener")
}

// namedPath is a config key and the file it names, for the kept-list
// collision check.
type namedPath struct{ key, path string }

// checkTLSListener checks tls_listener: and applies its defaults. listen is
// the resolved RFC 8907 listen ("" is none).
func checkTLSListener(y *tlsListenerYAML, listen string) (*TLSListenerConfig, error) {
	t := y.TLSListenerConfig
	const key = "tls_listener"
	t.Listen = or(t.Listen, ":300")
	if listen != "" && sameBind(listen, t.Listen) {
		return nil, fmt.Errorf("config: %s.listen %s is the same address as listen %s; RFC 9887 §3.1 requires its "+
			"own port", key, t.Listen, listen)
	}
	for _, f := range []struct{ name, path string }{{"cert_file", t.CertFile}, {"key_file", t.KeyFile},
		{"client_ca_file", t.ClientCAFile}} {
		if f.path == "" {
			return nil, fmt.Errorf("config: %s.%s is required", key, f.name)
		}
	}
	for _, f := range []struct{ name, path string }{{"cert_file", t.CertFile}, {"key_file", t.KeyFile},
		{"client_ca_file", t.ClientCAFile}, {"intermediates_file", t.IntermediatesFile}} {
		if f.path == "" {
			continue
		}
		if err := readableFile(key+"."+f.name, f.path); err != nil {
			return nil, err
		}
	}
	id := &t.DeviceIdentity
	if id.Match == nil {
		id.Match = []string{"dns_name", "ip_address"}
	}
	if len(id.Match) == 0 {
		return nil, fmt.Errorf("config: %s.device_identity.match must list dns_name or ip_address, or both", key)
	}
	for i, m := range id.Match {
		if (m != "dns_name" && m != "ip_address") || slices.Index(id.Match, m) != i {
			return nil, fmt.Errorf("config: %s.device_identity.match lists each of dns_name or ip_address at "+
				"most once; got %q", key, m)
		}
	}
	if len(id.DNSSuffixes) > 0 && !slices.Contains(id.Match, "dns_name") {
		return nil, fmt.Errorf("config: %s.device_identity.dns_suffixes needs dns_name in match", key)
	}
	for i, s := range id.DNSSuffixes {
		s = strings.ToLower(strings.Trim(s, "."))
		if !dnsShape(s) {
			return nil, fmt.Errorf("config: %s.device_identity.dns_suffixes[%d] is not a DNS suffix (letters, "+
				"digits, - and ., no wildcard)", key, i)
		}
		id.DNSSuffixes[i] = s
	}
	for i, n := range t.ServerNames {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !dnsShape(n) {
			return nil, fmt.Errorf("config: %s.server_names[%d] is not a server name (letters, digits, - and ., "+
				"no wildcard)", key, i)
		}
		t.ServerNames[i] = n
	}
	t.HandshakeTimeout = orD(t.HandshakeTimeout, 10*time.Second)
	if t.HandshakeTimeout < time.Second || t.HandshakeTimeout > 30*time.Second {
		return nil, fmt.Errorf("config: %s.handshake_timeout must be between 1s and 30s; got %s", key, t.HandshakeTimeout)
	}
	if t.SessionTicketLifetime < 0 || t.SessionTicketLifetime > time.Hour {
		return nil, fmt.Errorf("config: %s.session_ticket_lifetime must be between 0s and 1h; got %s", key,
			t.SessionTicketLifetime)
	}
	t.ExpiryWarningFraction = 0.33
	if y.ExpiryWarningFractionSet != nil {
		t.ExpiryWarningFraction = *y.ExpiryWarningFractionSet
	}
	if !(t.ExpiryWarningFraction >= 0 && t.ExpiryWarningFraction < 1) { // NaN fails both
		return nil, fmt.Errorf("config: %s.expiry_warning_fraction must be at least 0 and below 1 (0 is off; "+
			"0.33 warns in a certificate's last third); got %g", key, t.ExpiryWarningFraction)
	}
	t.ReloadInterval = orD(t.ReloadInterval, time.Minute)
	if t.ReloadInterval < 10*time.Second || t.ReloadInterval > time.Hour {
		return nil, fmt.Errorf("config: %s.reload_interval must be between 10s and 1h; got %s", key, t.ReloadInterval)
	}
	if t.CertificateStatus == nil {
		return nil, fmt.Errorf("config: %s.certificate_status is required (RFC 9887 §3.4 requires revocation "+
			"checking): name crls or an ocsp block, or set disabled: true", key)
	}
	if len(t.CertificateStatus.CRLs) > 0 {
		if t.StateDir == "" {
			return nil, fmt.Errorf("config: %s.state_dir is required with certificate_status.crls, an absolute "+
				"directory: each verified list is kept there across a restart", key)
		}
		if !filepath.IsAbs(t.StateDir) {
			return nil, fmt.Errorf("config: %s.state_dir must be absolute, so the lists are kept in one place "+
				"whatever the working directory", key)
		}
	}
	others := []namedPath{{key + ".cert_file", t.CertFile}, {key + ".key_file", t.KeyFile},
		{key + ".client_ca_file", t.ClientCAFile}, {key + ".intermediates_file", t.IntermediatesFile}}
	if err := checkStatusBlock(t.CertificateStatus, key+".certificate_status", TLSListenerStateDir(&t),
		others); err != nil {
		return nil, err
	}
	return &t, nil
}

// sameBind reports whether two listen addresses would bind the same socket:
// one port, and one host or either a wildcard. Port 0 never conflicts.
func sameBind(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || ap != bp || ap == "0" {
		return false
	}
	wild := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ah == bh || wild(ah) || wild(bh)
}

// dnsShape is letters, digits, - and ., between 1 and 253 bytes, no empty
// label and no wildcard.
func dnsShape(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

var errNoListener = errors.New("config: port49d serves no TACACS+ listener: listen is none and there is no " +
	"tls_listener; set one or both")
