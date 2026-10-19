package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// storesYAML mirrors the stores block (plan 11a; spec §13 decision 51).
type storesYAML struct {
	Directory *storeYAML `yaml:"directory"`
	Session   *storeYAML `yaml:"session"`
}

// StoresConfig is stores:, resolved (plan 11a; spec §13 decision 51).
// Directory holds the revocation marks, the second factors, the enrollment
// mark, the unlocks, the logout records and membership's pins (R11);
// Session holds every other record. Shared is a single
// site: stores.session omitted, or naming the directory's keyspace, so one
// store holds both and Session equals Directory.
type StoresConfig struct {
	Directory StoreConfig
	Session   StoreConfig
	Shared    bool
	// sessionNamed is whether stores.session was written: SessionPath's.
	sessionNamed bool
}

// SessionPath is the config path the session store's keys are written
// under: stores.session, or stores.directory when stores.session was
// omitted. A line naming a session-store key builds it from this.
func (s StoresConfig) SessionPath() string {
	if !s.sessionNamed {
		return "stores.directory"
	}
	return "stores.session"
}

// storeCheck resolves one store block: at is its path, and session is
// whether it serves sessions, which binds packet_deadline and
// health.interval to its call_timeout (ruling R22).
type storeCheck func(at string, s storeYAML, session bool) (StoreConfig, error)

// checkStores resolves stores: (ruling R22): the directory store, memory
// when absent; the session store, the directory's when absent or naming
// its keyspace. check resolves each block.
func checkStores(y storesYAML, check storeCheck) (StoresConfig, error) {
	var dirY storeYAML
	if y.Directory != nil {
		dirY = *y.Directory
	}
	if y.Session == nil {
		d, err := check("stores.directory", dirY, true)
		if err != nil {
			return StoresConfig{}, err
		}
		return StoresConfig{Directory: d, Session: d, Shared: true}, nil
	}
	if y.Directory == nil {
		return StoresConfig{}, errors.New("stores.directory is required: it holds the marks, the enrollments and " +
			"the logouts; for a single site, name the one store under stores.directory and omit stores.session")
	}
	only := sessionOnly(dirY) // read before check fills in the defaults
	sess, err := check("stores.session", *y.Session, true)
	if err != nil {
		return StoresConfig{}, err
	}
	dir, err := check("stores.directory", dirY, false)
	if err != nil {
		return StoresConfig{}, err
	}
	switch {
	case dir.Backend != sess.Backend:
		return StoresConfig{}, fmt.Errorf("stores.directory.backend %s and stores.session.backend %s: the two "+
			"stores are both memory (one process holds everything) or both etcd (port49-broker beside port49d)",
			dir.Backend, sess.Backend)
	case dir.Backend == BackendMemory:
		return StoresConfig{Directory: sess, Session: sess, Shared: true, sessionNamed: true}, nil
	}
	same, overlap := relate(dir.Etcd, sess.Etcd)
	switch {
	case same && only != "":
		return StoresConfig{}, fmt.Errorf("stores.directory.%s: stores.directory and stores.session name one "+
			"store (the same endpoints and prefix), and %s is the session store's key: set it under "+
			"stores.session alone", only, only)
	case same:
		if k := disagree(dir.Etcd, sess.Etcd); k != "" {
			return StoresConfig{}, fmt.Errorf("stores.directory and stores.session name one store (the same "+
				"endpoints and prefix) and set %s differently: omit stores.session for a single site, or give "+
				"both the same %s", k, k)
		}
		return StoresConfig{Directory: sess, Session: sess, Shared: true, sessionNamed: true}, nil
	case overlap:
		return StoresConfig{}, fmt.Errorf("stores.directory (prefix %s) and stores.session (prefix %s) share an "+
			"endpoint and one prefix holds the other: the broker's etcd role covers every key under its prefix, "+
			"so it would reach both; give each a prefix of its own, or name one store", dir.Etcd.Prefix,
			sess.Etcd.Prefix)
	case only != "":
		return StoresConfig{}, fmt.Errorf("stores.directory.%s: a session store's key; stores.session names a "+
			"store of its own, so set it under stores.session", only)
	}
	return StoresConfig{Directory: dir, Session: sess, sessionNamed: true}, nil
}

// sessionOnly names the first key y sets that a directory store of its
// own does not take (ruling R22), "" when none: what the session store's
// traffic, its hold and its go-dark need.
func sessionOnly(y storeYAML) string {
	switch {
	case y.PacketDeadline != 0:
		return "packet_deadline"
	case y.Etcd == nil:
		return ""
	case y.Etcd.HealthSet != nil:
		return "etcd.health"
	case y.Etcd.ContextCacheSet != nil:
		return "etcd.context_cache"
	case y.Etcd.HoldTTL != 0:
		return "etcd.hold_ttl"
	case y.Etcd.SweepInterval != 0:
		return "etcd.sweep_interval"
	case y.Etcd.LeaseGrace != 0:
		return "etcd.lease_grace"
	case y.Etcd.Breaker != (EtcdBreaker{}):
		return "etcd.breaker"
	case y.Etcd.MaxInFlight != (EtcdInFlight{}):
		return "etcd.max_in_flight"
	}
	return ""
}

// relate says whether two resolved etcd blocks name one keyspace (same:
// the same prefix, compared with one trailing "/", and the same endpoint
// hosts, compared case-insensitively) or reach into each other (overlap: a
// host in common and one prefix under the other).
func relate(a, b *EtcdConfig) (same, overlap bool) {
	ha, hb := hostsOf(a.Endpoints), hostsOf(b.Endpoints)
	common := false
	for h := range ha {
		common = common || hb[h]
	}
	pa, pb := slashed(a.Prefix), slashed(b.Prefix)
	nested := strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
	return common && pa == pb && maps.Equal(ha, hb), common && nested
}

func hostsOf(endpoints []string) map[string]bool {
	out := map[string]bool{}
	for _, ep := range endpoints {
		if u, err := url.Parse(ep); err == nil && u.Host != "" {
			out[strings.ToLower(u.Host)] = true
		}
	}
	return out
}

func slashed(p string) string {
	if strings.HasSuffix(p, "/") {
		return p
	}
	return p + "/"
}

// disagree names the first key, of those a directory takes, that two
// blocks naming one store set differently; "" when none does.
func disagree(d, s *EtcdConfig) string {
	brokerOf := func(e *EtcdConfig) EtcdIdentity {
		if e.Broker == nil {
			return EtcdIdentity{}
		}
		return *e.Broker
	}
	switch {
	case d.CAFile != s.CAFile:
		return "etcd.ca_file"
	case d.Daemon != s.Daemon:
		return "etcd.daemon"
	case brokerOf(d) != brokerOf(s):
		return "etcd.broker"
	case d.Roles != s.Roles:
		return "etcd.roles"
	case d.CallTimeout != s.CallTimeout:
		return "etcd.call_timeout"
	case d.BulkTimeout != s.BulkTimeout:
		return "etcd.bulk_timeout"
	case d.StartTimeout != s.StartTimeout:
		return "etcd.start_timeout"
	}
	return ""
}

// sessionBackend is the session store's backend as written: the session
// block's, else the directory block's, else memory.
func (y storesYAML) sessionBackend() string {
	switch {
	case y.Session != nil && y.Session.Backend != "":
		return y.Session.Backend
	case y.Directory != nil && y.Directory.Backend != "":
		return y.Directory.Backend
	}
	return BackendMemory
}

// StoresBlocks is stores: from either file's bytes, port49d.yaml's or
// port49-broker.yaml's, decoded as strictly as Load (the stale seed keys
// first, as Load refuses them) and checked for its shape alone: either
// identity may be named or absent (plan 7e, pre-flight I8). It is for
// `port49d store-roles`, which reads nothing else.
func StoresBlocks(raw []byte) (StoresConfig, error) {
	if err := staleSeedKeys(raw); err != nil {
		return StoresConfig{}, err
	}
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return StoresConfig{}, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema",
			decodeFault(err))
	}
	s, err := checkStores(f.Stores, checkStoreShape)
	if err != nil {
		return StoresConfig{}, fmt.Errorf("config: %w", err)
	}
	return s, nil
}
