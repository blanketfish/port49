package port49d

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blanketfish/port49/internal/config"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// storeRolesCmd is `port49d store-roles [--config FILE] [--broker-config
// FILE]` (spec §12; plans 7d, 7e, 11a): it prints the etcdctl commands that
// create port49's two roles for each store's keyspace, and a user per
// component named by its certificate's CN: the daemon's from port49d.yaml,
// the broker's from port49-broker.yaml (or from port49d.yaml when it names
// one and --broker-config is not given). One store prints one section; a
// session store of its own prints a section per store, each to run as that
// cluster's root (R23). It holds no etcd credential and changes nothing.
func storeRolesCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("store-roles", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	brokerPath := fs.String("broker-config", "/etc/port49/port49-broker.yaml", "path to port49-broker.yaml")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: port49d store-roles [--config FILE] [--broker-config FILE]")
		return 2
	}
	brokerGiven := false
	fs.Visit(func(f *flag.Flag) { brokerGiven = brokerGiven || f.Name == "broker-config" })
	dsc, err := storesBlocksOf(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49d store-roles:", err)
		return 1
	}
	if dsc.Directory.Etcd == nil {
		fmt.Fprintln(stderr, "port49d store-roles: stores.directory.backend is not etcd; there are no roles to make")
		return 1
	}
	bsc, brokerFile := dsc, *cfgPath
	if brokerGiven || dsc.Directory.Etcd.Broker == nil {
		if bsc, err = storesBlocksOf(*brokerPath); err != nil {
			fmt.Fprintf(stderr, "port49d store-roles: the broker's identity is read from port49-broker.yaml, "+
				"named by --broker-config: %v\n", err)
			return 1
		}
		brokerFile = *brokerPath
	}
	if bsc.Shared != dsc.Shared {
		fmt.Fprintf(stderr, "port49d store-roles: %s and %s disagree on whether stores.session is a store of its "+
			"own\n", *cfgPath, brokerFile)
		return 1
	}
	secs := []rolesSection{{what: "stores.directory", scope: etcdstore.ScopeShared, d: dsc.Directory.Etcd,
		b: bsc.Directory.Etcd}}
	if !dsc.Shared {
		secs = []rolesSection{
			{what: "stores.directory", name: "directory", scope: etcdstore.ScopeDirectory, d: dsc.Directory.Etcd,
				b: bsc.Directory.Etcd},
			{what: "stores.session", name: "session", scope: etcdstore.ScopeSession, d: dsc.Session.Etcd,
				b: bsc.Session.Etcd},
		}
	}
	// Every section is checked before anything is printed: a half-printed
	// script run by etcd's root is worse than none.
	for i := range secs {
		if err := secs[i].check(*cfgPath, brokerFile); err != nil {
			fmt.Fprintln(stderr, "port49d store-roles:", err)
			return 1
		}
	}
	for i, s := range secs {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		s.print(stdout)
	}
	return 0
}

// rolesSection is one store's roles: its config path, its name in a split
// ("" for one store), its scope, and the daemon's and the broker's blocks.
type rolesSection struct {
	what, name string
	scope      etcdstore.Scope
	d, b       *config.EtcdConfig
	users      map[string]string // role → CN, set by check
}

// check fills users and refuses what the output cannot carry: a missing
// identity, one CN for both, the two files at different keyspaces, and a
// name a shell would read.
func (s *rolesSection) check(cfgPath, brokerFile string) error {
	switch {
	case s.d == nil || s.d.Daemon == (config.EtcdIdentity{}):
		return fmt.Errorf("%s names no %s.etcd.daemon: it is port49d.yaml's", cfgPath, s.what)
	case s.b == nil || s.b.Broker == nil:
		return fmt.Errorf("%s names no %s.etcd.broker; --broker-config is port49-broker.yaml's", brokerFile, s.what)
	case s.d.Prefix != s.b.Prefix:
		return fmt.Errorf("the two files name different keyspaces: %s.etcd.prefix is %q in %s and %q in %s",
			s.what, s.d.Prefix, cfgPath, s.b.Prefix, brokerFile)
	}
	s.users = map[string]string{}
	for _, id := range []struct{ role, path string }{
		{etcdstore.RoleDaemon, s.d.Daemon.CertFile},
		{etcdstore.RoleBroker, s.b.Broker.CertFile},
	} {
		cn, err := commonName(id.path)
		if err != nil {
			return fmt.Errorf("%s: %v", id.path, err)
		}
		s.users[id.role] = cn
	}
	if s.users[etcdstore.RoleDaemon] == s.users[etcdstore.RoleBroker] {
		return fmt.Errorf("%s.etcd.daemon and %s.etcd.broker are both CN %q: each component needs its own "+
			"certificate (decision 35)", s.what, s.what, s.users[etcdstore.RoleDaemon])
	}
	// The output is run by etcd's root in a shell: a name that holds
	// anything a shell reads is refused, never quoted into it (pre-flight
	// M34).
	for _, n := range []struct{ what, v string }{
		{"the daemon certificate's CN", s.users[etcdstore.RoleDaemon]},
		{"the broker certificate's CN", s.users[etcdstore.RoleBroker]},
		{s.what + ".etcd.prefix", s.d.Prefix},
	} {
		if !shellSafe(n.v) {
			return fmt.Errorf("%s %q holds a character outside [A-Za-z0-9._@/-]; nothing printed", n.what, n.v)
		}
	}
	// The endpoints go into a comment's ETCDCTL_ENDPOINTS=…: a URL's ":" and
	// the list's "," are theirs; anything else a shell reads is refused.
	for _, ep := range s.d.Endpoints {
		if !shellSafe(strings.ReplaceAll(ep, ":", "")) {
			return fmt.Errorf("%s.etcd.endpoints %q holds a character outside [A-Za-z0-9.:_@/-]; nothing printed",
				s.what, ep)
		}
	}
	return nil
}

// print writes the section: its header, the roles and their grants, the
// users, and the auth lines.
func (s rolesSection) print(w io.Writer) {
	if s.name == "" {
		fmt.Fprintf(w, "# port49 roles for keyspace %s (plan 7e). Run as etcd's root user, once.\n", s.d.Prefix)
		// What the daemon's role is worth, no more than spec §12 says.
		fmt.Fprintln(w, "# port49_daemon cannot write a revocation mark, so it cannot lift a revocation by")
		fmt.Fprintln(w, "# principal or certificate. The daemon's credential cannot write a mark, meta/, the")
		fmt.Fprintln(w, "# ledger record or the superseded record; port49d holds it alone (plan 7e). Under")
		fmt.Fprintln(w, "# stores.directory.etcd.roles: unenforced the daemon's is as wide as the broker's.")
	} else {
		fmt.Fprintf(w, "# port49 roles for the %s store (%s): keyspace %s. Run these as THAT cluster's root user,\n"+
			"# once (point etcdctl at it: ETCDCTL_ENDPOINTS=%s).\n", s.name, s.what, s.d.Prefix,
			strings.Join(s.d.Endpoints, ","))
		fmt.Fprintln(w, "# on one cluster the second section's role add lines fail with \"role already exists\"; that is expected.")
		if s.scope == etcdstore.ScopeDirectory {
			fmt.Fprintln(w, "# port49_daemon reads the revocation marks (rv/), meta/ping and meta/seal_keys alone and writes")
			fmt.Fprintln(w, "# nothing; port49_broker holds the keyspace.")
		} else {
			fmt.Fprintln(w, "# port49_daemon holds what a login, an authorization and accounting touch; the marks are the")
			fmt.Fprintln(w, "# directory store's, which it reads there.")
		}
	}
	// etcdctl role add fails on a role that exists and leaves its grants;
	// a grant on another range than these is added to the role, not
	// replaced (task 11 review M3). port49d's start check refuses a daemon
	// role that reaches further.
	fmt.Fprintln(w, "# if a role already exists, check it with etcdctl role get first: a grant on a range")
	fmt.Fprintln(w, "# not printed here stays in force.")
	made := map[string]bool{}
	for _, g := range etcdstore.RolesFor(s.d.Prefix, s.scope) {
		if !made[g.Role] {
			fmt.Fprintf(w, "etcdctl role add %s\n", g.Role)
			made[g.Role] = true
		}
		perm := "read"
		if g.Write {
			perm = "readwrite"
		}
		if g.RangeEnd == "" { // one key: no --prefix, or etcd would grant everything under it
			fmt.Fprintf(w, "etcdctl role grant-permission %s %s %s\n", g.Role, perm, g.Key)
			continue
		}
		fmt.Fprintf(w, "etcdctl role grant-permission %s %s --prefix=true %s\n", g.Role, perm, g.Key)
	}
	for _, role := range []string{etcdstore.RoleDaemon, etcdstore.RoleBroker} {
		fmt.Fprintf(w, "etcdctl user add %s --no-password\n", s.users[role])
		fmt.Fprintf(w, "etcdctl user grant-role %s %s\n", s.users[role], role)
	}
	fmt.Fprintln(w, "# then, if auth is not enabled yet: etcdctl user add root --no-password &&")
	fmt.Fprintln(w, "#   etcdctl user grant-role root root && etcdctl auth enable")
}

// storesBlocksOf reads the stores: block of the file at path, checked for
// its shape alone (config.StoresBlocks).
func storesBlocksOf(path string) (config.StoresConfig, error) {
	raw, err := config.ReadRegular(path, config.MaxConfigSize)
	if err != nil {
		return config.StoresConfig{}, err
	}
	return config.StoresBlocks(raw)
}

// shellSafe reports whether s is non-empty and every byte of it is one of
// [A-Za-z0-9._@/-], which a POSIX shell passes as one word unread.
func shellSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._@/-", r):
		default:
			return false
		}
	}
	return true
}

// commonName is the subject CN of the first certificate in a PEM file:
// the user etcd authenticates it as.
func commonName(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", err
	}
	if c.Subject.CommonName == "" {
		return "", fmt.Errorf("the certificate has no CN, which etcd needs as the user name")
	}
	return c.Subject.CommonName, nil
}
