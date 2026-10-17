package port49d

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rhwendt/port49/internal/config"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// storeRolesCmd is `port49d store-roles [--config FILE] [--broker-config
// FILE]` (spec §12; plans 7d, 7e): it prints the etcdctl commands that
// create port49's two roles for the etcd prefix of stores: and a user per
// component named by its certificate's CN, the daemon's from port49d.yaml and
// the broker's from port49-broker.yaml (Ruling 14). It holds no etcd
// credential and changes nothing; etcd's root runs the output, once.
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
	dst, err := storeBlocksOf(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49d store-roles:", err)
		return 1
	}
	dsc, dat := dst.Directory, dst.SessionPath()+".etcd"
	if dsc.Etcd == nil {
		fmt.Fprintf(stderr, "port49d store-roles: %s.backend is not etcd; there are no roles to make\n", dst.SessionPath())
		return 1
	}
	if dsc.Etcd.Daemon == (config.EtcdIdentity{}) {
		fmt.Fprintf(stderr, "port49d store-roles: %s names no %s.daemon: it is port49d.yaml's\n", *cfgPath, dat)
		return 1
	}
	// A 7d port49d.yaml names both identities, and is read whole when no
	// --broker-config says otherwise (Ruling 1; config.Load would refuse
	// it, and store-roles never calls Load).
	broker := dsc.Etcd.Broker
	if dsc.Etcd.Broker != nil && !brokerGiven {
		fmt.Fprintf(stderr, "port49d store-roles: %s names %s.broker, a 7d layout: move the broker's "+
			"identity to port49-broker.yaml and pass it with --broker-config\n", *cfgPath, dat)
	} else {
		if dsc.Etcd.Broker != nil {
			stale, _ := commonName(dsc.Etcd.Broker.CertFile)
			fmt.Fprintf(stderr, "port49d store-roles: %s still names %s.broker (CN %q); the broker's identity "+
				"is read from %s; remove it from port49d.yaml, which port49d refuses at start\n", *cfgPath, dat, stale, *brokerPath)
		}
		bst, err := storeBlocksOf(*brokerPath)
		if err != nil {
			fmt.Fprintf(stderr, "port49d store-roles: the broker's identity is read from port49-broker.yaml, "+
				"named by --broker-config: %v\n", err)
			return 1
		}
		bsc, bat := bst.Directory, bst.SessionPath()+".etcd"
		if bsc.Etcd == nil || bsc.Etcd.Broker == nil {
			fmt.Fprintf(stderr, "port49d store-roles: %s names no %s.broker; --broker-config is "+
				"port49-broker.yaml's\n", *brokerPath, bat)
			return 1
		}
		if bsc.Etcd.Prefix != dsc.Etcd.Prefix {
			fmt.Fprintf(stderr, "port49d store-roles: the two files name different keyspaces: the etcd prefix "+
				"is %q in %s and %q in %s\n", dsc.Etcd.Prefix, *cfgPath, bsc.Etcd.Prefix, *brokerPath)
			return 1
		}
		broker = bsc.Etcd.Broker
	}
	users := map[string]string{}
	for _, id := range []struct{ role, path string }{
		{etcdstore.RoleDaemon, dsc.Etcd.Daemon.CertFile},
		{etcdstore.RoleBroker, broker.CertFile},
	} {
		cn, err := commonName(id.path)
		if err != nil {
			fmt.Fprintf(stderr, "port49d store-roles: %s: %v\n", id.path, err)
			return 1
		}
		users[id.role] = cn
	}
	if users[etcdstore.RoleDaemon] == users[etcdstore.RoleBroker] {
		fmt.Fprintf(stderr, "port49d store-roles: %s.daemon and %s.broker are both CN %q: each "+
			"component needs its own certificate (decision 35)\n", dat, dat, users[etcdstore.RoleDaemon])
		return 1
	}
	// The output is run by etcd's root in a shell: a name that holds
	// anything a shell reads is refused, never quoted into it (pre-flight
	// M34).
	names := []struct{ what, v string }{
		{"the daemon certificate's CN", users[etcdstore.RoleDaemon]},
		{"the broker certificate's CN", users[etcdstore.RoleBroker]},
		{dat + ".prefix", dsc.Etcd.Prefix},
	}
	for _, n := range names {
		if !shellSafe(n.v) {
			fmt.Fprintf(stderr, "port49d store-roles: %s %q holds a character outside [A-Za-z0-9._@/-]; "+
				"nothing printed\n", n.what, n.v)
			return 1
		}
	}
	fmt.Fprintf(stdout, "# port49 roles for keyspace %s (plan 7e). Run as etcd's root user, once.\n", dsc.Etcd.Prefix)
	// What the daemon's role is worth, no more than spec §12 says.
	fmt.Fprintln(stdout, "# port49_daemon cannot write a revocation mark, so it cannot lift a revocation by")
	fmt.Fprintln(stdout, "# principal or certificate. The daemon's credential cannot write a mark, meta/, the")
	fmt.Fprintln(stdout, "# ledger record or the superseded record; port49d holds it alone (plan 7e). Under")
	fmt.Fprintf(stdout, "# %s.roles: unenforced the daemon's is as wide as the broker's.\n", dat)
	// etcdctl role add fails on a role that exists and leaves its grants;
	// a grant on another range than these is added to the role, not
	// replaced (task 11 review M3). port49d's start check refuses a daemon
	// role that reaches further.
	fmt.Fprintln(stdout, "# if a role already exists, check it with etcdctl role get first: a grant on a range")
	fmt.Fprintln(stdout, "# not printed here stays in force.")
	made := map[string]bool{}
	for _, g := range etcdstore.Roles(dsc.Etcd.Prefix) {
		if !made[g.Role] {
			fmt.Fprintf(stdout, "etcdctl role add %s\n", g.Role)
			made[g.Role] = true
		}
		perm := "read"
		if g.Write {
			perm = "readwrite"
		}
		if g.RangeEnd == "" { // one key: no --prefix, or etcd would grant everything under it
			fmt.Fprintf(stdout, "etcdctl role grant-permission %s %s %s\n", g.Role, perm, g.Key)
			continue
		}
		fmt.Fprintf(stdout, "etcdctl role grant-permission %s %s --prefix=true %s\n", g.Role, perm, g.Key)
	}
	for _, role := range []string{etcdstore.RoleDaemon, etcdstore.RoleBroker} {
		fmt.Fprintf(stdout, "etcdctl user add %s --no-password\n", users[role])
		fmt.Fprintf(stdout, "etcdctl user grant-role %s %s\n", users[role], role)
	}
	fmt.Fprintln(stdout, "# then, if auth is not enabled yet: etcdctl user add root --no-password &&")
	fmt.Fprintln(stdout, "#   etcdctl user grant-role root root && etcdctl auth enable")
	return 0
}

// storeBlocksOf reads the stores: block of the file at path, checked for its
// shape alone (config.StoresBlocks). A file whose stores are not one store is
// refused until the roles of two are printed (plan 11a, Task 11).
func storeBlocksOf(path string) (config.StoresConfig, error) {
	raw, err := config.ReadRegular(path, config.MaxConfigSize)
	if err != nil {
		return config.StoresConfig{}, err
	}
	s, err := config.StoresBlocks(raw)
	if err != nil {
		return config.StoresConfig{}, err
	}
	if !s.Shared {
		return config.StoresConfig{}, errors.New("stores.session names a store of its own; this build prints one store's roles")
	}
	return s, nil
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
