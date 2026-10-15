package port49d

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/directory"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// storeRolesCmd is `port49d store-roles [--config FILE] [--broker-config
// FILE]` (spec §12; plans 7d, 7e): it prints the etcdctl commands that
// create port49's two roles for store.etcd.prefix and a user per component
// named by its certificate's CN, the daemon's from port49d.yaml and the
// broker's from port49-broker.yaml (Ruling 14). It holds no etcd credential
// and changes nothing; etcd's root runs the output, once. A broker file that
// names an enrollment store on an etcd of its own (plan 9e, D12) gets a second
// section for that cluster: the broker's role over that prefix, and a user
// for the certificate there.
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
	dsc, err := storeBlocksOf(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49d store-roles:", err)
		return 1
	}
	if dsc.Etcd == nil {
		fmt.Fprintln(stderr, "port49d store-roles: store.backend is not etcd; there are no roles to make")
		return 1
	}
	if dsc.Etcd.Daemon == (config.EtcdIdentity{}) {
		fmt.Fprintf(stderr, "port49d store-roles: %s names no store.etcd.daemon: it is port49d.yaml's\n", *cfgPath)
		return 1
	}
	// A 7d port49d.yaml names both identities, and is read whole when no
	// --broker-config says otherwise (Ruling 1; config.Load would refuse
	// it, and store-roles never calls Load).
	broker := dsc.Etcd.Broker
	brokerFile := *cfgPath // the file that names the broker's identity, and its enrollment store
	if dsc.Etcd.Broker != nil && !brokerGiven {
		fmt.Fprintf(stderr, "port49d store-roles: %s names store.etcd.broker, a 7d layout: move the broker's "+
			"identity to port49-broker.yaml and pass it with --broker-config\n", *cfgPath)
	} else {
		if dsc.Etcd.Broker != nil {
			stale, _ := commonName(dsc.Etcd.Broker.CertFile)
			fmt.Fprintf(stderr, "port49d store-roles: %s still names store.etcd.broker (CN %q); the broker's identity "+
				"is read from %s; remove it from port49d.yaml, which port49d refuses at start\n", *cfgPath, stale, *brokerPath)
		}
		bsc, err := storeBlocksOf(*brokerPath)
		if err != nil {
			fmt.Fprintf(stderr, "port49d store-roles: the broker's identity is read from port49-broker.yaml, "+
				"named by --broker-config: %v\n", err)
			return 1
		}
		if bsc.Etcd == nil || bsc.Etcd.Broker == nil {
			fmt.Fprintf(stderr, "port49d store-roles: %s names no store.etcd.broker; --broker-config is "+
				"port49-broker.yaml's\n", *brokerPath)
			return 1
		}
		if bsc.Etcd.Prefix != dsc.Etcd.Prefix {
			fmt.Fprintf(stderr, "port49d store-roles: the two files name different keyspaces: store.etcd.prefix "+
				"is %q in %s and %q in %s\n", dsc.Etcd.Prefix, *cfgPath, bsc.Etcd.Prefix, *brokerPath)
			return 1
		}
		broker = bsc.Etcd.Broker
		brokerFile = *brokerPath
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
		fmt.Fprintf(stderr, "port49d store-roles: store.etcd.daemon and store.etcd.broker are both CN %q: each "+
			"component needs its own certificate (decision 35)\n", users[etcdstore.RoleDaemon])
		return 1
	}
	// An enrollment store on an etcd of its own (plan 9e, D12) is another
	// cluster with another user for the broker's certificate there.
	enroll, enrollCN, err := enrollmentEtcdOf(brokerFile)
	if err != nil {
		fmt.Fprintf(stderr, "port49d store-roles: %v\n", err)
		return 1
	}
	// The output is run by etcd's root in a shell: a name that holds
	// anything a shell reads is refused, never quoted into it (pre-flight
	// M34).
	names := []struct{ what, v string }{
		{"the daemon certificate's CN", users[etcdstore.RoleDaemon]},
		{"the broker certificate's CN", users[etcdstore.RoleBroker]},
		{"store.etcd.prefix", dsc.Etcd.Prefix},
	}
	if enroll != nil {
		names = append(names, struct{ what, v string }{"the enrollment store's etcd certificate's CN", enrollCN},
			struct{ what, v string }{"broker.directory.enrollment_store.etcd.prefix", enroll.Prefix})
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
	fmt.Fprintln(stdout, "# store.etcd.roles: unenforced the daemon's is as wide as the broker's.")
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
	if enroll != nil {
		// Only the broker uses it: the broker's role over this keyspace alone,
		// on that cluster. Run against it, not the first.
		fmt.Fprintf(stdout, "\n# port49's enrollment store has an etcd of its own (broker.directory.enrollment_store.etcd,\n"+
			"# endpoints %s, keyspace %s). Run these as THAT cluster's root user, once (point etcdctl\n"+
			"# at it, e.g. ETCDCTL_ENDPOINTS), not on the cluster above.\n", strings.Join(enroll.Endpoints, ","), enroll.Prefix)
		fmt.Fprintf(stdout, "etcdctl role add %s\n", etcdstore.RoleBroker)
		fmt.Fprintf(stdout, "etcdctl role grant-permission %s readwrite --prefix=true %s\n", etcdstore.RoleBroker, enroll.Prefix)
		fmt.Fprintf(stdout, "etcdctl user add %s --no-password\n", enrollCN)
		fmt.Fprintf(stdout, "etcdctl user grant-role %s %s\n", enrollCN, etcdstore.RoleBroker)
		fmt.Fprintln(stdout, "# then, if auth is not enabled there yet: etcdctl user add root --no-password &&")
		fmt.Fprintln(stdout, "#   etcdctl user grant-role root root && etcdctl auth enable")
	}
	return 0
}

// enrollmentEtcdOf is the own etcd of the enrollment store the file at path
// names, and its certificate's CN; nil when it names none.
func enrollmentEtcdOf(path string) (*directory.EnrollmentEtcd, string, error) {
	raw, err := config.ReadRegular(path, config.MaxConfigSize)
	if err != nil {
		return nil, "", err
	}
	e, err := config.EnrollmentEtcdOf(raw)
	if err != nil || e == nil {
		return nil, "", err
	}
	cn, err := commonName(e.CertFile)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", e.CertFile, err)
	}
	return e, cn, nil
}

// storeBlocksOf reads the store: block of the file at path, checked for its
// shape alone (config.StoreBlocks).
func storeBlocksOf(path string) (config.StoreConfig, error) {
	raw, err := config.ReadRegular(path, config.MaxConfigSize)
	if err != nil {
		return config.StoreConfig{}, err
	}
	return config.StoreBlocks(raw)
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
