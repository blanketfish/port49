package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rhwendt/port49/internal/config"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// storeRolesCmd is `port49d store-roles [--config FILE]` (spec §12; plan
// 7d): it prints the etcdctl commands that create port49's two roles for
// store.etcd.prefix and a user per component named by its certificate's
// CN. It holds no etcd credential and changes nothing; etcd's root runs
// the output, once.
func storeRolesCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("store-roles", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: port49d store-roles [--config FILE]")
		return 2
	}
	raw, err := config.ReadRegular(*cfgPath, config.MaxConfigSize)
	if err != nil {
		fmt.Fprintln(stderr, "port49d store-roles:", err)
		return 1
	}
	sc, err := config.StoreOf(raw)
	if err != nil {
		fmt.Fprintln(stderr, "port49d store-roles:", err)
		return 1
	}
	if sc.Etcd == nil {
		fmt.Fprintln(stderr, "port49d store-roles: store.backend is not etcd; there are no roles to make")
		return 1
	}
	users := map[string]string{}
	for role, path := range map[string]string{etcdstore.RoleDaemon: sc.Etcd.Daemon.CertFile,
		etcdstore.RoleBroker: sc.Etcd.Broker.CertFile} {
		cn, err := commonName(path)
		if err != nil {
			fmt.Fprintf(stderr, "port49d store-roles: %s: %v\n", path, err)
			return 1
		}
		users[role] = cn
	}
	if users[etcdstore.RoleDaemon] == users[etcdstore.RoleBroker] {
		fmt.Fprintf(stderr, "port49d store-roles: store.etcd.daemon and store.etcd.broker are both CN %q: each "+
			"component needs its own certificate (decision 35)\n", users[etcdstore.RoleDaemon])
		return 1
	}
	// The output is run by etcd's root in a shell: a name that holds
	// anything a shell reads is refused, never quoted into it (pre-flight
	// M34).
	for _, n := range []struct{ what, v string }{
		{"the daemon certificate's CN", users[etcdstore.RoleDaemon]},
		{"the broker certificate's CN", users[etcdstore.RoleBroker]},
		{"store.etcd.prefix", sc.Etcd.Prefix},
	} {
		if !shellSafe(n.v) {
			fmt.Fprintf(stderr, "port49d store-roles: %s %q holds a character outside [A-Za-z0-9._@/-]; "+
				"nothing printed\n", n.what, n.v)
			return 1
		}
	}
	fmt.Fprintf(stdout, "# port49 roles for keyspace %s (plan 7d). Run as etcd's root user, once.\n", sc.Etcd.Prefix)
	// What the daemon's role is worth, no more than spec §12 says.
	fmt.Fprintln(stdout, "# port49_daemon cannot write a revocation mark, so it cannot lift a revocation by")
	fmt.Fprintln(stdout, "# principal or certificate. That holds for the daemon's credential taken alone:")
	fmt.Fprintln(stdout, "# until plan 7e port49d also holds the broker's, whose role is the whole keyspace,")
	fmt.Fprintln(stdout, "# marks included, and under store.etcd.roles: unenforced the daemon's is too.")
	made := map[string]bool{}
	for _, g := range etcdstore.Roles(sc.Etcd.Prefix) {
		if !made[g.Role] {
			fmt.Fprintf(stdout, "etcdctl role add %s\n", g.Role)
			made[g.Role] = true
		}
		perm := "read"
		if g.Write {
			perm = "readwrite"
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
