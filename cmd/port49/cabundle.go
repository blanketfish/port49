package main

import (
	"cmp"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/userconfig"
)

// keepCABundle keeps the CA bundle the broker sent on the connection the
// agent verified, in ~/.port49/broker_ca/<host>_<port>.pem, 0600, for the
// next login to trust beside its broker_ca (spec §13 decision 43 ruling 25).
// So a rotation of the broker's CA asks nothing of the user. A bundle out of
// bounds, or one that drops the CA this connection was verified to, is
// refused and the file left as it was; a change is logged by fingerprint.
// A broker that sends no bundle clears what was kept (forgetBundle), so a
// CA planted by whoever held the broker's key once is gone at the real
// broker's next answer; one that refused its own bundle at start (refused)
// leaves the kept file as it was, since it sends none by fault, not by
// choice. Nothing here ends the session.
func keepCABundle(broker, bundle string, refused bool, root *x509.Certificate, log io.Writer) {
	path, err := userconfig.CABundlePath(broker)
	if err != nil {
		fmt.Fprintf(log, "port49 agent: the broker's CA bundle is not kept: %v\n", err)
		return
	}
	if refused {
		fmt.Fprintf(log, "port49 agent: the broker refused its own tls_ca_bundle_file at start (its log says why), "+
			"so it sends no CA bundle; %s is left as it was\n", path)
		return
	}
	if bundle == "" {
		forgetBundle(path, root, log)
		return
	}
	certs, err := api.ParseCABundle([]byte(bundle))
	if err == nil && (root == nil || !slices.ContainsFunc(certs, root.Equal)) {
		err = errors.New("it does not hold the CA this connection was verified to")
	}
	if err != nil {
		fmt.Fprintf(log, "port49 agent: the broker's CA bundle is refused: %v; %s is left as it was\n", err, path)
		return
	}
	was := "none"
	old, err := userconfig.ReadPrivate(path, api.MaxCABundleBytes, "broker CA bundle")
	if err == nil {
		var held []*x509.Certificate
		if held, err = api.ParseCABundle(old); err == nil {
			if slices.EqualFunc(held, certs, (*x509.Certificate).Equal) {
				return
			}
			was = api.CAFingerprints(held)
		}
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		was = "unreadable; replaced"
	}
	if err := userconfig.WritePrivate(path, api.EncodeCABundle(certs), "broker CA bundle"); err != nil {
		fmt.Fprintf(log, "port49 agent: the broker's CA bundle is not kept: %v\n", err)
		return
	}
	fmt.Fprintf(log, "port49 agent: kept the broker's CA bundle in %s: %s (was %s)\n", path, api.CAFingerprints(certs), was)
}

// forgetBundle clears the bundle kept at path when the broker, on a verified
// connection, sends none (decision 43 ruling 25). A kept file that does not
// hold the CA this connection was verified to is not needed for it, and is
// removed; one that does is cut to that CA alone, so the next login still
// verifies the broker while any other CA it held is dropped.
func forgetBundle(path string, root *x509.Certificate, log io.Writer) {
	old, err := userconfig.ReadPrivate(path, api.MaxCABundleBytes, "broker CA bundle")
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	held, perr := api.ParseCABundle(old)
	if err == nil && perr != nil {
		err = perr
	}
	if err != nil || root == nil {
		fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle, and %s is left as it was: %v\n", path,
			cmp.Or(err, errors.New("no CA was verified")))
		return
	}
	if !slices.ContainsFunc(held, root.Equal) {
		if err := os.Remove(path); err != nil {
			fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle, and %s is not removed: %v\n", path, err)
			return
		}
		fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle; removed %s (it held %s)\n", path,
			api.CAFingerprints(held))
		return
	}
	if len(held) == 1 {
		return
	}
	only := []*x509.Certificate{root}
	if err := userconfig.WritePrivate(path, api.EncodeCABundle(only), "broker CA bundle"); err != nil {
		fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle, and %s is not changed: %v\n", path, err)
		return
	}
	fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle; %s now holds only the CA this connection was "+
		"verified to: %s (was %s)\n", path, api.CAFingerprints(only), api.CAFingerprints(held))
}

// withKeptBundle is caPEM and the bundle the agent kept for broker, which a
// login trusts together (decision 43 ruling 25). A kept file that cannot be
// used is refused, naming it: it is the agent's to rewrite, and deleting it
// loses nothing but what the broker sends again.
func withKeptBundle(broker string, caPEM []byte) ([]byte, error) {
	if broker == "" {
		return caPEM, nil
	}
	path, err := userconfig.CABundlePath(broker)
	if err != nil {
		return caPEM, nil // the broker URL is refused where it is used
	}
	raw, err := userconfig.ReadPrivate(path, api.MaxCABundleBytes, "broker CA bundle")
	if errors.Is(err, fs.ErrNotExist) {
		return caPEM, nil
	}
	if err == nil {
		_, err = api.ParseCABundle(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("%s, the broker's CA bundle the agent kept: %w; remove it, and the next agent keeps "+
			"the broker's again", path, err)
	}
	return append(append(slices.Clip(caPEM), '\n'), raw...), nil
}
