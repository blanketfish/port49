package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/store/crypt"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// directoryKeysRecheckEvery is how often a runner on a directory of its own
// reads the directory's key window again (R27); a variable so a test can
// shorten it.
var directoryKeysRecheckEvery = time.Hour

// checkDirectoryKeys is the start's key check on a directory store of its
// own (plan 11a, R27). Every region holds one encryption key set: a window
// that does not hold the current key the directory's meta/seal_keys names
// cannot open what the last broker to start there seals, and the start is
// refused (a *storeFault), naming the store and the key id, never key
// material. A record that does not decode is said; with write
// (port49-broker), it, or no record, is written over with this window, as
// every broker start writes its own. Only an outage is returned besides.
func checkDirectoryKeys(ctx context.Context, proc string, d *etcdstore.Store, ref storeRef, keys crypt.Keys,
	out io.Writer, bound time.Duration, write bool) error {
	rctx, cancel := context.WithTimeout(ctx, bound)
	last, ok, err := d.SealKeys(rctx)
	cancel()
	undecodable := errors.Is(err, etcdstore.ErrSealKeysUndecodable)
	if err != nil && !undecodable {
		return fmt.Errorf("directory store: reading its key window: %w", err)
	}
	if ok && (last.Current == "" || crypt.LineKeyID(last.Current) == "?") {
		undecodable, ok = true, false // a record that names no key id is as good as unreadable
	}
	held := keys.Current.ID == last.Current || keys.Previous != nil && keys.Previous.ID == last.Current
	if ok && !held {
		id := crypt.LineKeyID(last.Current)
		return &storeFault{fmt.Errorf("crypt: the directory store (%s) was last written by a process whose "+
			"current key is %q, which this configuration does not hold (%s); every region holds the same "+
			"encryption keys (decision 51): set encryption.previous to %q and start %s again",
			ref.where(), id, keyWindow(keys), id, proc)}
	}
	if undecodable {
		if write {
			fmt.Fprintf(out, "%s: crypt: the directory store's key window (%s) does not name a readable key id; "+
				"rewritten with this process's window\n", proc, ref.recordKey())
		} else {
			fmt.Fprintf(out, "%s: crypt: the directory store's key window (%s) does not name a readable key id; "+
				"every region holds the same encryption keys, and this start cannot check that it does\n",
				proc, ref.recordKey())
		}
	}
	if !write {
		return nil
	}
	cur := etcdstore.SealKeys{Current: keys.Current.ID, WrittenAt: time.Now().UTC()}
	if keys.Previous != nil {
		cur.Previous = keys.Previous.ID
	}
	pctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	return d.PutSealKeys(pctx, cur)
}

// checkTwoStores refuses a split whose two blocks are one keyspace named two
// ways (an IP and a DNS name), which the config's text compare (R22) cannot
// see (plan 11a, R28). It reads each cluster's id; ids that differ, or
// prefixes that are neither equal nor one holding the other, end it. An id
// is not proof of one cluster (etcd derives it from the peer URLs and the
// token, so two default single-node clusters share one), so a match is
// probed (sameCluster): the directory handle grants a short lease and the
// session handle looks it up; the split is refused only when it finds it,
// and the lease is revoked after. A probe that cannot complete refuses the
// start, naming the handle and a closed-set cause.
func checkTwoStores(ctx context.Context, cfg config.Config, sess, dir *etcdstore.Store, bound time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	a, err := sess.ClusterID(cctx)
	if err != nil {
		return fmt.Errorf("session store: reading its cluster id: %w", err)
	}
	b, err := dir.ClusterID(cctx)
	if err != nil {
		return fmt.Errorf("directory store: reading its cluster id: %w", err)
	}
	sp := strings.TrimSuffix(cfg.Stores.Session.Etcd.Prefix, "/") + "/"
	dp := strings.TrimSuffix(cfg.Stores.Directory.Etcd.Prefix, "/") + "/"
	if a != b || !strings.HasPrefix(sp, dp) && !strings.HasPrefix(dp, sp) {
		return nil
	}
	same, err := sameCluster(cctx, ctx, sess, dir, bound)
	if err != nil {
		return &storeFault{fmt.Errorf("stores.directory and stores.session reach etcd clusters with one id (%x) "+
			"and related prefixes, and the check that they are two keyspaces failed: %v; not starting", a, err)}
	}
	if !same {
		return nil // two clusters that share an id: two keyspaces
	}
	return &storeFault{fmt.Errorf("stores.directory (prefix %s) and stores.session (prefix %s) reach one etcd "+
		"cluster (id %x), and one prefix holds the other: they are one keyspace named two ways; omit "+
		"stores.session for a single site, or give the directory a cluster of its own",
		cfg.Stores.Directory.Etcd.Prefix, cfg.Stores.Session.Etcd.Prefix, a)}
}

// sameCluster tells whether two store handles reach one etcd cluster, which
// a matching cluster id does not: etcd derives the id from the peer URLs and
// the token, so separate clusters can share it. The directory handle grants a
// short lease and the session handle asks after it; only one cluster knows
// it. etcd checks no role for a lease call, so any identity can ask. A call
// that cannot complete is an error naming the handle and a closed-set cause.
func sameCluster(cctx, ctx context.Context, sess, dir *etcdstore.Store, bound time.Duration) (bool, error) {
	id, ttl, err := dir.ProbeLeaseGrant(cctx)
	if err != nil {
		return false, fmt.Errorf("the directory store could not grant its probe lease (%s)", outageCause(err))
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bound)
		defer cancel()
		dir.ProbeLeaseRevoke(rctx, id)
	}()
	seen, err := sess.ProbeLeaseSeen(cctx, id, ttl)
	if err != nil {
		return false, fmt.Errorf("the session store could not look up the probe lease (%s)", outageCause(err))
	}
	return seen, nil
}

// recheckDirectoryKeys reads the directory's key window every
// directoryKeysRecheckEvery while the runner runs, and says a window this
// process does not hold, once per change of the record (R27: a region that
// rotated out of order). It never writes.
func (r *runner) recheckDirectoryKeys(ctx context.Context) {
	t := time.NewTicker(directoryKeysRecheckEvery)
	defer t.Stop()
	said := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d := r.dir.get()
		if d == nil {
			continue
		}
		err := checkDirectoryKeys(ctx, "port49-broker", d, directoryRef(r.cfg), r.keys, io.Discard,
			4*r.cfg.Stores.Directory.Etcd.CallTimeout, false)
		var f *storeFault
		switch {
		case errors.As(err, &f) && f.Error() != said:
			fmt.Fprintf(stderr, "port49-broker: %v; this process keeps running, and password sign-in and pins sealed under that "+
				"key fail here until it holds it\n", f)
			said = f.Error()
		case err == nil:
			said = ""
		}
	}
}
