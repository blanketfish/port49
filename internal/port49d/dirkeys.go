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
	held := keys.Current.ID == last.Current || keys.Previous != nil && keys.Previous.ID == last.Current
	if ok && !held {
		id := crypt.LineKeyID(last.Current)
		return &storeFault{fmt.Errorf("%s: crypt: the directory store (%s) was last written by a process whose "+
			"current key is %q, which this configuration does not hold (%s); every region holds the same "+
			"encryption keys (decision 51): add %q to encryption, then start again", proc, ref.where(), id,
			keyWindow(keys), id)}
	}
	if undecodable {
		fmt.Fprintf(out, "%s: crypt: the directory store's key window is unreadable (meta/seal_keys does not "+
			"decode); every region holds the same encryption keys, and this start cannot check that it does\n", proc)
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

// checkTwoStores refuses a split whose two blocks reach one etcd cluster
// with the same prefix, or one prefix holding the other (plan 11a, R28):
// one keyspace named two ways (an IP and a DNS name), which the config's
// text compare (R22) cannot see. It reads each cluster's id within bound.
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
	return &storeFault{fmt.Errorf("stores.directory (prefix %s) and stores.session (prefix %s) reach one etcd "+
		"cluster (id %x), and one prefix holds the other: they are one keyspace named two ways; omit "+
		"stores.session for a single site, or give the directory a cluster of its own",
		cfg.Stores.Directory.Etcd.Prefix, cfg.Stores.Session.Etcd.Prefix, a)}
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
			fmt.Fprintf(stderr, "%v; this process keeps running, and password sign-in and pins sealed under that "+
				"key fail here until it holds it\n", f)
			said = f.Error()
		case err == nil:
			said = ""
		}
	}
}
