package port49d

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// The offline broker on two stores opens the directory store without asking
// the floor too: an emergency revoke against an old cluster must still run,
// and the directory open (offline.go) is its own call from the session open.
func TestTheOfflineBrokerOnTwoStoresOpensOldMembers(t *testing.T) {
	was := endpointVersions
	t.Cleanup(func() { endpointVersions = was })
	asked := 0
	endpointVersions = func(s *etcdstore.Store, ctx context.Context, eps []string, per time.Duration) []etcdstore.EndpointVersion {
		asked++
		vs := was(s, ctx, eps, per)
		for i := range vs {
			vs[i].Version, vs[i].Err = "3.5.2", nil
		}
		return vs
	}
	f := splitFleet(t)
	f.twoStores(t)
	var out syncBuffer
	run, err := offlineBroker(context.Background(), f.broker, io.Discard, &out)
	if err != nil {
		t.Fatalf("the offline broker was refused on two stores: %v\n%s", err, out.String())
	}
	run.close()
	if asked != 0 || strings.Contains(out.String(), "floor") {
		t.Fatalf("the offline broker asked the floor %d times:\n%s", asked, out.String())
	}
}
