package port49d

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// A member below the floor refuses the start, naming it; one that does not
// answer is said and does not hold the start (decision 53 ruling 9).
func TestTheFloorRefusesAnOldMemberAndSaysADarkOne(t *testing.T) {
	var out bytes.Buffer
	err := checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e1:2379", Version: "3.6.15"},
		{Endpoint: "https://e2:2379", Err: errors.New("deadline")}}, "session store", &out, "port49d")
	if err != nil || !strings.Contains(out.String(), "https://e2:2379 did not answer") ||
		!strings.Contains(out.String(), "3.6.15") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	out.Reset()
	err = checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e1:2379", Version: "3.6.15"},
		{Endpoint: "https://e3:2379", Version: "3.5.2"}}, "session store", &out, "port49d")
	if err == nil || !strings.Contains(err.Error(), "https://e3:2379") || !strings.Contains(err.Error(), "3.5.2") ||
		!strings.Contains(err.Error(), etcdstore.VersionFloor) {
		t.Fatalf("%v", err)
	}
}

// What a member answers is its own text: a version that does not parse is
// refused without being quoted, and a probe's error text is not printed.
func TestTheFloorNeverEchoesWhatAMemberSaid(t *testing.T) {
	const said = "FAKE-member-text\nport49d: forged line"
	var out bytes.Buffer
	err := checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e1:2379", Version: said}}, "session store",
		&out, "port49d")
	if err == nil || !strings.Contains(err.Error(), "https://e1:2379") || !strings.Contains(err.Error(), etcdstore.VersionFloor) ||
		strings.Contains(err.Error(), "FAKE-member-text") || strings.Contains(err.Error(), "forged") {
		t.Fatalf("%v", err)
	}
	out.Reset()
	err = checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e2:2379",
		Err: errors.New("rpc error: FAKE-member-text\nforged")}}, "session store", &out, "port49d")
	if err != nil || strings.Contains(out.String(), "FAKE-member-text") || strings.Contains(out.String(), "forged") ||
		!strings.Contains(out.String(), "https://e2:2379 did not answer") {
		t.Fatalf("%v\n%s", err, out.String())
	}
}

// A server start against a member below the floor is refused as a store
// fault, and the offline path is not (decision 53 ruling 9; pre-flight M13).
func TestAStartAgainstAMemberBelowTheFloorIsRefused(t *testing.T) {
	was := endpointVersions
	t.Cleanup(func() { endpointVersions = was })
	endpointVersions = func(s *etcdstore.Store, ctx context.Context, eps []string, per time.Duration) []etcdstore.EndpointVersion {
		vs := was(s, ctx, eps, per)
		for i := range vs {
			vs[i].Version, vs[i].Err = "3.5.2", nil
		}
		return vs
	}
	cfgPath, _ := etcdSplit(t)
	out, err := runExpectingRefusal(t, cfgPath)
	if err == nil || !strings.Contains(err.Error()+out, "3.5.2, below the floor") {
		t.Fatalf("%v\n%s", err, out)
	}
	// The offline path opens the same store: an emergency revoke against an
	// old cluster must still run.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var off bytes.Buffer
	s, err := attempt(context.Background(), cfg, sessionRef(cfg), metrics.New(prometheus.NewRegistry()), &off, false)
	if err != nil {
		t.Fatalf("the offline path was refused: %v\n%s", err, off.String())
	}
	s.Close()
	if strings.Contains(off.String(), "floor") {
		t.Fatalf("the offline path asked the floor:\n%s", off.String())
	}
}

// An emergency revoke against an old cluster must still run: the offline
// broker opens the store without asking the floor.
func TestTheOfflineBrokerOpensAMemberBelowTheFloor(t *testing.T) {
	was := endpointVersions
	t.Cleanup(func() { endpointVersions = was })
	endpointVersions = func(s *etcdstore.Store, ctx context.Context, eps []string, per time.Duration) []etcdstore.EndpointVersion {
		vs := was(s, ctx, eps, per)
		for i := range vs {
			vs[i].Version, vs[i].Err = "3.5.2", nil
		}
		return vs
	}
	f := splitFleet(t)
	var out syncBuffer
	run, err := offlineBroker(context.Background(), f.broker, io.Discard, &out)
	if err != nil {
		t.Fatalf("the offline broker was refused: %v\n%s", err, out.String())
	}
	run.close()
	if strings.Contains(out.String(), "floor") {
		t.Fatalf("the offline broker asked the floor:\n%s", out.String())
	}
}

// A member on a release candidate of a floor release is refused, naming the
// version and saying why: the text is fixed apart from the parsed version.
func TestAFloorReleaseCandidateIsRefusedWithAFixedReason(t *testing.T) {
	var out bytes.Buffer
	err := checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e1:2379", Version: "3.5.8-rc.0"}},
		"session store", &out, "port49d")
	if err == nil || !strings.Contains(err.Error(), "version 3.5.8-rc.0, below the floor") ||
		!strings.Contains(err.Error(), "a pre-release is older than its release") ||
		!strings.Contains(err.Error(), etcdstore.VersionFloor) {
		t.Fatalf("%v", err)
	}
	out.Reset()
	if err := checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e1:2379", Version: "3.5.9-rc.0"}},
		"session store", &out, "port49d"); err != nil || !strings.Contains(out.String(), "3.5.9-rc.0") {
		t.Fatalf("%v\n%s", err, out.String())
	}
}
