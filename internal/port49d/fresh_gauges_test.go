package port49d

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/store"
)

// The directory store's two gauges exist at 0 once an etcd daemon tells them, and not before: a
// memory-backed daemon never calls tellFresh, so an alert on reachable == 0 has no series to
// page on (plan 12c, Task 5 fix 1, C1).
func TestTheDirectoryGaugesExistOnlyOnceTold(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	if testutil.CollectAndCount(m.StoreDirectoryReachable) != 0 || testutil.CollectAndCount(m.StoreKeyspaceHeld) != 0 {
		t.Fatal("a daemon that never told the gauges has a series")
	}
	tellFresh(store.NewFreshness(time.Now), m)
	if testutil.CollectAndCount(m.StoreDirectoryReachable) != 1 || testutil.ToFloat64(m.StoreDirectoryReachable) != 0 ||
		testutil.CollectAndCount(m.StoreDirectoryConfirmed) != 1 || testutil.ToFloat64(m.StoreDirectoryConfirmed) != 0 {
		t.Fatal("after tellFresh both series are not at 0")
	}
}

// A broker with a directory_password verifier says so, so the alert on its enrollment store can
// tell "never reached" (the gauge absent) from "no such verifier" (plan 12c, Task 5 fix 1, I1).
func TestSettingThePasswordSignInSetsItsConfiguredGauge(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	setPasswordSignIn(config.Config{Broker: &config.BrokerConfig{Identity: &oidc.Config{}}}, &broker.Broker{Metrics: m})
	if v := testutil.ToFloat64(m.DirectoryPasswordConfigured); v != 0 {
		t.Fatalf("with no verifier: %v", v)
	}
	setPasswordSignIn(config.Config{Broker: &config.BrokerConfig{Identity: &oidc.Config{PasswordSignIn: &oidc.PasswordSignIn{}}}},
		&broker.Broker{Metrics: m})
	if v := testutil.ToFloat64(m.DirectoryPasswordConfigured); v != 1 {
		t.Fatalf("with a verifier: %v", v)
	}
}
