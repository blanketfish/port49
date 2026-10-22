package lab

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rhwendt/port49/internal/daemon/metrics"
)

const vcsSample = "bin/port49d: go1.26.0\n\tpath\tgithub.com/rhwendt/port49/cmd/port49d\n" +
	"\tbuild\tvcs=git\n\tbuild\tvcs.revision=0123456789abcdef0123456789abcdef01234567\n\tbuild\tvcs.modified=true\n"

func TestBuildVCSReadsRevisionAndModified(t *testing.T) {
	v, err := parseBuildVCS(vcsSample)
	if err != nil || v.Revision != "0123456789abcdef0123456789abcdef01234567" || !v.Modified {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := parseBuildVCS("bin/port49d: go1.26.0\n\tbuild\tvcs.modified=false\n"); err == nil {
		t.Fatal("no vcs.revision: a binary built with -buildvcs=false is refused")
	}
}

// Review I2: an arm's binary is checked, not taken on trust.
func TestL80ArmBinaryCheck(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	pre := "2222222222222222222222222222222222222222"
	hasFix := func(rev string) (bool, error) {
		switch rev {
		case head:
			return true, nil
		case pre:
			return false, nil
		}
		return false, errors.New("unknown revision")
	}
	for name, c := range map[string]struct {
		arm     string
		v       buildVCS
		invalid bool
	}{
		"fixed at HEAD, clean":        {"fixed", buildVCS{head, false}, false},
		"fixed at HEAD, modified":     {"fixed", buildVCS{head, true}, true},
		"fixed from an older build":   {"fixed", buildVCS{pre, false}, true},
		"baseline before the fix":     {"baseline", buildVCS{pre, false}, false},
		"baseline that holds the fix": {"baseline", buildVCS{head, false}, true},
		"baseline, unknown revision":  {"baseline", buildVCS{"3333333333333333333333333333333333333333", false}, true},
		"baseline, modified":          {"baseline", buildVCS{pre, true}, true},
	} {
		err := l80ArmCheck(c.arm, c.v, head, hasFix)
		if (err != nil) != c.invalid {
			t.Errorf("%s: %v, want invalid %v", name, err, c.invalid)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "INVALID: ") {
			t.Errorf("%s: %v does not say INVALID", name, err)
		}
	}
}

// The qual run's offer comes from the binary's own revision: anything but
// the harness tree's clean HEAD is INVALID, since the table could differ.
func TestQualBinaryMatchesTheTree(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	if err := qualBinaryCheck(buildVCS{head, false}, head); err != nil {
		t.Fatal(err)
	}
	for _, v := range []buildVCS{{head, true}, {"2222222222222222222222222222222222222222", false}} {
		if err := qualBinaryCheck(v, head); err == nil || !strings.HasPrefix(err.Error(), "INVALID: ") {
			t.Errorf("%+v: %v", v, err)
		}
	}
}

// Review I1: tls_token_login's capture opens only once no connection is
// open, or the run is INVALID; the grade is never loosened instead.
func TestQualWaitNoConnections(t *testing.T) {
	seq := func(vals ...float64) func() (float64, bool) {
		i := 0
		return func() (float64, bool) {
			v := vals[min(i, len(vals)-1)]
			i++
			return v, true
		}
	}
	nap := func(time.Duration) {}
	if err := qualWaitNoConnections(seq(2, 1, 0), 10, nap); err != nil {
		t.Fatalf("drains to 0: %v", err)
	}
	if err := qualWaitNoConnections(seq(1), 10, nap); err == nil || !strings.HasPrefix(err.Error(), "INVALID: ") {
		t.Fatalf("never drains: %v", err)
	}
	if err := qualWaitNoConnections(func() (float64, bool) { return 0, false }, 10, nap); err != nil {
		t.Fatalf("a daemon that has had no connection exports no series: %v", err)
	}
}

// The selector is the daemon's own spelling, so an absent series means no
// connection, never a typo.
func TestQualConnectionsGaugeSpelling(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	m.Connections.WithLabelValues("open").Add(3)
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if v, ok := l73MetricValue(rec.Body.String(), qualConnectionsOpen); !ok || v != 3 {
		t.Fatalf("%s reads %v %v from the daemon's metrics", qualConnectionsOpen, v, ok)
	}
}

// run.json's field names are genprofile's: a misspelling would read as
// false there and leave the facts absent forever (review O1).
func TestQualRunNamesTheCleanCaptureAndTheOffer(t *testing.T) {
	b, err := json.Marshal(qualRun{TLSServerSingleConnectOffered: true, TLSCaptureStartedClean: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"tls_server_single_connect_offered":true`, `"tls_capture_started_clean":true`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("run.json lacks %s: %s", key, b)
		}
	}
}
