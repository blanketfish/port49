package port49d

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestConnectionCap(t *testing.T) {
	for _, c := range []struct {
		set    int
		nofile uint64
		want   int
		err    string
	}{
		{0, 1 << 20, 1<<20 - 1024, ""},
		{0, 1024, 512, ""},
		{0, 1 << 40, 1 << 20, ""}, // effectively unlimited: bounded
		{5000, 1 << 20, 5000, ""},
		{1000, 1024, 0, "leaves fewer than 256"},
	} {
		got, err := connectionCap(c.set, c.nofile)
		if got != c.want || (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%+v: %d, %v", c, got, err)
		}
	}
}

// port49d's start sizes the cap, says it, and publishes it: the wiring the
// server tests cannot see (pre-flight I11).
func TestTheStartSaysAndPublishesTheCap(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfgPath, _ := policyOnlyRun(t)
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("limits: {max_connections: 64}\n")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	startSplitDaemon(t, cfgPath, &out, 1)
	waitFor(t, &out, "at most 64 TACACS+ connections at once (limits.max_connections)")
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if ms == nil {
		t.Fatalf("no metrics line:\n%s", out.String())
	}
	if got := scrapeGauge(t, ms[1], "port49_connections_max"); got != 64 {
		t.Fatalf("port49_connections_max = %v", got)
	}
}
