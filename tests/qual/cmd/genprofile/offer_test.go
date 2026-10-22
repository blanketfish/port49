package main

import (
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/devicemock"
)

// tlsConnAt is one header-only TLS connection open from syn to end (zero:
// still open when the capture stopped).
func tlsConnAt(base time.Time, syn, end time.Duration) conn {
	c := conn{SYNAt: base.Add(syn)}
	if end > 0 {
		c.EndAt, c.End = base.Add(end), "server-fin"
	} else {
		c.End = "open"
	}
	return c
}

func recAt(base time.Time, event string, at time.Duration) *rec {
	return &rec{Event: event, at: base.Add(at)}
}

// RI4: "honored" and "ignored" are graded from the connections' times and
// port49's own records, in header terms only; absent, not false, where port49
// never offered.
func TestServerSingleConnectFact(t *testing.T) {
	base := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	note := devicemock.Source{Note: "tests/lab/results/QUAL-x-cisco_nxos.md", Register: "QUAL"}
	s := time.Second
	reused := []conn{tlsConnAt(base, 0, 0)}
	reusedRecs := []*rec{recAt(base, "redeem", s), recAt(base, "authorize_session", 2*s),
		recAt(base, "account", 3*s), recAt(base, "authorize_command", 4*s)}
	perRequest := []conn{tlsConnAt(base, 0, 2*s), tlsConnAt(base, 3*s, 5*s), tlsConnAt(base, 6*s, 8*s)}
	perRequestRecs := []*rec{recAt(base, "redeem", s), recAt(base, "authorize_session", 4*s), recAt(base, "account", 7*s)}
	// Two sessions on a connection, but only behind an accounting record:
	// arm E's pipelining, not reuse.
	afterAcct := []conn{tlsConnAt(base, 0, 2*s), tlsConnAt(base, 3*s, 6*s)}
	afterAcctRecs := []*rec{recAt(base, "redeem", s), recAt(base, "account", 4*s), recAt(base, "authorize_command", 5*s)}
	for name, c := range map[string]struct {
		offered bool
		conns   []conn
		recs    []*rec
		want    string
	}{
		"offered, one connection carries a session after a completed non-accounting one": {true, reused, reusedRecs, devicemock.FactTLSServerSingleConnectHonored},
		"offered, every connection carries one session":                                  {true, perRequest, perRequestRecs, devicemock.FactTLSServerSingleConnectIgnored},
		"offered, two sessions only behind accounting":                                   {true, afterAcct, afterAcctRecs, ""},
		"never offered, reused":                                                          {false, reused, reusedRecs, ""},
		"never offered, per request":                                                     {false, perRequest, perRequestRecs, ""},
		"offered, no records":                                                            {true, perRequest, nil, ""},
	} {
		f := serverSingleConnectFact(c.offered, c.conns, c.recs, note)
		switch {
		case c.want == "" && f != nil:
			t.Errorf("%s: wrote %s, want no claim", name, f.ID)
		case c.want != "" && (f == nil || f.ID != c.want):
			t.Errorf("%s: wrote %+v, want %s", name, f, c.want)
		case f != nil && (f.Status != "measured" || len(f.Sources) != 1 || f.Sources[0] != note || f.What == ""):
			t.Errorf("%s: %+v", name, f)
		}
	}
}
