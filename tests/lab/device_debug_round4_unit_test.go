package lab

import (
	"strings"
	"testing"
)

// Step 4c: the counters read the lines the measured images print. The fixtures
// copy the shape of the kept lines of that run; every value is fake.

func TestDeviceDebugCEOSCountersFromTheCounterLines(t *testing.T) {
	c := func(name string) string {
		return "2026-10-23 15:52:47.342339  1140 TacacsLib            6 TACACS+ counter " + name + " host 192.0.2.1:300/0/Tacacs+ TLS"
	}
	kept := strings.Join([]string{
		c("connOpens"), c("connFails"), // a refused open: opened, then failed
		c("connOpens"), c("messagesSent"), c("messagesReceived"), c("messagesSent"), c("messagesReceived"), c("connCloses"),
		c("connOpens"), c("messagesSent"), c("messagesReceived"), c("connCloses"),
	}, "\n")
	s := deviceDebugSummarize("eos", deviceDebugKept(kept))
	if s.Opened != 3 || s.Closed != 2 || s.Failed != 1 {
		t.Errorf("opened=%d closed=%d failed=%d, want 3 2 1", s.Opened, s.Closed, s.Failed)
	}
	got := []int{}
	for _, cn := range s.Conns {
		got = append(got, cn.Total())
	}
	if len(got) != 3 || got[0] != 0 || got[1] != 2 || got[2] != 1 {
		t.Errorf("requests per connection %v, want [0 2 1]", got)
	}
}

func TestDeviceDebugXRdClosingTheSocketIsAClose(t *testing.T) {
	kept := "RP/0/RP0/CPU0:Oct 23 15:31:11.860 UTC: tacacsd[1139]: Socket connected successfully\n" +
		"RP/0/RP0/CPU0:Oct 23 15:31:12.195 UTC: tacacsd[1139]: closing the socket 1000084"
	s := deviceDebugSummarize("iosxr", deviceDebugKept(kept))
	if s.Opened != 1 || s.Closed != 1 {
		t.Errorf("opened=%d closed=%d, want 1 1", s.Opened, s.Closed)
	}
}

// Junos: the auditd accounting line is the one request line measured; the
// reservation-file "opened" lines of authd are not connections.
func TestDeviceDebugJunosCountsAccountingFromAuditd(t *testing.T) {
	kept := strings.Join([]string{
		"Oct 23 15:31:11.100 srx1 authd[6]: /var/db/x.reserv opened", // not a connection
		"Oct 23 15:31:11.100 srx1 authd[6]: Read persistent Address Reservations encodeType 3",
		"Oct 23 15:31:12.400 srx1 auditd[20326]: AUDITD_TACPLUS_MSG_SENT: successfully sent tacacs+ Accounting-Request message",
	}, "\n")
	s := deviceDebugSummarize("junos", deviceDebugKept(kept))
	if s.Opened != 0 {
		t.Errorf("opened=%d: an authd file-open line counted as a connection", s.Opened)
	}
	if len(s.Conns) != 1 || s.Conns[0].Acct != 1 || s.Conns[0].Authen != 0 || s.Conns[0].Author != 0 {
		t.Errorf("summary %+v", s)
	}
}

// Authentication stays unmeasured until the login path's tag is known: a guessed
// phrase on any line does not count.
func TestDeviceDebugJunosAuthenticationIsUnmeasured(t *testing.T) {
	s := deviceDebugSummarize("junos", "Oct 23 15:31:11.200 srx1 authd[6]: sending authentication request 3 to host")
	if len(s.Conns) != 0 {
		t.Errorf("a guessed authentication line counted: %+v", s)
	}
}

// W2: cEOS's failed opens are written next to the opens.
func TestDeviceDebugFailedOpensAreWritten(t *testing.T) {
	c := func(name string) string {
		return "2026-10-23 15:52:47.342339  1140 TacacsLib            6 TACACS+ counter " + name + " host 192.0.2.1:300/0/Tacacs+ TLS"
	}
	kept := deviceDebugKept(c("connOpens") + "\n" + c("connFails"))
	if sum := ddArmSummary("eos", "tls_unknown_ca", kept, 2, nil); !strings.Contains(sum, "failed_opens=1") {
		t.Errorf("the summary does not write the failed opens")
	}
	_, obs, err := ddDebugNote(ddNoteRun{Platform: "arista_ceos", Profile: "eos", Image: "x", Cells: []ddNoteCell{{Cell: "tls_unknown_ca", Kept: kept, RawLines: 2}}})
	if err != nil || !strings.Contains(obs, "failed_opens=1") {
		t.Errorf("the note does not write the failed opens (err %v)", err)
	}
}

func TestDeviceDebugTagCounterEmitsOnlyCounts(t *testing.T) {
	var tags ddTagCounts
	f := ddTestFilter("junos")
	f.Tags = &tags
	long := "z" + strings.Repeat("y", 30)
	in := strings.Join([]string{
		"Oct 23 15:31:11 srx1 authd[6]: line one",
		"Oct 23 15:31:12 srx1 authd[6]: line two",
		"Oct 23 15:31:13 srx1 sshd[7]: login",
		"Oct 23 15:31:14 srx1 " + ddSentinelKey + "[8]: x", // a secret in the tag position
		"Oct 23 15:31:15 srx1 Mixed[9]: x",                 // mixed case
		"Oct 23 15:31:16 srx1 " + long + "[9]: x",          // too long
		"Oct 23 15:31:17 srx1 deadbeef0011[1]: x",          // hex
		"Oct 23 15:31:18 srx1 " + ddSentinelToken + ": x",  // a minted token
		"no tag at all",
	}, "\n")
	f.Secrets = func() []string { return append(ddTestSecrets(), "p49-zzz") }
	if _, err := f.Keep(in); err != nil {
		t.Fatal(err)
	}
	got := tags.String()
	if got != "authd=2 sshd=1 other=6" {
		t.Errorf("tags %q", got)
	}
	for _, bad := range []string{ddSentinelKey, ddSentinelToken, "Mixed", long, "deadbeef"} {
		if strings.Contains(got, bad) {
			t.Errorf("a tag position value reached the counts")
		}
	}
}

func TestDeviceDebugTagCounterCapsAtThirtyTags(t *testing.T) {
	var tags ddTagCounts
	f := ddTestFilter("junos")
	f.Tags = &tags
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, "Oct 23 15:31:11 srx1 proc"+strings.Repeat("a", i%3)+string(rune('a'+i%26))+string(rune('a'+i/26))+": x")
	}
	if _, err := f.Keep(strings.Join(lines, "\n")); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(tags.String(), "="); n != 31 {
		t.Errorf("%d entries, want 30 tags and other", n)
	}
	if !strings.HasSuffix(tags.String(), "other=10") {
		t.Errorf("the tags past the cap are not counted as other: %q", tags.String())
	}
}
