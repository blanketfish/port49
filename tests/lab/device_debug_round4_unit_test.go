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

// Junos: every line of the tacplus traceoptions file is a TACACS line whatever its
// prefix; the same rules scrub it; a line of the auth log still needs the facility.
func TestDeviceDebugJunosTacplusFileKeepsEveryLine(t *testing.T) {
	f := ddTestFilter("junos")
	tok := ddSentinelToken
	in := strings.Join([]string{
		"Oct 23 15:31:11.100 conn up to 192.0.2.1",                    // no facility word
		"Oct 23 15:31:11.200 got reply for " + ddSentinelKey + " end", // a known secret
		"Oct 23 15:31:11.300 bearer " + tok + " end",                  // a minted token
		"Oct 23 15:31:11.400 cfg key 7 08224A end",                    // type 7
		"Oct 23 15:31:11.500 cfg secret \"$9$qf3nCtu1hSyKvLx\" end",   // $9$
		"Oct 23 15:31:11.600 dump c0 01 02 03 04",                     // a hex dump
		"Oct 23 15:31:11.700 body_payload word",                       // a body word
		"Oct 23 15:31:11.800 tls_aes_128_gcm_sha256 negotiated",       // a marker
		"6b 2d 31", // a message of only hex groups, with nothing before it
		"",
	}, "\n")
	f.Secrets = func() []string { return append(ddTestSecrets(), tok) }
	got, err := f.KeepSource(in, true)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(got), "\n")
	if len(lines) != 5 {
		t.Fatalf("kept %d lines, want 5 (plain, secret, token, type 7, nine)", len(lines))
	}
	for _, bad := range []string{ddSentinelKey, tok, "08224A", "qf3nCtu1hSyKvLx", "c0 01"} {
		if strings.Contains(string(got), bad) {
			t.Errorf("a scrubbed value survived")
		}
	}
	if !strings.Contains(string(got), "conn up to") || strings.Count(string(got), "<redacted>") < 3 {
		t.Errorf("the plain line was lost or the values were not redacted")
	}
	// the same text is dropped by the facility rule when it is not from the tacplus file
	if got, _ := f.KeepSource("Oct 23 15:31:11.100 conn up to 192.0.2.1", false); got != "" {
		t.Errorf("a line with no facility was kept from a file that is not the tacplus file")
	}
}

func TestDeviceDebugJunosCollectsTheTacplusFileWhole(t *testing.T) {
	cmds := deviceDebugCmds["junos"]
	var ran []string
	run := func(cmd string) (string, error) {
		ran = append(ran, cmd)
		switch cmd {
		case "show log p49-tacplus.log":
			return "show log p49-tacplus.log\nOct 23 15:31:11.100 conn up to 192.0.2.1\nlab@vjunos> \n", nil
		case "show log p49-auth.log":
			return "Oct 23 15:31:11.100 auditd[5]: login ok\nOct 23 15:31:11.200 authd[6]: TACACS ok\n", nil
		}
		return "", nil
	}
	kept, err := captureDeviceDebug(ddTestFilter("junos"), run, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(kept), "\n") != 1 { // two lines: conn up, and authd[6]
		t.Errorf("the echo or the prompt was kept: %d lines", strings.Count(string(kept), "\n")+1)
	}
	if !strings.Contains(string(kept), "conn up to") || strings.Contains(string(kept), "auditd") || !strings.Contains(string(kept), "authd[6]") {
		t.Errorf("collection did not apply the file rule to the tacplus file only: %q", kept)
	}
	_ = cmds
}

// Junos wording is a guess from the vendor documents, not measured.
func TestDeviceDebugJunosCountersReadTheGuessedWording(t *testing.T) {
	kept := strings.Join([]string{
		"Oct 23 15:31:11.100 tacplus: connecting to server 192.0.2.1",
		"Oct 23 15:31:11.200 tacplus: sent tacacs authentication request message",
		"Oct 23 15:31:11.300 tacplus: sent tacacs authorization request message",
		"Oct 23 15:31:11.400 tacplus: closing connection to server 192.0.2.1",
	}, "\n")
	s := deviceDebugSummarize("junos", deviceDebugKept(kept))
	if s.Opened != 1 || len(s.Conns) != 1 || s.Conns[0].Authen != 1 || s.Conns[0].Author != 1 || s.Conns[0].Closed == "" {
		t.Errorf("summary %+v", s)
	}
}
