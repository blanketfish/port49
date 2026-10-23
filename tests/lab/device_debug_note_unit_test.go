package lab

import (
	"os"
	"strings"
	"testing"
)

// ddNoteFixtureRun is an armed IOS XE run with two cells, built from lines in the
// step 4 shapes. The image string is invented: the note takes it from the run.
func ddNoteFixtureRun() ddNoteRun {
	f := ddTestFilter("iosxe")
	token := f.Keep(strings.Join([]string{
		ddXEPre + "TPLUS: immediate connect 3, new 0x7F12",
		ddXEPre + "TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 7)",
		ddXEPre + "TPLUS: processing authentication login request id 1",
		ddXEPre + "TPLUS: Accounting request created for 0(alice07)",
		"*Oct 23 09:48:30.001: TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)",
		"*Oct 23 09:48:30.100: TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 8)",
		"*Oct 23 09:48:30.101: TPLUS: Authorization request created for 0(alice07)",
	}, "\n"))
	ca := f.Keep(strings.Join([]string{
		"*Oct 23 09:49:01.000: TAC+: opened 172.100.100.1/49",
		"*Oct 23 09:49:01.050: TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)",
	}, "\n"))
	return ddNoteRun{
		Platform: "cisco_iosxe", Profile: "iosxe", Image: "Test Router 1.2.3",
		Cells: []ddNoteCell{
			{Cell: "tls_token_login", Kept: token, RawLines: 700, Ready: 1,
				TLSConns: []string{"conn port=57518 syn=09:48:29.345 hold=0.03s end=server-fin", "conn port=57532 syn=09:48:30.090 hold=open end=open"},
				Shapes:   []string{"show logging => _ tplus _ cmd _ debug tacacs _", "show logging => _ tac _ handle tacacs _ secure message _"}},
			{Cell: "tls_unknown_ca", Kept: ca, RawLines: 400,
				TLSConns: []string{"conn port=57600 syn=09:49:00.990 hold=0.08s end=server-rst"},
				Shapes:   []string{"show logging => _ author _ cmd _"}},
		},
	}
}

// The note is the golden text, byte for byte: the claim, a blank line, the
// observation. Update testdata/device_debug_note.golden.md only after reading
// the new text.
func TestDeviceDebugNoteMatchesTheGoldenText(t *testing.T) {
	claim, obs, err := ddDebugNote(ddNoteFixtureRun())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/device_debug_note.golden.md")
	if err != nil {
		t.Fatal(err)
	}
	if got := claim + "\n\n" + obs; got != string(want) {
		t.Errorf("the note differs from testdata/device_debug_note.golden.md:\n%s", got)
	}
}

// Platform and image come from the run: another run gives another note, and no
// platform or image of another row is in it.
func TestDeviceDebugNoteTakesPlatformAndImageFromTheRun(t *testing.T) {
	a := ddNoteFixtureRun()
	b := ddNoteFixtureRun()
	b.Platform, b.Image = "some_other_platform", "Other Image 9.9"
	ca, oa, _ := ddDebugNote(a)
	cb, ob, _ := ddDebugNote(b)
	if !strings.Contains(ca+oa, "cisco_iosxe") || !strings.Contains(ca+oa, "Test Router 1.2.3") {
		t.Errorf("the first note lacks its platform or image")
	}
	if !strings.Contains(cb+ob, "some_other_platform") || !strings.Contains(cb+ob, "Other Image 9.9") {
		t.Errorf("the second note lacks its platform or image")
	}
	for _, other := range []string{"cisco_iosxe", "Test Router 1.2.3", "cisco_xrd", "Catalyst", "XRd", "vJunos", "cEOS"} {
		if strings.Contains(cb+ob, other) {
			t.Errorf("the second note names %q, which is not its platform or image", other)
		}
	}
}

// With nothing kept every question says it is unmeasured, and the note says the
// filter kept nothing: there is no answer without a debug line.
func TestDeviceDebugNoteSaysUnmeasuredWhenNothingWasKept(t *testing.T) {
	in := ddNoteRun{Platform: "arista_ceos", Profile: "eos", Image: "Test EOS 1.0", Cells: []ddNoteCell{
		{Cell: "tls_token_login", RawLines: 860, TLSConns: []string{"conn port=1 syn=10:05:10.587 hold=0.01s end=server-fin", "conn port=2 syn=10:05:12.968 hold=0.00s end=server-fin"},
			Shapes: []string{"show agent Aaa logs => _ created socket _"}},
		{Cell: "tls_unknown_ca", RawLines: 10},
	}}
	_, obs, err := ddDebugNote(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"**Which debug line marks a connection open?** Unmeasured: no kept line is a connection open.",
		"**tls_token_login: why does the device open a second connection?** Unmeasured: the capture holds 2 connections and the kept debug marks 0 open(s).",
		"**How does a connection end?** Unmeasured: no kept line is a close or a TLS failure.",
		"**Do requests ride one connection together (pipelining)?** Unmeasured: no kept line is a request.",
		"**the filter kept nothing**",
	} {
		if !strings.Contains(obs, want) {
			t.Errorf("the note lacks %q:\n%s", want, obs)
		}
	}
	// A cell that was not run armed is unmeasured, not absent.
	_, obs, _ = ddDebugNote(ddNoteRun{Platform: "p", Profile: "eos", Image: "i", Cells: []ddNoteCell{{Cell: "tls_unknown_ca"}}})
	if !strings.Contains(obs, "**tls_token_login: why does the device open a second connection?** Unmeasured: the cell was not run armed.") ||
		!strings.Contains(obs, "**Do requests ride one connection together (pipelining)?** Unmeasured: the cell was not run armed.") {
		t.Errorf("a missing cell is not said to be unmeasured:\n%s", obs)
	}
}

// Junos has no close line and its requests cannot be assigned to a connection:
// the note says so rather than printing a zero or a count.
func TestDeviceDebugNoteJunosCloseAndPipeliningAreUnmeasured(t *testing.T) {
	f := ddTestFilter("junos")
	kept := f.Keep(strings.Join([]string{
		"Oct 23 10:00:24.100000 authd[900]: opened 172.100.100.1/49",
		"Oct 23 10:00:24 vjunos authd[900]: sent tacacs+ authentication request message, 7",
		"Oct 23 10:00:24 vjunos authd[900]: sent tacacs+ authorization request message, 8",
		"Oct 23 10:00:25 vjunos authd[900]: send failed: authentication with error TLS 5 has failed",
	}, "\n"))
	in := ddNoteRun{Platform: "juniper_vjunos-router", Profile: "junos", Image: "Test Junos 1.0", Cells: []ddNoteCell{
		{Cell: "tls_token_login", Kept: kept, RawLines: 440, TLSConns: []string{"conn port=1 syn=10:00:24.309 hold=0.01s end=server-fin"}},
		{Cell: "tls_unknown_ca", Kept: kept, RawLines: 440, TLSConns: []string{"conn port=2 syn=10:00:30.000 hold=0.00s end=server-rst"}},
	}}
	_, obs, err := ddDebugNote(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"closed=unknown",
		"neither file has a close line",
		"**Do requests ride one connection together (pipelining)?** Unmeasured: 2 request line(s) were kept, but the trace's requests cannot be assigned to a connection",
		"TLS failure `",
	} {
		if !strings.Contains(obs, want) {
			t.Errorf("the junos note lacks %q:\n%s", want, obs)
		}
	}
	if strings.Contains(obs, "closed=0") || strings.Contains(obs, "close `") {
		t.Errorf("the junos note counts or quotes a close:\n%s", obs)
	}
}

// A line with a secret word, a hex run or a long token run never goes in a note,
// whatever put it in the input: the write is refused, not the line trimmed.
func TestDeviceDebugNoteRefusesUnsafeLines(t *testing.T) {
	for name, mut := range map[string]func(*ddNoteRun){
		"kept secret word": func(r *ddNoteRun) { r.Cells[0].Kept += "\n09:48:31.000 TPLUS: connected socket password" },
		"kept hex run":     func(r *ddNoteRun) { r.Cells[0].Kept += "\n09:48:31.000 TPLUS: connected socket deadbeefcafe0123" },
		"kept long run": func(r *ddNoteRun) {
			r.Cells[0].Kept += deviceDebugKept("\n09:48:31.000 TPLUS: connected socket " + strings.Repeat("Zz", 14))
		},
		"shape payload": func(r *ddNoteRun) { r.Cells[0].Shapes = append(r.Cells[0].Shapes, "show logging => _ payload _") },
		"capture token": func(r *ddNoteRun) { r.Cells[0].TLSConns = append(r.Cells[0].TLSConns, "conn token=x") },
	} {
		in := ddNoteFixtureRun()
		mut(&in)
		wrote := false
		err := qualWriteDebug(in, nil, func(string, string) { wrote = true })
		if err == nil || wrote {
			t.Errorf("%s: the note was written (err %v)", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "deadbeef") {
			t.Errorf("%s: the error names the line", name)
		}
	}
}

// The writer passes the run's secrets through the same gate as every results
// note, and writes the claim and observation once when they are clean.
func TestDeviceDebugNoteWriterGatesAndWrites(t *testing.T) {
	in := ddNoteFixtureRun()
	n := 0
	if err := qualWriteDebug(in, []string{"zorkmid-not-in-note"}, func(claim, obs string) {
		n++
		if claim == "" || obs == "" {
			t.Errorf("an empty note was written")
		}
	}); err != nil || n != 1 {
		t.Fatalf("clean note: err %v, written %d", err, n)
	}
	in.Cells[0].Shapes = append(in.Cells[0].Shapes, "show logging => _ zorkmid-xyz-17 _")
	wrote := false
	err := qualWriteDebug(in, []string{"zorkmid-xyz-17"}, func(string, string) { wrote = true })
	if err == nil || wrote {
		t.Errorf("a note holding a run secret was written (err %v)", err)
	}
	if err != nil && strings.Contains(err.Error(), "zorkmid-xyz-17") {
		t.Errorf("the error names the secret")
	}
	if err := qualWriteDebug(ddNoteRun{Platform: "p", Profile: "nope", Image: "i", Cells: in.Cells}, nil, func(string, string) {}); err == nil {
		t.Errorf("an unknown profile wrote a note")
	}
	if err := qualWriteDebug(ddNoteRun{Platform: "p", Profile: "iosxe", Image: "i"}, nil, func(string, string) {}); err == nil {
		t.Errorf("a run with no cell wrote a note")
	}
}

// An EOS or Junos TLS failure line answers the "how does it end" question for a
// platform that has a close line too; a close line alone answers it elsewhere.
func TestDeviceDebugNoteQuotesTheFailureLine(t *testing.T) {
	f := ddTestFilter("eos")
	kept := f.Keep("2026-10-23 10:05:13.100000 21 Aaa Tacacs: error: ssl failed 7 tls\n2026-10-23 10:05:13.200000 21 Aaa Tacacs: close 5")
	_, obs, err := ddDebugNote(ddNoteRun{Platform: "arista_ceos", Profile: "eos", Image: "i",
		Cells: []ddNoteCell{{Cell: "tls_unknown_ca", Kept: kept, RawLines: 5}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(obs, "`tls_unknown_ca`: close `10:05:13.200000 Tacacs: close <masked>`, TLS failure `10:05:13.100000 Tacacs: error: ssl failed <masked> tls`") {
		t.Errorf("the end-of-connection answer is not both lines:\n%s", obs)
	}
}
