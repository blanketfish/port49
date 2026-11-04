//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/tests/deviceaaa"
)

func l88TestPlatform(sel string) platform {
	for _, p := range platforms {
		if p.sel == sel {
			return p
		}
	}
	panic("no platform " + sel)
}

// The lines l88Apply sends are Render's output with lab values and nothing added.
func TestL88AppliesTheShippedFileUnchanged(t *testing.T) {
	for _, p := range platforms {
		ref, ok := l88Refs[p.name]
		if !ok {
			continue
		}
		for _, transport := range []string{"tcp", "tls"} {
			if transport == "tls" && !l88HasTLS(p.sel) {
				continue
			}
			var sent []string
			err := l88ApplyWith(p, transport, l88Servers, func(lines []string) error {
				sent = append(sent, lines...)
				return nil
			})
			if err != nil {
				t.Fatalf("%s %s: %v", p.sel, transport, err)
			}
			renderAs := transport
			if p.name == "nokia_srlinux" && transport == "tls" {
				// No TLS reference exists for SR Linux (cell h): the plain one, then a tls-profile and port 300.
				renderAs = "tcp"
				plain, _ := deviceaaa.Render(ref, "tcp", l88Values(p, l88Servers), labKeyDefault)
				if len(sent) != len(plain)+2*len(l88Servers) || !strings.Contains(sent[len(sent)-1], "tacacs port 300") {
					t.Errorf("%s tls: the plain reference plus a tls-profile and port per server, got %q", p.sel, sent)
				}
				sent = sent[:len(plain)]
			}
			want, err := deviceaaa.Render(ref, renderAs, l88Values(p, l88Servers), labKeyDefault)
			if err != nil {
				t.Fatalf("%s %s: %v", p.sel, transport, err)
			}
			if !reflect.DeepEqual(sent, want) {
				t.Errorf("%s %s: the lab sent lines other than Render's\nsent: %q\nwant: %q", p.sel, transport, sent, want)
			}
			if len(sent) == 0 {
				t.Errorf("%s %s: nothing was sent", p.sel, transport)
			}
		}
	}
}

func TestL88CellsPerPlatform(t *testing.T) {
	has := func(cells []string, c string) bool {
		for _, x := range cells {
			if x == c {
				return true
			}
		}
		return false
	}
	for _, p := range platforms {
		if _, ok := l88Refs[p.name]; !ok {
			continue
		}
		cells := l88Cells(p.sel, false)
		junos := strings.HasPrefix(p.name, "juniper_")
		if has(cells, "i") != junos {
			t.Errorf("%s: cell i present %v, want %v (Junos only)", p.sel, has(cells, "i"), junos)
		}
		if has(l88Cells(p.sel, true), "i") {
			t.Errorf("%s: the TLS pass repeats cell i", p.sel)
		}
		for _, c := range []string{"a", "b", "c", "d", "e", "f"} {
			if !has(cells, c) {
				t.Errorf("%s: cell %s is missing", p.sel, c)
			}
		}
		// The TLS pass (cell h) runs only the cells the transport changes: not c, g or i.
		want := "a,b,d,e,f"
		if p.name == "nokia_srlinux" {
			want = "h" // SR Linux over RFC 9887 is not measured (L92): the pass records one observation and runs nothing else
		}
		if got := strings.Join(l88Cells(p.sel, true), ","); got != want {
			t.Errorf("%s: the TLS pass runs %s, want %s", p.sel, got, want)
		}
	}
	// Cell h is the TLS pass itself (PORT49_L88_TLS=1), never a cell of the plain pass.
	for _, p := range platforms {
		if _, ok := l88Refs[p.name]; ok && has(l88Cells(p.sel, false), "h") {
			t.Errorf("%s: the plain pass lists cell h", p.sel)
		}
	}
	// g is skipped where L29 measured the platform.
	for _, sel := range []string{"eos", "vjunos", "nxos", "iosxe"} {
		if has(l88Cells(sel, false), "g") {
			t.Errorf("%s: L29 measured it; cell g must be skipped", sel)
		}
	}
	for _, sel := range []string{"vsrx", "xrd261", "srlinux", "vjunos26", "iosxe1718", "nxos106", "ceos436"} {
		if !has(l88Cells(sel, false), "g") {
			t.Errorf("%s: L29 did not measure it; cell g must run", sel)
		}
	}
}

func TestL88NoteHoldsNoSecret(t *testing.T) {
	const pw = "Zk3-known-lab-password-9XyQ"
	hash := "$6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv"
	n := newL88Note(l88TestPlatform("eos"), "tcp", pw, hash)
	n.cell("a", "PASS", "refused for "+pw+" and "+hash+" with key "+labKeyDefault+" and "+breakglassPassword,
		"set system login user x authentication encrypted-password "+hash+" // "+pw)
	n.fact("typed " + pw)
	out, err := n.render()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{pw, hash, labKeyDefault, breakglassPassword} {
		if strings.Contains(out, s) {
			t.Errorf("the note holds %q", s)
		}
	}
	if !strings.Contains(out, "refused for") {
		t.Errorf("the note lost its observation:\n%s", out)
	}
	// The write-time screen refuses a note that still holds the password.
	n.raw = pw
	if _, err := n.render(); err == nil {
		t.Errorf("a note holding the password rendered")
	}
}

func TestL88PasswordHashShapes(t *testing.T) {
	const pw = "p-w-for-shape-0123"
	cases := map[string]string{"arista_eos": "$6$", "cisco_nxos": "$1$", "cisco_iosxe": "$9$", "juniper_vjunos-router": "$6$",
		"nokia_srlinux": "$6$", "cisco_xrd": "$6$", "arista_ceos": "$6$", "juniper_vsrx": "$6$"}
	for name, prefix := range cases {
		h, err := l88PasswordHash(name, pw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasPrefix(h, prefix) || strings.Contains(h, pw) {
			t.Errorf("%s: hash %q has the wrong shape", name, l88Shape(h))
		}
	}
	a, _ := l88PasswordHash("cisco_iosxe", pw)
	b, _ := l88PasswordHash("cisco_iosxe", pw)
	if a == b {
		t.Errorf("IOS XE type 9 hashes of one password match: the salt is not random")
	}
}

func TestL88LocalAccountLines(t *testing.T) {
	const hash = "$6$s$h"
	for name, want := range map[string]string{
		"juniper_vjunos-router": `set system login user l88deny authentication encrypted-password "$6$s$h"`,
		"arista_eos":            "username l88deny privilege 1 secret sha512 $6$s$h",
		"arista_ceos":           "username l88deny privilege 1 secret sha512 $6$s$h",
	} {
		add, del := l88LocalAccount(name, "l88deny", hash)
		if !slices.Contains(add, want) {
			t.Errorf("%s: add = %q, want the line %q", name, add, want)
		}
		if len(del) == 0 || strings.Contains(strings.Join(del, "\n"), hash) {
			t.Errorf("%s: delete lines %q are empty or carry the hash", name, del)
		}
	}
}

func TestL88AccountCounts(t *testing.T) {
	recs := []map[string]any{
		{"event": "account", "username": "alice01", "flags": "start"},
		{"event": "account", "username": "alice01", "flags": "stop"},
		{"event": "account", "username": "alice02", "flags": "start"},
		{"event": "redeem", "username": "alice01"},
	}
	if s, p := l88AccountCounts(recs, "alice01"); s != 1 || p != 1 {
		t.Errorf("counts = %d, %d; want 1, 1", s, p)
	}
}

func TestL88MissingTreatsEOSDefaultVRFAsImplicit(t *testing.T) {
	typed := []string{"ip tacacs vrf default source-interface Management1", "server 172.100.100.1 vrf default",
		"tacacs-server host 172.100.100.1 vrf default key 0 " + labKeyDefault, "aaa authentication login default group port49 local"}
	shown := "ip tacacs source-interface Management1\naaa group server tacacs+ port49\n   server 172.100.100.1\n" +
		"aaa authentication login default group port49 local\n"
	if m := l88Missing(typed, shown); len(m) != 0 {
		t.Errorf("missing = %q, want none", m)
	}
	if m := l88Missing(append(typed, "aaa accounting exec default start-stop group port49"), shown); len(m) != 1 {
		t.Errorf("missing = %q, want the accounting line", m)
	}
}

func TestL88ExpandListsMakesOneLinePerMember(t *testing.T) {
	got := l88ExpandLists([]string{"set system accounting events [ login change-log ]", "set system authentication-order tacplus"})
	want := []string{"set system accounting events login", "set system accounting events change-log", "set system authentication-order tacplus"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestL88RedactRemovesEveryCredentialAndKeepsTheDevicesWords(t *testing.T) {
	n := newL88Note(platform{name: "arista_eos"}, "tcp", "pw-Zx81-run-password-value", "$6$salt$hashhashhashhashhashhash")
	n.addSecret("tokentokentokentoken")
	n.addSecret("123456")
	device := "Password: ssh: handshake failed with pw-Zx81-run-password-value and $6$salt$hashhashhashhashhashhash; " +
		"tokentokentokentoken, 123456, " + breakglassPassword + ", " + labKeyDefault + " % Authorization failed " +
		"abcdefghijklmnopqrstuvwxyz0123456789"
	got := n.redact(device)
	for _, s := range []string{"pw-Zx81-run-password-value", "$6$salt$hashhashhashhashhashhash", "tokentokentokentoken", "123456",
		breakglassPassword, labKeyDefault, "abcdefghijklmnopqrstuvwxyz0123456789"} {
		if strings.Contains(got, s) {
			t.Errorf("the redacted text still holds %q: %s", s, got)
		}
	}
	for _, keep := range []string{"Password:", "% Authorization failed", "handshake failed", "<redacted>", "<LONG>"} {
		if !strings.Contains(got, keep) {
			t.Errorf("the redacted text lost %q: %s", keep, got)
		}
	}
}

func TestL88EvidenceDropsLinesThatCouldHoldACredential(t *testing.T) {
	got := l88Evidence("Server: 172.100.100.1 state: UP\r\nPassword: x\nauth token abc\nthe secret\nPayload 00ff\neyJhbGci\nTPLUS: sent")
	if strings.Contains(got, "x") && strings.Contains(got, "Password") || strings.Contains(got, "token") ||
		strings.Contains(got, "secret") || strings.Contains(got, "Payload") || strings.Contains(got, "eyJ") {
		t.Errorf("a line that could hold a credential survived: %q", got)
	}
	if !strings.Contains(got, "state: UP") || !strings.Contains(got, "TPLUS: sent") {
		t.Errorf("a plain line was dropped: %q", got)
	}
}

func TestL88OnlyCellsKeepsEveryCellByDefault(t *testing.T) {
	all := []string{"a", "b", "c", "d", "e", "f"}
	if got := l88OnlyCells(all, ""); !slices.Equal(got, all) {
		t.Errorf("an empty filter dropped cells: %v", got)
	}
	if got := l88OnlyCells(all, "a,e,x"); !slices.Equal(got, []string{"a", "e"}) {
		t.Errorf("the filter kept %v, want a and e", got)
	}
}

// TestL88NoteNeverHoldsAHashedKey: SR Linux prints a TLS profile's private key as
// `key $aes1$<salt>=$<base64>`; no form of it, not even the salt, reaches a note.
func TestL88NoteNeverHoldsAHashedKey(t *testing.T) {
	n := newL88Note(platform{name: "nokia_srlinux", version: "x"}, "tls", "pw", "hash")
	in := "profile l73-dev {\n    key $aes1$AWWGR+cgIqEYU28=$abcdefghijklmnopqrstuvwxyz0123456789ABCD\n    secret-key $aes1$AW+lB33r5=$short\n}"
	n.fact(n.redact(l88DropKeyLines(in)))
	n.fact(n.mask(in))
	out, err := n.render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "$aes1$") || strings.Contains(out, "AWWGR") {
		t.Errorf("a hashed key survived:\n%s", out)
	}
}

// TestL88NoteAlwaysPointsAtACapture: CLAUDE.md rule 3 needs a capture pointer in every closed
// note; a note without one says why, and the pointer survives the 24-character masking.
func TestL88NoteAlwaysPointsAtACapture(t *testing.T) {
	n := newL88Note(platform{name: "arista_eos", version: "x"}, "tcp", "pw", "hash")
	out, err := n.render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Capture: none kept: ") {
		t.Errorf("a note with no capture does not say so:\n%s", out)
	}
	n.capture("tests/lab/evidence/L88-f-arista_eos-vEOS-4.31.2F-arista_eos.pcap")
	n.fact(n.redact("Capture: tests/lab/evidence/L88-g-arista_eos-vEOS-4.31.2F-arista_eos.pcap"))
	out, err = n.render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Capture: `tests/lab/evidence/L88-f-arista_eos-vEOS-4.31.2F-arista_eos.pcap`") {
		t.Errorf("the cited capture is missing:\n%s", out)
	}
	if strings.Contains(out, "<LONG>") {
		t.Errorf("a committed-file pointer was masked:\n%s", out)
	}
}

// TestL88WireSeesThePortTheDeviceDials: over RFC 9887 the device dials 300, so a reader that
// keeps port 49 only prints "0 connections" for a pass in which the device connected.
func TestL88WireSeesThePortTheDeviceDials(t *testing.T) {
	at := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "tls.pcap")
	pcap := l73FakePcap(40000, 300, []l73FakeSeg{
		{fromDevice: true, flags: 0x02, at: at},
		{fromDevice: false, flags: 0x12, at: at.Add(time.Millisecond)},
		{fromDevice: false, flags: 0x04, at: at.Add(2 * time.Millisecond)},
	})
	if err := os.WriteFile(path, pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	got := l88WireFile(path, l73TDevice, 300, at.Add(-time.Second), at.Add(time.Second))
	if !strings.Contains(got, "1 connections from the device in the window: 1 with a SYN, 1 answered SYN-ACK, 1 with an RST") {
		t.Errorf("port 300 not read:\n%s", got)
	}
	if got := l88WireFile(path, l73TDevice, 49, at.Add(-time.Second), at.Add(time.Second)); !strings.Contains(got, "0 connections") {
		t.Errorf("port 49 should see nothing here:\n%s", got)
	}
}

func TestL88AccountGone(t *testing.T) {
	if err := l88AccountGone("l88deny", "show running-config | include username\nusername admin privilege 15\n"); err != nil {
		t.Errorf("an absent account read as present: %v", err)
	}
	for _, still := range []string{"username l88deny privilege 1 secret 9 x", "set system login user l88deny class read-only", "    l88deny {\n        password x"} {
		if l88AccountGone("l88deny", still) == nil {
			t.Errorf("a present account read as gone: %q", still)
		}
	}
}
