//go:build lab

package lab

import (
	"reflect"
	"slices"
	"strings"
	"testing"

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
			want, err := deviceaaa.Render(ref, transport, l88Values(p, l88Servers), labKeyDefault)
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
			if !has(cells, c) || !has(l88Cells(p.sel, true), c) {
				t.Errorf("%s: cell %s is missing", p.sel, c)
			}
		}
	}
	for _, sel := range []string{"vjunos26", "iosxe1718", "nxos106", "ceos436", "xrd261"} {
		if !has(l88Cells(sel, false), "h") {
			t.Errorf("%s: cell h is missing", sel)
		}
		if has(l88Cells(sel, true), "h") {
			t.Errorf("%s: the TLS pass is cell h itself, it lists no h", sel)
		}
	}
	for _, sel := range []string{"eos", "vjunos", "vsrx", "nxos", "iosxe", "srlinux"} {
		if has(l88Cells(sel, false), "h") {
			t.Errorf("%s: has no TLS image, but lists cell h", sel)
		}
	}
	// g is skipped where L29 measured the platform, unless TLS.
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
	for _, sel := range []string{"vjunos26", "iosxe1718", "nxos106", "ceos436", "xrd261"} {
		if !has(l88Cells(sel, true), "g") {
			t.Errorf("%s: cell g must run over TLS", sel)
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
