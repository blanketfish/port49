package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// Every L76 cell is in the register row, word for word, in order, once.
func TestL76CellsAreTheRegistersCells(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "2026-08-23-policy-engine-spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(ln, "| **L76** |") {
			row = ln
		}
	}
	if row == "" {
		t.Fatal("spec §15 has no L76 row")
	}
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	if len(l76Cells) != len(want) {
		t.Fatalf("%d cells, want %d", len(l76Cells), len(want))
	}
	last := -1
	for i, c := range l76Cells {
		if c.id != want[i] {
			t.Errorf("cell %d is %q, want %q", i, c.id, want[i])
		}
		at := strings.Index(row, "("+c.id+") "+c.claim)
		if at < 0 {
			t.Errorf("cell %s's claim is not in the row:\n%s", c.id, c.claim)
		}
		if at <= last {
			t.Errorf("cell %s is out of order in the row", c.id)
		}
		if n := strings.Count(row, "("+c.id+") "+c.claim); n != 1 {
			t.Errorf("cell %s's claim is in the row %d times, want once", c.id, n)
		}
		last = at
	}
	if !strings.HasPrefix(l76Claim(), "Nokia SR Linux") || !strings.Contains(l76Claim(), "(j) "+l76Cells[9].claim) {
		t.Errorf("l76Claim does not carry the cells: %q", l76Claim())
	}
}

// The topology, inventory, seeds and startup config agree with the constants.
func TestL76FilesAgree(t *testing.T) {
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	topo := read(l76Topo)
	for _, s := range []string{"name: port49-srlinux", "    " + l76Node + ":", "kind: nokia_srlinux",
		"image: " + l76Image, "startup-config: ../" + l76Config, "mgmt-ipv4: " + l76Addr,
		"network: port49-lab", "ipv4-subnet: 172.100.100.0/24"} {
		if !strings.Contains(topo, s) {
			t.Errorf("%s lacks %q", l76Topo, s)
		}
	}
	inv := read("inventory-lab.yaml")
	if !strings.Contains(inv, "{name: "+l76Node+", platform: "+l76PlatformName+", addresses: ["+l76Addr+"]}") {
		t.Errorf("inventory-lab.yaml has no %s line", l76Node)
	}
	cfg := read("port49d-lab.yaml")
	for n := 1; n <= 16; n++ {
		s := "{nas: " + l76Node + ", username: alice" + l76TwoDigits(n) + "}"
		if strings.Count(cfg, s) != 1 {
			t.Errorf("port49d-lab.yaml holds %q %d times, want once", s, strings.Count(cfg, s))
		}
	}
	cli := read(l76Config)
	for i, b := range []byte(cli) {
		if b > 0x7e || (b < 0x20 && b != '\n' && b != '\t') {
			t.Fatalf("%s byte %d is %#02x: startup configs are pure ASCII", l76Config, i, b)
		}
	}
	for _, s := range []string{
		"secret-key " + labcreds.Key, "password " + labcreds.BreakglassPassword,
		"user " + labcreds.BreakglassUser + " {", "server-group local {", "type local",
		"server-group port49 {", "type tacacs", "priv-lvl-authorization true",
		"server 172.100.100.1 {", "network-instance mgmt", "port 49",
		"event command {", "record start-stop",
		"role p49-read {", "priv-lvl 1\n", "role p49-admin {", "priv-lvl 15",
		"action read", "action write",
	} {
		if !strings.Contains(cli, s) {
			t.Errorf("%s lacks %q", l76Config, s)
		}
	}
	if got := l76LeafList(cli, "authentication-method"); strings.Join(got, " ") != "port49 local" {
		t.Errorf("authentication-method is %v, want [port49 local]", got)
	}
	if got := l76LeafList(cli, "accounting-method"); strings.Join(got, " ") != "port49" {
		t.Errorf("accounting-method is %v, want [port49]", got)
	}

	// Each statement sits in the block that owns it: the priv-lvl to role
	// mapping is what cell (h) measures, so a swap must not pass.
	path := func(names ...string) []string {
		t.Helper()
		lines := strings.Split(cli, "\n")
		for _, n := range names {
			var ok bool
			if lines, ok = l76Child(lines, n); !ok {
				t.Fatalf("%s has no block %q under %q", l76Config, n, names)
			}
		}
		return lines
	}
	for _, c := range []struct {
		where []string
		own   string
	}{
		{[]string{"system", "aaa", "authorization", "role p49-read", "tacacs"}, "priv-lvl 1"},
		{[]string{"system", "aaa", "authorization", "role p49-admin", "tacacs"}, "priv-lvl 15"},
		{[]string{"system", "configuration", "role p49-read", "rule /"}, "action read"},
		{[]string{"system", "configuration", "role p49-admin", "rule /"}, "action write"},
		{[]string{"system", "aaa", "server-group port49", "tacacs"}, "priv-lvl-authorization true"},
		{[]string{"system", "aaa", "server-group port49", "server 172.100.100.1", "tacacs"}, "port 49\nsecret-key " + labcreds.Key},
	} {
		if got := strings.Join(l76Own(path(c.where...)), "\n"); got != c.own {
			t.Errorf("%s holds %q, want %q", strings.Join(c.where, " > "), got, c.own)
		}
	}
	user := path("system", "aaa", "authentication", "user "+labcreds.BreakglassUser)
	if got := strings.Join(l76Own(user), "\n"); !strings.HasPrefix(got, "password "+labcreds.BreakglassPassword+"\nrole [") {
		t.Errorf("%s's own lines are not its password and its role list", labcreds.BreakglassUser)
	}
	if got := l76LeafList(strings.Join(user, "\n"), "role"); strings.Join(got, " ") != "p49-admin" {
		t.Errorf("%s's roles are %v, want [p49-admin]", labcreds.BreakglassUser, got)
	}
}

// l76Child returns the body of the first direct child block of lines whose
// header line is `name {`, by brace depth.
func l76Child(lines []string, name string) ([]string, bool) {
	depth, start := 0, -1
	for i, ln := range lines {
		ln = strings.TrimSpace(ln)
		if depth == 0 && start < 0 && ln == name+" {" {
			start = i + 1
		}
		if strings.HasSuffix(ln, "{") {
			depth++
		}
		if ln == "}" {
			depth--
			if start >= 0 && depth == 0 {
				return lines[start:i], true
			}
		}
	}
	return nil, false
}

// l76Own returns the depth-0 lines of a block body: its leaf statements,
// without the blocks nested in it and without bracket-list contents.
func l76Own(body []string) []string {
	var out []string
	depth := 0
	for _, ln := range body {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "":
		case strings.HasSuffix(ln, "{"):
			depth++
		case ln == "}":
			depth--
		case depth == 0:
			out = append(out, ln)
		}
	}
	return out
}

func l76TwoDigits(n int) string { return string([]byte{byte('0' + n/10), byte('0' + n%10)}) }
