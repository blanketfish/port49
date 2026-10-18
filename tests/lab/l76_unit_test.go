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
}

func l76TwoDigits(n int) string { return string([]byte{byte('0' + n/10), byte('0' + n%10)}) }
